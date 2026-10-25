//! RaidCall encrypted SQLite page decryptor.
//!
//! Mirrors the legacy Windows CryptoAPI sequence:
//!   CryptHashData(SHA1, derive_plain_key(account).as_bytes())
//!   CryptDeriveKey(CALG_RC4, flags=0) using MS Enhanced CSP (128-bit)
//!   CryptDecrypt(Final=true) independently for every SQLite page.
//!
//! RC4 and SHA-1 are intentionally used only to read legacy files.

pub mod discovery;

use sha1::{Digest, Sha1};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// SQLite file header used to validate decrypted data.
pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Derive the legacy key material from an account name.
pub fn derive_plain_key(account: &str) -> Result<String, String> {
    if account.is_empty() {
        return Err("account is empty".into());
    }
    let account = account.split_once('@').map_or(account, |(left, _)| left);
    if account.is_empty() {
        return Err("account starts with '@'".into());
    }
    let mut result = String::new();
    for ch in account.to_lowercase().chars() {
        match ch {
            'a'..='z' => {
                let pos = (ch as u8 - b'a') as u32;
                let code = 1 + pos.min(25 - pos);
                result.push_str(&code.to_string());
            }
            '0'..='9' => result.push((b'a' + (ch as u8 - b'0')) as char),
            _ => result.push('1'),
        }
    }
    Ok(result)
}

/// Default 128-bit RC4 key from MS Enhanced Cryptographic Provider v1.0.
/// CryptoAPI CryptDeriveKey(CALG_RC4, SHA1, dwFlags=0) takes SHA1[0..16].
pub fn derive_rc4_key(account: &str) -> Result<[u8; 16], String> {
    let plain = derive_plain_key(account)?;
    let digest = Sha1::digest(plain.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Ok(key)
}

struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty());
        let mut state = [0u8; 256];
        for (i, v) in state.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Self { state, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let k = self.state[self.state[self.i as usize]
                .wrapping_add(self.state[self.j as usize]) as usize];
            *byte ^= k;
        }
    }
}

/// Decrypt one independent SQLite page, beginning with a fresh RC4 state.
pub fn decrypt_page(data: &mut [u8], key: &[u8; 16]) {
    Rc4::new(key).apply(data);
}

/// Read and validate the SQLite page size stored in a decrypted header.
pub fn sqlite_page_size(header: &[u8]) -> Result<usize, String> {
    if header.len() < 18 {
        return Err("input header is shorter than 18 bytes".into());
    }
    let encoded = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if encoded == 1 { 65536 } else { usize::from(encoded) };
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(format!("invalid SQLite page size: {page_size}"));
    }
    Ok(page_size)
}

/// Options for decrypting an encrypted RaidCall database.
#[derive(Debug, Clone)]
pub struct DecryptOptions {
    pub input: PathBuf,
    pub account: String,
    pub output: PathBuf,
    pub overwrite: bool,
    pub verify_header: bool,
}

/// Summary of a completed decryption.
#[derive(Debug, Clone)]
pub struct DecryptReport {
    pub account: String,
    pub output: PathBuf,
    pub page_size: usize,
    pub pages: u64,
    pub bytes: u64,
}

// Remove unfinished temporary files on early return or I/O failure.
struct StagedOutput {
    path: PathBuf,
}
impl Drop for StagedOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_sibling_path(destination: &Path, marker: &str, attempt: u32) -> PathBuf {
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_nanos();
    let file = destination.file_name().unwrap_or_default().to_string_lossy();
    destination.with_file_name(format!(".{file}.{marker}.{}.{}.{}",
        std::process::id(), epoch, attempt))
}

fn create_staged_output(path: &Path) -> Result<(StagedOutput, File), String> {
    for attempt in 0..32 {
        let candidate = unique_sibling_path(path, "decrypt-tmp", attempt);
        match OpenOptions::new().create_new(true).write(true).open(&candidate) {
            Ok(file) => return Ok((StagedOutput { path: candidate }, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create temporary output: {e}")),
        }
    }
    Err("could not allocate a unique temporary file".into())
}

// Publish the completed output, retaining the old file if publication fails.
fn publish_output(staged: &Path, destination: &Path, overwrite: bool) -> Result<(), String> {
    if destination.exists() {
        if !overwrite {
            return Err(format!("output exists: {} (enable overwrite)", destination.display()));
        }
        if !destination.is_file() {
            return Err("output exists but is not a regular file".into());
        }
        // Move old output aside first, so Windows can rename the staged file.
        // Restore it if publishing the new file fails.
        for attempt in 0..32 {
            let backup = unique_sibling_path(destination, "decrypt-backup", attempt);
            if backup.exists() {
                continue;
            }
            match fs::rename(destination, &backup) {
                Ok(()) => {
                    match fs::rename(staged, destination) {
                        Ok(()) => {
                            let _ = fs::remove_file(&backup);
                            return Ok(());
                        }
                        Err(e) => {
                            let restored = fs::rename(&backup, destination);
                            return Err(format!("cannot publish output: {e}; restoring original: {restored:?}"));
                        }
                    }
                }
                Err(e) => return Err(format!("cannot back up existing output: {e}")),
            }
        }
        return Err("could not allocate a unique backup file".into());
    }
    fs::rename(staged, destination).map_err(|e| format!("cannot publish output: {e}"))
}

/// Decrypt the source file without touching it. Progress callback receives (done,total) bytes.
pub fn decrypt_file(
    options: &DecryptOptions,
    mut progress: impl FnMut(u64, u64),
) -> Result<DecryptReport, String> {
    if !options.input.is_file() {
        return Err(format!("input not found: {}", options.input.display()));
    }
    if options.input.as_os_str().is_empty() || options.output.as_os_str().is_empty() {
        return Err("input and output paths are required".into());
    }
    let source = fs::canonicalize(&options.input).map_err(|e| format!("cannot resolve input: {e}"))?;
    if options.output.exists() {
        let target = fs::canonicalize(&options.output)
            .map_err(|e| format!("cannot resolve output: {e}"))?;
        if source == target {
            return Err("input and output are the same file".into());
        }
        if !options.overwrite {
            return Err(format!("output exists: {} (enable overwrite)", options.output.display()));
        }
    }

    let key = derive_rc4_key(&options.account)?;
    let mut reader = BufReader::new(File::open(&source)
        .map_err(|e| format!("cannot open input: {e}"))?);
    let total = reader.get_ref().metadata()
        .map_err(|e| format!("cannot stat input: {e}"))?.len();
    let mut header = [0u8; 100];
    reader.read_exact(&mut header)
        .map_err(|e| format!("cannot read 100-byte encrypted header: {e}"))?;
    decrypt_page(&mut header, &key);
    if options.verify_header && !header.starts_with(SQLITE_MAGIC) {
        return Err("decrypted header is not SQLite; check the account name".into());
    }
    let page_size = sqlite_page_size(&header)?;
    reader.seek(SeekFrom::Start(0))
        .map_err(|e| format!("cannot rewind input: {e}"))?;

    let parent = options.output.parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("cannot create output directory: {e}"))?;
    let (staged, temporary_file) = create_staged_output(&options.output)?;
    let mut writer = BufWriter::new(temporary_file);
    let mut buffer = vec![0u8; page_size];
    let mut done = 0u64;
    let mut pages = 0u64;
    progress(0, total);
    loop {
        // read() can return a short read; fill a whole page unless EOF.
        let mut count = 0;
        while count < page_size {
            let read = reader.read(&mut buffer[count..])
                .map_err(|e| format!("cannot read page: {e}"))?;
            if read == 0 { break; }
            count += read;
        }
        if count == 0 { break; }
        decrypt_page(&mut buffer[..count], &key);
        writer.write_all(&buffer[..count])
            .map_err(|e| format!("cannot write output page: {e}"))?;
        done += count as u64;
        pages += 1;
        progress(done, total);
    }
    writer.flush().map_err(|e| format!("cannot flush output: {e}"))?;
    writer.get_ref().sync_all().map_err(|e| format!("cannot sync output: {e}"))?;
    drop(writer);
    publish_output(&staged.path, &options.output, options.overwrite)?;
    Ok(DecryptReport {
        account: options.account.clone(), output: options.output.clone(),
        page_size, pages, bytes: done,
    })
}

