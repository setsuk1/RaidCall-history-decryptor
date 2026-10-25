//! Command-line interface for decrypting RaidCall history databases.

use raidcall_history_decryptor::{decrypt_file, DecryptOptions};
use std::env;
use std::path::PathBuf;

fn usage() {
    println!("RaidCall history .dat decryptor (portable Rust)");
    println!();
    println!("Usage: rc-dat-decrypt <file.dat> [--account NAME] [--out FILE] [--force] [--no-verify]");
    println!("       rc-dat-decrypt --help");
    println!();
    println!("Options:");
    println!("  --account NAME  Account used to encrypt the file (default: input file stem)");
    println!("  --out FILE      SQLite output (default: replace .dat with .sqlite3)");
    println!("  --force         Allow overwriting an existing output, preserving it on errors");
    println!("  --no-verify     Skip decrypted SQLite magic check (not recommended)");
    println!("  -h, --help      Print this help");
}

fn parse_options() -> Result<Option<DecryptOptions>, String> {
    let mut dat: Option<PathBuf> = None;
    let mut account: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut overwrite = false;
    let mut verify_header = true;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let item = arg.to_string_lossy();
        match item.as_ref() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "--force" => overwrite = true,
            "--no-verify" => verify_header = false,
            "--account" => {
                let value = args.next().ok_or("--account requires a value")?;
                account = Some(value.to_string_lossy().into_owned());
            }
            "--out" => {
                out = Some(PathBuf::from(args.next().ok_or("--out requires a path")?));
            }
            "--" => {
                if dat.is_some() { return Err("multiple input files are not supported".into()); }
                dat = Some(PathBuf::from(args.next().ok_or("input .dat is required")?));
                if args.next().is_some() { return Err("multiple input files are not supported".into()); }
                break;
            }
            _ if item.starts_with('-') => return Err(format!("unknown argument: {item}")),
            _ => {
                if dat.replace(PathBuf::from(arg)).is_some() {
                    return Err("multiple input files are not supported".into());
                }
            }
        }
    }
    let dat = dat.ok_or("input .dat is required (see --help)")?;
    let account = account.unwrap_or_else(|| dat.file_stem()
        .map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
    let output = out.unwrap_or_else(|| dat.with_extension("sqlite3"));
    Ok(Some(DecryptOptions {
        input: dat, account, output, overwrite, verify_header,
    }))
}

fn main() {
    let options = match parse_options() {
        Ok(Some(options)) => options,
        Ok(None) => return,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("Use --help for usage.");
            std::process::exit(2);
        }
    };
    let mut last_percent = None;
    match decrypt_file(&options, |done, total| {
        let percent = if total == 0 { 100 } else { done.saturating_mul(100) / total };
        if last_percent != Some(percent) {
            eprint!("\rDecrypting: {percent:3}%");
            last_percent = Some(percent);
        }
    }) {
        Ok(report) => {
            eprintln!();
            println!("Input:      {}", options.input.display());
            println!("Account:    {}", report.account);
            println!("Page size:  {}", report.page_size);
            println!("Pages:      {}", report.pages);
            println!("Bytes:      {}", report.bytes);
            println!("SQLite out: {}", report.output.display());
        }
        Err(e) => {
            if last_percent.is_some() { eprintln!(); }
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
