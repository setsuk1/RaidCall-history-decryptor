//! RaidCall account discovery used by the Windows GUI.
//!
//! A standard Taiwanese RaidCall installation stores accounts at
//! `%APPDATA%\RCTW\<account>\<account>.dat`.
//! This module only enumerates metadata and NEVER decrypts files while scanning.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// An account folder containing its matching encrypted database file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaidCallAccount {
    pub account: String,
    pub dat_path: PathBuf,
}

/// Scan only immediate account directories under an RCTW root.
///
/// Ignore folders that have no matching `<account>.dat` or that are not
/// account-shaped; do not recursively traverse caches or temp directories.
pub fn discover_accounts_in(root: &Path) -> io::Result<Vec<RaidCallAccount>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let folder = entry.file_name();
        let Some(name) = folder.to_str() else { continue };
        if name.is_empty() || !name.contains('@') {
            continue;
        }

        // Use the actual directory spelling to construct the filename.
        let dat_path = entry.path().join(format!("{name}.dat"));
        if dat_path.is_file() {
            found.push(RaidCallAccount {
                account: name.to_owned(),
                dat_path,
            });
        }
    }
    found.sort_by(|a, b| {
        a.account
            .to_ascii_lowercase()
            .cmp(&b.account.to_ascii_lowercase())
            .then_with(|| a.account.cmp(&b.account))
    });
    Ok(found)
}

/// Locate RaidCall account files in the Windows application-data directory.
#[cfg(target_os = "windows")]
pub fn discover_windows_accounts() -> Result<Vec<RaidCallAccount>, String> {
    let appdata = std::env::var_os("APPDATA")
        .ok_or("APPDATA is not set; browse to your .dat file manually")?;
    let root = PathBuf::from(appdata).join("RCTW");
    discover_accounts_in(&root)
        .map_err(|err| format!("Cannot scan {}: {err}", root.display()))
}

