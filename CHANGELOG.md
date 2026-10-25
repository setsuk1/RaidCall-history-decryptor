# Changelog

All notable changes to the RaidCall History Decryptor are documented here.

## 0.1.0 — Rust rewrite (2026-10-25)

### Compared with the original Python/CryptoAPI script

| Capability | Original Python script | Current Rust version |
| --- | --- | --- |
| Implementation | Python and Windows CryptoAPI | Native Rust SHA-1 / RC4, with no Python or CryptoAPI runtime dependency |
| Operating systems | Windows only | Windows and Linux; macOS is not supported |
| Interface | Command line only | Command line plus native desktop GUI |
| Account discovery | Input filename / manual `--account` | Windows GUI detects RaidCall account directories; manual account entry remains available |
| Input and output | Explicit input and optional `--out` | GUI file pickers and output selection; CLI flags retained in Rust |
| Progress | Console operation | GUI progress bar and CLI progress output |
| Overwrite protection | `--force` | Confirmation in GUI, `--force` in CLI; staged file writes protect pre-existing output on failure |
| Display | Not applicable | Traditional Chinese / English, resizable scrollable form, custom application icon |
| Graphics | Not applicable | Vulkan preferred; Windows DX12/WARP and compatible GL fallback; Linux Glow fallback |

### Compatibility and data preservation

- The default decrypted output filename ends with `.sqlite3` in both the desktop GUI and command-line application.

- Implements the legacy account-to-key derivation and independently resets RC4 for each encrypted SQLite page, preserving the original encrypted-file format.
- Validates the decrypted SQLite magic and page size unless header verification is explicitly disabled.
- Produces a decrypted SQLite file; it **does not** modify the encrypted RaidCall source file.
- The Rust command-line tool replaces the previous Python script; Python and Windows CryptoAPI are no longer required to run the decryptor.
