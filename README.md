# RaidCall History Decryptor

[繁體中文 README](README.zh-TW.md) · [Changelog](CHANGELOG.md)

Decrypts RaidCall `*.dat` chat/history files into a normal SQLite database you can open with standard tools.

The decryption method was recovered through static analysis of `raidcall.exe` and `SQLite.dll`:
- `raidcall.exe` derives the **plaintext key** from the account string.
- `SQLite.dll` derives an **RC4 key from SHA1(key_bytes)** and decrypts each SQLite page via CryptoAPI.

## Disclaimer

This project was developed through static analysis of RaidCall v8.3.0. Use at your own discretion.
If there are any copyright concerns, please contact us and this tool will be removed promptly.

## Requirements

- Windows or Linux
- Stable Rust toolchain to build from source
- GUI system libraries and a suitable Vulkan, Direct3D 12 (Windows), or OpenGL renderer when running the desktop application

Python is **not** required to run the decryptor. The Python snippets later in this README are optional examples for examining SQLite databases and cached images.

## Build

Desktop GUI:

```sh
cargo build --release --features gui --bin raidcall-gui
```

Command-line executable:

```sh
cargo build --release --bin rc-dat-decrypt
```

Binaries are written to `target/release/` (`.exe` on Windows). The Windows build additionally needs a resource compiler for the executable icon.

## Building with VS Code

Open the repository folder in VS Code, then press **Ctrl+Shift+B** for the native Release build. Use **Terminal → Run Task** to choose native Debug, Windows x64, Linux, or both Release targets. **Run: Native GUI (Debug)** builds and launches the desktop application. The F5 launch configurations use the native Debug task.

These VS Code tasks use the included `.vscode/build.py` helper and require Python 3.10+ **only for build-task routing**, not to run the compiled decryptor. On Windows, compiling Linux targets uses WSL2 with its own Rust and Python 3 installations. On Linux, compiling Windows x64 requires the Rust `x86_64-pc-windows-gnu` target and MinGW-w64, including `gcc` and `windres`. You can also build directly with the Cargo commands above without Python.

## Basic usage

Launch `raidcall-gui` (`raidcall-gui.exe` on Windows). Select an account from the Windows account list or browse to a `.dat` file, confirm the original account, choose the destination, and click **Decrypt**. The GUI supports Traditional Chinese and English, scrolling in smaller windows, progress reporting, and overwrite confirmation.

You can also use the Rust command-line program:

```bat
rc-dat-decrypt "%APPDATA%\RCTW\<account>@raidcall.com.tw\<account>@raidcall.com.tw.dat" --force
```

By default, the output is written **beside the input file** as `<account>@raidcall.com.tw.sqlite3`, not beside the executable.

## If the `.dat` filename is not the account

By default the command-line tool assumes `--account` is the `.dat` filename stem (e.g. `<account>@raidcall.com.tw`).
If you are decrypting something like `Popup.dat` or `olConfig.dat`, pass the correct account explicitly:

```bat
rc-dat-decrypt "%APPDATA%\RCTW\temp\Popup.dat" --account "<account>@raidcall.com.tw" --out "Popup.sqlite3" --force
```

## Options

- `--account <name>`: supply the original account name (otherwise inferred from the input filename)
- `--out <path>`: choose output file path
- `--force`: overwrite output if it already exists
- `--no-verify`: skips checking that the decrypted header starts with `SQLite format 3\0` (not recommended)
- `--help`: display usage information

## Opening / reading the decrypted DB

You can open the output with:

- [SQLite viewer](https://inloop.github.io/sqlite-viewer/)
- `sqlite3.exe`
- Python:

```python
import sqlite3
con = sqlite3.connect(r"%USERPROFILE%\Documents\<account>@raidcall.com.tw.sqlite3")
cur = con.cursor()
cur.execute("select name from sqlite_master where type='table' order by name")
print(cur.fetchall())
```

Common tables (varies by account/version):
- `tb_msg_chat`, `tb_msg_chat_v2` (chat messages)
- `tb_group_msg`, `tb_groupchat_record`
- `tb_user`, `tb_stranger`, `tb_sys_notice`, `tb_unread_msg`

## Image messages: URL ↔ local `ChatImage` cache

In `tb_msg_chat.msg` and `tb_msg_chat_v2.msg`, images are represented as:

```text
[image]<URL>[/image]
```

RaidCall stores the **URL in the DB**, but the **image bytes are cached on disk**:

```text
%APPDATA%\RCTW\<account>@raidcall.com.tw\ChatImage\<md5(url_utf8)>
```

Notes:
- The filename is **lowercase MD5 hex** of the full URL encoded as **UTF-8**.
- Cached files usually have **no extension**; determine type by magic bytes (e.g. PNG starts with `89 50 4E 47`).
- If the file does not exist, it simply was not cached (never downloaded / cache cleared).

### Convert method (URL → local file)

Python example:

```python
import hashlib
from pathlib import Path

url = "http://img.rcshow.tv/images/..."
account = "<account>@raidcall.com.tw"

cache_dir = Path(r"%APPDATA%") / "RCTW" / account / "ChatImage"
name = hashlib.md5(url.encode("utf-8")).hexdigest()  # lowercase hex
local_file = cache_dir / name
print(local_file, local_file.exists())
```

### Export cached images referenced by chat

```python
import hashlib, os, re, shutil, sqlite3
from pathlib import Path

account = "<account>@raidcall.com.tw"
db = Path(os.environ["USERPROFILE"]) / "Documents" / f"{account}.sqlite3"
cache = Path(os.environ["APPDATA"]) / "RCTW" / account / "ChatImage"
out = Path(os.environ["USERPROFILE"]) / "Documents" / f"{account}_ChatImage_export"
out.mkdir(parents=True, exist_ok=True)

pat = re.compile(r"\[image\](.+?)\[/image\]", re.IGNORECASE)

con = sqlite3.connect(str(db))
cur = con.cursor()
cur.execute("select id, msg from tb_msg_chat_v2 where msg like '%[image]%'")
for msg_id, msg in cur.fetchall():
    m = pat.search(msg or "")
    if not m:
        continue
    url = m.group(1).strip()
    name = hashlib.md5(url.encode("utf-8")).hexdigest()
    src = cache / name
    if src.exists():
        shutil.copyfile(src, out / name)  # still no extension
con.close()
```

## Troubleshooting

### "decrypted header is not SQLite; wrong account/key?"

Most often the `--account` you used doesn't match the folder/account that created the DB.
Use the account folder name under `%APPDATA%\RCTW\` as the account string.

### It works for some accounts but not others

Different accounts can have different `.dat` sizes/contents, but the key derivation is per-account.
Make sure you decrypt with the matching account value.

## Notes (key derivation summary)

The plaintext key is derived from the substring **before `@`** in the account:
- `a..z` are mapped to `1..13..1` (palindrome)
- `0..9` map to `a..j`
- other characters map to `1`

In the original client, that derived key is passed as **ASCII bytes** into `SQLite.dll`'s `sqlite3_key_interop`, which uses `CryptCreateHash(CALG_SHA1)` and `CryptDeriveKey(CALG_RC4)` before decrypting each page with `CryptDecrypt`. The Rust edition implements the compatible SHA-1/RC4 process without requiring Windows CryptoAPI.

---

## Development Tools

This project was developed using the following reverse engineering tools:
- [Ghidra 11.3.2](https://github.com/NationalSecurityAgency/ghidra)
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- [OpenAI Codex 5.2](https://chatgpt.com/codex)

## Development Notes

In the past, manual analysis took weeks without successfully clarifying the complete decryption logic.
Although it was possible to roughly understand the call flow and library interactions, the specific decryption method could not be fully documented.
With LLM assistance, the final piece of the puzzle was completed in just one week.
