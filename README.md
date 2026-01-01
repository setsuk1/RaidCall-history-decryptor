# RaidCall History Decryptor

[繁體中文 README](README.zh-TW.md)

Decrypts RaidCall `*.dat` chat/history files into a normal SQLite database you can open with standard tools.

This script was derived from static analysis of `raidcall.exe` + `SQLite.dll`:
- `raidcall.exe` derives the **plaintext key** from the account string.
- `SQLite.dll` derives an **RC4 key from SHA1(key_bytes)** and decrypts each SQLite page via CryptoAPI.

## Disclaimer

This project was developed through static analysis of RaidCall v8.3.0. Use at your own discretion.
If there are any copyright concerns, please contact us and this tool will be removed promptly.

## Requirements

- Windows
- Python 3.x

## Basic usage

Run the script and point it at an `*.dat` file:

```bat
python rc_dat_decrypt.py "%APPDATA%\RCTW\<account>@raidcall.com.tw\<account>@raidcall.com.tw.dat" --force
```

Output (default): a decrypted `*.sqlite` written **next to the script**:

```text
<account>@raidcall.com.tw.sqlite
```

## If the `.dat` filename is not the account

By default the script assumes `--account` is the `.dat` filename stem (e.g. `<account>@raidcall.com.tw`).
If you are decrypting something like `Popup.dat` or `olConfig.dat`, pass the correct account explicitly:

```bat
python rc_dat_decrypt.py "%APPDATA%\RCTW\temp\Popup.dat" --account "<account>@raidcall.com.tw" --out "Popup.sqlite" --force
```

## Options

- `--out <path>`: choose output file path
- `--force`: overwrite output if it already exists
- `--no-verify`: skips checking that the decrypted header starts with `SQLite format 3\0` (not recommended)

## Opening / reading the decrypted DB

You can open the output with:

- [SQLite viewer](https://inloop.github.io/sqlite-viewer/)
- `sqlite3.exe`
- Python:

```python
import sqlite3
con = sqlite3.connect(r"%USERPROFILE%\Documents\<account>@raidcall.com.tw.sqlite")
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
db = Path(os.environ["USERPROFILE"]) / "Documents" / f"{account}.sqlite"
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

That derived key is passed as **ASCII bytes** into `SQLite.dll`'s `sqlite3_key_interop`,
which uses `CryptCreateHash(CALG_SHA1)` + `CryptDeriveKey(CALG_RC4)` and then decrypts each page with `CryptDecrypt`.

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
