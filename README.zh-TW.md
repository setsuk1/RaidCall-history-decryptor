# RC 語音歷史紀錄解密工具

將 RC 語音的加密聊天紀錄檔案 `*.dat` 解密並轉換成標準的 SQLite 資料庫格式，讓你可以使用一般工具開啟查看。

此腳本是透過靜態分析 `raidcall.exe` 和 `SQLite.dll` 而得：
- `raidcall.exe` 會從帳號字串衍生出**明文金鑰**
- `SQLite.dll` 使用 **SHA1(key_bytes) 衍生 RC4 金鑰**，並透過 Windows CryptoAPI 解密每個 SQLite 頁面

## 免責聲明

本專案是透過靜態分析 RC 語音 v8.3.0 所開發，若有任何疑慮請勿使用。  
若有任何侵權疑慮，請聯絡我們，我們將盡快移除此工具。


## 環境需求

- Windows
- Python 3.x

## 基本使用方式

執行腳本並指向你的 `*.dat` 檔案：

```bat
python rc_dat_decrypt.py "%APPDATA%\RCTW\<account>@raidcall.com.tw\<account>@raidcall.com.tw.dat" --force
```

預設輸出：解密後的 `*.sqlite` 檔案會儲存在**腳本所在目錄**：

```text
<account>@raidcall.com.tw.sqlite
```

## 如果 `.dat` 檔名不是帳號名稱

腳本預設會假設 `--account` 參數是 `.dat` 檔案的主檔名（例如 `<account>@raidcall.com.tw`）。
如果你要解密的檔案名稱是 `Popup.dat` 或 `olConfig.dat` 之類的，請明確指定正確的帳號：

```bat
python rc_dat_decrypt.py "%APPDATA%\RCTW\temp\Popup.dat" --account "<account>@raidcall.com.tw" --out "Popup.sqlite" --force
```


## 參數選項

- `--out <path>`: 指定輸出檔案路徑
- `--force`: 強制覆蓋已存在的檔案
- `--no-verify`: 跳過檢查解密後的標頭是否為 `SQLite format 3\0`（不建議使用）

## 開啟或讀取解密後的資料庫

你可以使用以下工具開啟輸出檔案：

- [SQLite viewer](https://inloop.github.io/sqlite-viewer/)
- `sqlite3.exe`
- Python：

```python
import sqlite3
con = sqlite3.connect(r"%USERPROFILE%\Documents\<account>@raidcall.com.tw.sqlite")
cur = con.cursor()
cur.execute("select name from sqlite_master where type='table' order by name")
print(cur.fetchall())
```

常見的資料表（依帳號/版本而異）：
- `tb_msg_chat`, `tb_msg_chat_v2`（聊天訊息）
- `tb_group_msg`、`tb_groupchat_record`
- `tb_user`、`tb_stranger`、`tb_sys_notice`、`tb_unread_msg`

## 圖片訊息：URL ↔ 本地 `ChatImage` 快取

在 `tb_msg_chat.msg`和`tb_msg_chat_v2.msg` 欄位中，圖片的格式為：

```text
[image]<URL>[/image]
```

RC 語音會將 **URL 儲存在資料庫**，但**圖片本身會快取在磁碟**上：

```text
%APPDATA%\RCTW\<account>@raidcall.com.tw\ChatImage\<md5(url_utf8)>
```

注意事項：
- 檔案名稱是 URL 的 **UTF-8 編碼** 經過 **MD5 雜湊後的小寫十六進位值**
- 快取檔案通常**沒有副檔名**；請依據檔案的魔術數字判斷類型（例如 PNG 開頭為 `89 50 4E 47`）
- 如果檔案不存在，表示從未下載或快取已被清除

### 轉換方法（URL → 本地檔案）

Python 範例：

```python
import hashlib
from pathlib import Path

url = "http://img.rcshow.tv/images/..."
account = "<account>@raidcall.com.tw"

cache_dir = Path(r"%APPDATA%") / "RCTW" / account / "ChatImage"
name = hashlib.md5(url.encode("utf-8")).hexdigest()  # 小寫十六進位
local_file = cache_dir / name
print(local_file, local_file.exists())
```

### 匯出聊天中引用的快取圖片

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
        shutil.copyfile(src, out / name)  # 仍然沒有副檔名
con.close()
```

## 疑難排解

### 「decrypted header is not SQLite; wrong account/key?」錯誤

最常見的原因是你使用的 `--account` 參數與建立該資料庫的帳號/資料夾不符。
請使用 `%APPDATA%\RCTW\` 下的帳號資料夾名稱作為帳號字串。

### 某些帳號可以解密但其他帳號不行

不同帳號的 `.dat` 檔案大小/內容可能不同，但金鑰衍生方式是依據各別帳號。
請確保使用正確的帳號值來解密對應的檔案。

## 附註

### 金鑰衍生摘要

明文金鑰是從帳號字串中 **`@` 之前的部分**衍生而來：
- `a..z` 被映射為 `1..13..1`（迴文對稱）
- `0..9` 映射到 `a..j`
- 其他字元映射為 `1`

衍生出的金鑰會以 **ASCII 位元組**形式傳入 `SQLite.dll` 的 `sqlite3_key_interop` 函式，  
該函式使用 `CryptCreateHash(CALG_SHA1)` 和 `CryptDeriveKey(CALG_RC4)`，然後用 `CryptDecrypt` 解密每個頁面。

---

## 開發工具

此專案使用以下工具進行逆向工程：
- [Ghidra 11.3.2](https://github.com/NationalSecurityAgency/ghidra)
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- [OpenAI Codex 5.2](https://chatgpt.com/codex)

## 開發心得

過去透過人工分析，即使花費數週時間也無法完全理清解密邏輯。  
雖然能大致了解呼叫流程與函式庫間的互動，但無法將具體的解密方法整理出來。  
在 LLM 的輔助下，僅花費一週就成功完成最後一塊拼圖。