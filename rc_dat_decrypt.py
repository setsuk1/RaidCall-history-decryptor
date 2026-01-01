#!/usr/bin/env python3
import argparse
import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

sys.dont_write_bytecode = True

LETTER_MAP = {
    "a": "1",
    "b": "2",
    "c": "3",
    "d": "4",
    "e": "5",
    "f": "6",
    "g": "7",
    "h": "8",
    "i": "9",
    "j": "10",
    "k": "11",
    "l": "12",
    "m": "13",
    "n": "13",
    "o": "12",
    "p": "11",
    "q": "10",
    "r": "9",
    "s": "8",
    "t": "7",
    "u": "6",
    "v": "5",
    "w": "4",
    "x": "3",
    "y": "2",
    "z": "1",
}
DIGIT_MAP = {"0": "a", "1": "b", "2": "c", "3": "d", "4": "e", "5": "f", "6": "g", "7": "h", "8": "i", "9": "j"}


def derive_plain_key(account: str) -> str:
    if not account:
        raise ValueError("account is empty")
    at = account.find("@")
    if at == 0:
        raise ValueError("account starts with '@'")
    if at > 0:
        account = account[:at]
    account = account.lower()
    out: list[str] = []
    for ch in account:
        if "a" <= ch <= "z":
            out.append(LETTER_MAP.get(ch, "1"))
        elif "0" <= ch <= "9":
            out.append(DIGIT_MAP[ch])
        else:
            out.append("1")
    return "".join(out)


adv = ctypes.WinDLL("advapi32", use_last_error=True)

HCRYPTPROV = wintypes.HANDLE
HCRYPTHASH = wintypes.HANDLE
HCRYPTKEY = wintypes.HANDLE

CryptAcquireContextW = adv.CryptAcquireContextW
CryptAcquireContextW.argtypes = [
    ctypes.POINTER(HCRYPTPROV),
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
CryptAcquireContextW.restype = wintypes.BOOL

CryptCreateHash = adv.CryptCreateHash
CryptCreateHash.argtypes = [HCRYPTPROV, wintypes.DWORD, HCRYPTKEY, wintypes.DWORD, ctypes.POINTER(HCRYPTHASH)]
CryptCreateHash.restype = wintypes.BOOL

CryptHashData = adv.CryptHashData
CryptHashData.argtypes = [HCRYPTHASH, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD, wintypes.DWORD]
CryptHashData.restype = wintypes.BOOL

CryptDeriveKey = adv.CryptDeriveKey
CryptDeriveKey.argtypes = [HCRYPTPROV, wintypes.DWORD, HCRYPTHASH, wintypes.DWORD, ctypes.POINTER(HCRYPTKEY)]
CryptDeriveKey.restype = wintypes.BOOL

CryptDecrypt = adv.CryptDecrypt
CryptDecrypt.argtypes = [
    HCRYPTKEY,
    HCRYPTHASH,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
]
CryptDecrypt.restype = wintypes.BOOL

CryptDestroyHash = adv.CryptDestroyHash
CryptDestroyHash.argtypes = [HCRYPTHASH]
CryptDestroyHash.restype = wintypes.BOOL

CryptDestroyKey = adv.CryptDestroyKey
CryptDestroyKey.argtypes = [HCRYPTKEY]
CryptDestroyKey.restype = wintypes.BOOL

CryptReleaseContext = adv.CryptReleaseContext
CryptReleaseContext.argtypes = [HCRYPTPROV, wintypes.DWORD]
CryptReleaseContext.restype = wintypes.BOOL

PROV_RSA_FULL = 1
CRYPT_VERIFYCONTEXT = 0xF0000000
CRYPT_NEWKEYSET = 0x00000008
CALG_SHA1 = 0x00008004
CALG_RC4 = 0x00006801


class Rc4Sha1:
    def __init__(self, key_bytes: bytes):
        self._hProv = HCRYPTPROV()
        if not self._acquire_provider():
            raise OSError(ctypes.get_last_error(), "CryptAcquireContextW failed")
        self._hHash = HCRYPTHASH()
        self._hKey = HCRYPTKEY()
        if not CryptCreateHash(self._hProv, CALG_SHA1, HCRYPTKEY(), 0, ctypes.byref(self._hHash)):
            self.close()
            raise OSError(ctypes.get_last_error(), "CryptCreateHash(CALG_SHA1) failed")
        buf = (ctypes.c_ubyte * len(key_bytes)).from_buffer_copy(key_bytes)
        if not CryptHashData(self._hHash, buf, len(key_bytes), 0):
            self.close()
            raise OSError(ctypes.get_last_error(), "CryptHashData failed")
        if not CryptDeriveKey(self._hProv, CALG_RC4, self._hHash, 0, ctypes.byref(self._hKey)):
            self.close()
            raise OSError(ctypes.get_last_error(), "CryptDeriveKey(CALG_RC4) failed")
        CryptDestroyHash(self._hHash)
        self._hHash = HCRYPTHASH()

    def _acquire_provider(self) -> bool:
        provider = "Microsoft Enhanced Cryptographic Provider v1.0"
        if CryptAcquireContextW(ctypes.byref(self._hProv), None, provider, PROV_RSA_FULL, 0):
            return True
        if CryptAcquireContextW(ctypes.byref(self._hProv), None, provider, PROV_RSA_FULL, CRYPT_NEWKEYSET):
            return True
        return CryptAcquireContextW(ctypes.byref(self._hProv), None, None, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)

    def decrypt(self, data_bytes: bytes) -> bytes:
        buf = ctypes.create_string_buffer(data_bytes, len(data_bytes))
        dlen = wintypes.DWORD(len(data_bytes))
        if not CryptDecrypt(self._hKey, HCRYPTHASH(), True, 0, buf, ctypes.byref(dlen)):
            raise OSError(ctypes.get_last_error(), "CryptDecrypt failed")
        return buf.raw[: dlen.value]

    def close(self) -> None:
        if getattr(self, "_hKey", None) and self._hKey.value:
            CryptDestroyKey(self._hKey)
            self._hKey = HCRYPTKEY()
        if getattr(self, "_hHash", None) and self._hHash.value:
            CryptDestroyHash(self._hHash)
            self._hHash = HCRYPTHASH()
        if getattr(self, "_hProv", None) and self._hProv.value:
            CryptReleaseContext(self._hProv, 0)
            self._hProv = HCRYPTPROV()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def parse_sqlite_page_size(plain_header: bytes) -> int:
    if len(plain_header) < 18:
        raise ValueError("header too short")
    page_size = int.from_bytes(plain_header[16:18], "big")
    if page_size == 1:
        return 65536
    return page_size


def default_out_path(account: str) -> Path:
    script_dir = Path(__file__).resolve().parent
    return script_dir / f"{account}.sqlite"


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt RaidCall .dat (encrypted SQLite) into a normal SQLite DB.")
    parser.add_argument("dat", type=Path, help="Path to <account>.dat")
    parser.add_argument("--account", help="Account string (default: dat file stem, e.g. name@domain)")
    parser.add_argument("--out", type=Path, help="Output .sqlite path (default: next to this script)")
    parser.add_argument("--force", action="store_true", help="Overwrite output file if it exists")
    parser.add_argument("--no-verify", action="store_true", help="Skip SQLite header check")
    args = parser.parse_args()

    dat_path: Path = args.dat
    if not dat_path.is_file():
        print(f"error: not found: {dat_path}", file=sys.stderr)
        return 2

    account = args.account or dat_path.stem
    try:
        plain_key = derive_plain_key(account)
    except ValueError as e:
        print(f"error: cannot derive key from account {account!r}: {e}", file=sys.stderr)
        return 2

    out_path: Path = args.out or default_out_path(account)
    if out_path.exists() and not args.force:
        print(f"error: output already exists: {out_path} (use --force)", file=sys.stderr)
        return 2
    out_path.parent.mkdir(parents=True, exist_ok=True)

    key_bytes = plain_key.encode("ascii")
    with Rc4Sha1(key_bytes) as rc4:
        with dat_path.open("rb") as f:
            enc_header = f.read(100)
        plain_header = rc4.decrypt(enc_header)
        if not args.no_verify:
            if not plain_header.startswith(b"SQLite format 3\x00"):
                print("error: decrypted header is not SQLite; wrong account/key?", file=sys.stderr)
                print(f"  dat={dat_path}", file=sys.stderr)
                print(f"  account={account}", file=sys.stderr)
                print(f"  derived_key={plain_key}", file=sys.stderr)
                return 1
        page_size = parse_sqlite_page_size(plain_header)
        if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
            print(f"error: suspicious page size {page_size} (header decrypted but not sane)", file=sys.stderr)
            return 1

        with dat_path.open("rb") as fi, out_path.open("wb") as fo:
            while True:
                chunk = fi.read(page_size)
                if not chunk:
                    break
                fo.write(rc4.decrypt(chunk))

    print(f"dat:         {dat_path}")
    print(f"account:     {account}")
    print(f"derived_key: {plain_key}  (ascii)")
    print(f"page_size:   {page_size}")
    print(f"sqlite_out:  {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
