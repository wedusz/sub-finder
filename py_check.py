#!/usr/bin/env python3
"""py_check.py - verifikasi toolchain Python + pip + UA harness."""
import os, sys, ssl, shutil, sqlite3, platform, subprocess

UA = os.environ.get("UA") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0"
if not UA.startswith("Mozilla/5.0 (Windows NT 10.0"):
    sys.exit(2)


def sh(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (p.stdout or p.stderr).strip().splitlines()[0]
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"


print("python  :", sys.version.split()[0], platform.machine())
print("exe     :", sys.executable)
print("pip     :", sh([sys.executable, "-m", "pip", "-V"]))
print("pipx    :", sh([sys.executable, "-m", "pipx", "--version"]))
print("venv    :", sh([sys.executable, "-m", "venv", "-h"]) and "available")
print("pipx bin:", shutil.which("pipx") or os.path.expanduser("~/.local/bin/pipx.exe"))
print("openssl :", ssl.OPENSSL_VERSION)
print("sqlite  :", sqlite3.sqlite_version)
print("cacert  :", sh([sys.executable, "-c", "import certifi;print(certifi.where())"]))

try:
    import requests
    r = requests.get("https://httpbin.org/headers", headers={"User-Agent": UA}, timeout=25)
    print("http    :", r.status_code, "| UA echo:", r.json()["headers"]["User-Agent"])
except Exception as e:
    print("http    : SKIP", type(e).__name__, e)
