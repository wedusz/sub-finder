#!/usr/bin/env python3
"""subenum.py — passive subdomain enumeration + DNS resolve.

Sumber pasif: hackertarget, rapiddns, crt.sh (retry), certspotter.
Output: CSV (host,ip,cname,source) + list polos untuk tool lain.

Pakai:
    python subenum.py target.com -o out/batam
    python subenum.py target.com --resolve-only -i out/batam_subs.txt
"""
import argparse
import csv
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

UA = os.environ.get("UA") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) "
    "Gecko/20100101 Firefox/160.0"
)
if not UA.startswith("Mozilla/5.0 (Windows NT 10.0"):
    sys.exit(2)

S = requests.Session()
S.headers.update({"User-Agent": UA, "Accept": "application/json, text/html;q=0.9"})
TIMEOUT = 25


def _get(url, **kw):
    for attempt in range(3):
        try:
            r = S.get(url, timeout=TIMEOUT, **kw)
            if r.status_code == 200:
                return r
        except requests.RequestException:
            pass
        time.sleep(1.5 * (attempt + 1))
    return None


def from_hackertarget(domain):
    r = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not r or "error" in r.text[:40].lower():
        return set()
    return {
        ln.split(",")[0].strip().lower()
        for ln in r.text.splitlines()
        if "," in ln
    }


def from_crtsh(domain):
    r = _get(f"https://crt.sh/?q=%25.{domain}&output=json")
    out = set()
    if not r:
        return out
    try:
        rows = json.loads(r.text)
    except json.JSONDecodeError:
        return out
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            out.add(name.strip().lower().lstrip("*."))
    return out


def from_rapiddns(domain):
    out = set()
    for page in range(1, 4):
        r = _get(f"https://rapiddns.io/subdomain/{domain}?full=1&page={page}")
        if not r:
            break
        found = set(re.findall(rf"([a-z0-9_.-]+\.{re.escape(domain)})", r.text, re.I))
        found = {f.lower().lstrip("*.") for f in found}
        if not found or found <= out:
            break
        out |= found
    return out


def from_certspotter(domain):
    r = _get(f"https://api.certspotter.com/v1/issuances?domain={domain}"
             "&include_subdomains=true&expand=dns_names")
    out = set()
    if not r:
        return out
    try:
        for row in r.json():
            for name in row.get("dns_names", []):
                out.add(name.lower().lstrip("*."))
    except (json.JSONDecodeError, AttributeError):
        pass
    return out


SOURCES = {
    "hackertarget": from_hackertarget,
    "crtsh": from_crtsh,
    "rapiddns": from_rapiddns,
    "certspotter": from_certspotter,
}


def collect(domain, workers=4):
    """Kumpulkan nama unik dari semua sumber pasif (paralel)."""
    hits = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, domain): name for name, fn in SOURCES.items()}
        for fut, name in futs.items():
            try:
                names = fut.result()
            except Exception as exc:  # sumber mati tidak menghentikan run
                print(f"[-] {name}: {exc}", file=sys.stderr)
                continue
            print(f"[+] {name}: {len(names)}", file=sys.stderr)
            for n in names:
                if n.endswith("." + domain) or n == domain:
                    hits.setdefault(n, set()).add(name)
    return hits


def resolve(host):
    """A record + CNAME via socket (tanpa dependensi dnspython)."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return host, "", "", False
    cname = ""
    try:
        cname = socket.getfqdn(host) if socket.getfqdn(host) != host else ""
    except OSError:
        pass
    return host, ip, cname, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("-o", "--out", default=None, help="prefix output")
    ap.add_argument("-t", "--threads", type=int, default=32)
    ap.add_argument("--resolve-only", action="store_true")
    ap.add_argument("-i", "--input", help="file daftar host untuk resolve-only")
    args = ap.parse_args()

    prefix = args.out or args.domain.replace(".", "_")
    os.makedirs(os.path.dirname(prefix) or ".", exist_ok=True)

    if args.resolve_only and args.input:
        hosts = [l.strip() for l in open(args.input, encoding="utf-8") if l.strip()]
        srcmap = {h: {"input"} for h in hosts}
    else:
        srcmap = collect(args.domain)
        hosts = sorted(srcmap)

    print(f"[*] {len(hosts)} host unik, resolving...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        rows = list(ex.map(resolve, hosts))

    live = [r for r in rows if r[3]]
    with open(f"{prefix}_dns.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "ip", "cname", "alive", "sources"])
        for host, ip, cname, alive in rows:
            w.writerow([host, ip, cname, int(alive), ";".join(sorted(srcmap.get(host, [])))])
    with open(f"{prefix}_subs.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(h for h, *_ in rows) + "\n")
    with open(f"{prefix}_live.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(r[0] for r in live) + "\n")

    ips = sorted({r[1] for r in live})
    print(f"[=] {len(hosts)} nama, {len(live)} resolve, {len(ips)} IP unik")
    print(f"[=] {prefix}_dns.csv | {prefix}_subs.txt | {prefix}_live.txt")


if __name__ == "__main__":
    main()
