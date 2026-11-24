#!/usr/bin/env python3
"""
subfinder_live.py - enumerasi subdomain + deteksi server yang HIDUP (DNS + HTTP).

Fitur
  * passive enum : crt.sh, hackertarget, alienvault OTX (paralel, graceful fail)
  * brute force  : wordlist internal / -w file
  * DNS resolve  : A / AAAA / CNAME via dnspython async
  * wildcard guard: deteksi *.domain lalu buang false positive
  * HTTP probe   : https -> http fallback, multi-port, status/title/server/redirect
  * rate limit   : token bucket global (DNS & HTTP terpisah) + adaptive slowdown
                   saat kena 429/503, hormati Retry-After, retry berjenjang
  * output       : tabel rich, JSON, CSV, txt khusus host hidup

Pemakaian
  python subfinder_live.py example.com
  python subfinder_live.py example.com -w words.txt -t 200 --ports 443,80,8080
  python subfinder_live.py -l domains.txt --all --json out.json --csv out.csv
  python subfinder_live.py example.com --no-passive --no-brute   # cuma resolve daftar -w
  python subfinder_live.py example.com --rate 20 --dns-rate 200  # lambat, sopan
  python subfinder_live.py example.com --rate 0                  # tanpa limit (agresif)

UA global: env UA (fallback literal Firefox 160). Exit 2 kalau UA kosong/aneh.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import re
import socket
import string
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

UA = os.environ.get("UA") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0"
)
if not UA.startswith("Mozilla/5.0 (Windows NT 10.0"):
    sys.exit(2)

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except ImportError:
    sys.exit("[!] pip install dnspython")

try:
    import httpx
except ImportError:
    sys.exit("[!] pip install httpx")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn,
    )
except ImportError:
    sys.exit("[!] pip install rich")

if sys.platform == "win32":
    # dnspython async butuh add_reader -> SelectorEventLoop, bukan Proactor
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

console = Console(highlight=False)

DEFAULT_WORDS = """
www mail smtp pop imap webmail ns1 ns2 ns3 dns dns1 dns2 mx mx1 mx2 mail1 mail2
ftp sftp ssh vpn remote gateway gw proxy api apis api1 api2 api-dev api-staging
app apps web portal login sso auth id identity accounts account admin administrator
panel cpanel whm plesk dashboard manage management console control cp
dev develop development dev1 dev2 dev3 staging stage stg stg1 staging1 test testing
test1 test2 qa uat preprod prod production demo sandbox beta alpha preview
static assets cdn img images media files upload uploads download downloads docs
doc wiki help support status health metrics monitor monitoring grafana kibana
prometheus nagios zabbix logs log analytics stats tracker
blog news shop store cart payment payments pay checkout billing invoice
db database mysql postgres sql mssql redis mongo mongodb elastic elasticsearch
cache memcached queue rabbitmq kafka mq broker
git gitlab github jenkins ci cd build registry docker k8s kubernetes rancher
jira confluence sonar nexus artifactory vault consul nomad
s3 storage backup bak archive old legacy new v2 v3 internal intranet extranet
office owa exchange autodiscover autoconfig relay lists list mailer mta mx01
edge origin lb lb1 node node1 server server1 host host1
m mobile touch wap 4g im apn sip voip pbx
ns ns4 ns5 resolver root zone dns3 dns4
""".split()

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


class RateLimiter:
    """Token bucket async + global cooldown (adaptive saat target membalas 429/503).

    rate <= 0 berarti tanpa limit (mode agresif).
    """

    def __init__(self, rate: float, name: str = "http", burst: float | None = None):
        self.rate = float(rate)
        self.name = name
        self.burst = float(burst if burst is not None else max(1.0, self.rate))
        self.tokens = self.burst
        self.updated = time.monotonic()
        self.pause_until = 0.0
        self.lock = asyncio.Lock()
        self.granted = 0
        self.waited = 0
        self.penalties = 0
        self.penalty_total = 0.0

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    async def acquire(self, cost: float = 1.0) -> None:
        if not self.enabled:
            self.granted += 1
            return
        while True:
            wait = 0.0
            async with self.lock:
                now = time.monotonic()
                if now < self.pause_until:
                    wait = self.pause_until - now
                else:
                    self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
                    self.updated = now
                    if self.tokens >= cost:
                        self.tokens -= cost
                        self.granted += 1
                        return
                    wait = (cost - self.tokens) / self.rate
            self.waited += 1
            await asyncio.sleep(wait)

    def penalize(self, seconds: float) -> None:
        """Blok semua worker selama `seconds` (dipakai saat 429/503/timeout)."""
        if not self.enabled or seconds <= 0:
            return
        now = time.monotonic()
        self.pause_until = max(self.pause_until, now + seconds)
        self.tokens = 0.0
        self.updated = now
        self.penalties += 1
        self.penalty_total += seconds

    def stats(self) -> str:
        if not self.enabled:
            return f"{self.name}: unlimited ({self.granted} req)"
        return (
            f"{self.name}: {self.rate:g}/s, {self.granted} req, "
            f"{self.waited} antre, {self.penalties} penalty "
            f"({self.penalty_total:.1f}s)"
        )


def parse_retry_after(value: str | None, default: float) -> float:
    if not value:
        return default
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        # format HTTP-date -> pakai default saja
        return default


def backoff_delay(base: float, attempt: int, cap: float = 30.0) -> float:
    """Exponential backoff + jitter."""
    return min(cap, base * (2 ** attempt)) * (0.75 + random.random() * 0.5)


@dataclass
class Result:
    host: str
    ips: list[str] = field(default_factory=list)
    cname: str = ""
    alive_dns: bool = False
    wildcard: bool = False
    status: int = 0
    url: str = ""
    server: str = ""
    title: str = ""
    redirect: str = ""
    length: int = 0
    rt_ms: int = 0
    error: str = ""

    @property
    def live(self) -> bool:
        return self.alive_dns and self.status > 0


def load_words(path: str | None) -> list[str]:
    if not path:
        return sorted(set(DEFAULT_WORDS))
    p = Path(path)
    if not p.is_file():
        sys.exit(f"[!] wordlist tidak ada: {path}")
    words = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            words.append(line)
    return sorted(set(words))


# ---------------------------------------------------------------- DNS
class Resolver:
    def __init__(self, nameservers: list[str] | None, timeout: float,
                 limiter: RateLimiter | None = None, retries: int = 2):
        self.r = dns.asyncresolver.Resolver(configure=not bool(nameservers))
        if nameservers:
            self.r.nameservers = nameservers
        self.r.timeout = timeout
        self.r.lifetime = timeout * 2
        self.r.retry_servfail = False
        self.limiter = limiter
        self.retries = retries

    async def _query(self, host: str, rdtype: str):
        for attempt in range(self.retries + 1):
            if self.limiter:
                await self.limiter.acquire()
            try:
                return await self.r.resolve(host, rdtype, raise_on_no_answer=False)
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                if attempt >= self.retries:
                    raise
                # server DNS membatasi -> jeda global sebelum ulang
                if self.limiter:
                    self.limiter.penalize(backoff_delay(0.4, attempt, 5.0))
                await asyncio.sleep(backoff_delay(0.2, attempt, 3.0))
                continue
        return None

    async def resolve(self, host: str) -> tuple[list[str], str]:
        ips: set[str] = set()
        cname = ""
        for rdtype in ("A", "AAAA"):
            try:
                ans = await self._query(host, rdtype)
                if ans is not None:
                    for rr in ans:
                        ips.add(rr.address)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.exception.Timeout, dns.resolver.NoNameservers,
                    dns.exception.DNSException):
                pass
        try:
            ans = await self._query(host, "CNAME")
            if ans is not None:
                for rr in ans:
                    cname = str(rr.target).rstrip(".")
        except Exception:
            pass
        return sorted(ips), cname


async def wildcard_ips(res: Resolver, domain: str, samples: int = 3) -> set[str]:
    found: set[str] = set()
    for _ in range(samples):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        ips, _ = await res.resolve(f"{label}.{domain}")
        found.update(ips)
    return found


# ---------------------------------------------------------------- passive
async def passive_crtsh(client: httpx.AsyncClient, domain: str,
                        limiter: RateLimiter | None = None) -> set[str]:
    out: set[str] = set()
    try:
        if limiter:
            await limiter.acquire()
        r = await client.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=60
        )
        if r.status_code == 200 and r.text.strip().startswith("["):
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    out.add(name.strip().lower().lstrip("*.").rstrip("."))
    except Exception as e:
        console.print(f"[dim]crt.sh gagal: {type(e).__name__}[/dim]")
    return out


async def passive_hackertarget(client: httpx.AsyncClient, domain: str,
                               limiter: RateLimiter | None = None) -> set[str]:
    out: set[str] = set()
    try:
        if limiter:
            await limiter.acquire()
        r = await client.get(
            "https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=30
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:80]:
            for line in r.text.splitlines():
                if "," in line:
                    out.add(line.split(",")[0].strip().lower())
    except Exception as e:
        console.print(f"[dim]hackertarget gagal: {type(e).__name__}[/dim]")
    return out


async def passive_otx(client: httpx.AsyncClient, domain: str,
                      limiter: RateLimiter | None = None) -> set[str]:
    out: set[str] = set()
    try:
        if limiter:
            await limiter.acquire()
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=45,
        )
        if r.status_code == 200:
            for row in r.json().get("passive_dns", []):
                h = str(row.get("hostname", "")).strip().lower().rstrip(".")
                if h:
                    out.add(h)
    except Exception as e:
        console.print(f"[dim]otx gagal: {type(e).__name__}[/dim]")
    return out


# ---------------------------------------------------------------- HTTP
def extract_title(body: bytes) -> str:
    m = TITLE_RE.search(body[:65536])
    if not m:
        return ""
    t = re.sub(rb"\s+", b" ", m.group(1)).decode("utf-8", "replace").strip()
    return t[:90]


RETRY_STATUS = {429, 502, 503, 504}


async def probe(client: httpx.AsyncClient, host: str, ports: list[int], rt_limit: float,
                limiter: RateLimiter | None = None, retries: int = 2) -> Result:
    """Probe https lalu http. Rate limit dipegang di sini supaya retry ikut dihitung."""
    res = Result(host=host)
    schemes = [("https", p) for p in ports] + [("http", p) for p in ports]
    for scheme, port in schemes:
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        url = f"{scheme}://{host}" + ("" if default else f":{port}") + "/"
        for attempt in range(retries + 1):
            if limiter:
                await limiter.acquire()
            t0 = time.perf_counter()
            try:
                r = await client.get(url, timeout=rt_limit)
            except Exception as e:
                res.error = f"{type(e).__name__}"
                if limiter and isinstance(e, (httpx.TimeoutException, httpx.ConnectError)):
                    limiter.penalize(backoff_delay(0.25, attempt, 3.0))
                break
            res.rt_ms = int((time.perf_counter() - t0) * 1000)
            res.status = r.status_code
            res.url = url
            res.server = r.headers.get("server", "")[:40]
            res.redirect = r.headers.get("location", "")[:120]
            res.length = int(r.headers.get("content-length") or len(r.content))
            res.title = extract_title(r.content)
            if r.status_code in RETRY_STATUS and attempt < retries:
                # target membatasi -> jeda global, semua worker ikut berhenti
                delay = parse_retry_after(r.headers.get("retry-after"),
                                          backoff_delay(0.5, attempt))
                if limiter:
                    limiter.penalize(delay)
                else:
                    await asyncio.sleep(delay)
                res.error = f"retry:{r.status_code}"
                continue
            return res
    return res


# ---------------------------------------------------------------- pipeline
async def run(args: argparse.Namespace) -> int:
    words = load_words(args.wordlist) if not args.no_brute else []
    domains = args.domains
    dns_limiter = RateLimiter(args.dns_rate, "dns")
    http_limiter = RateLimiter(args.rate, "http")
    resolver = Resolver(args.ns, args.timeout, limiter=dns_limiter)

    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5"}
    limits = httpx.Limits(max_connections=args.threads, max_keepalive_connections=args.threads // 2)
    all_rows: list[Result] = []

    async with httpx.AsyncClient(
        headers=headers, verify=False, follow_redirects=False,
        limits=limits, http2=False,
    ) as client:
        for domain in domains:
            domain = domain.strip().lower().lstrip("*.").rstrip(".")
            if not domain or "." not in domain:
                console.print(f"[yellow]skip domain tidak valid: {domain!r}[/yellow]")
                continue

            console.rule(f"[bold cyan]{domain}")
            candidates: set[str] = set()

            if not args.no_passive:
                with console.status("passive enum: crt.sh / hackertarget / otx"):
                    found = await asyncio.gather(
                        passive_crtsh(client, domain, http_limiter),
                        passive_hackertarget(client, domain, http_limiter),
                        passive_otx(client, domain, http_limiter),
                        return_exceptions=True,
                    )
                for chunk in found:
                    if isinstance(chunk, set):
                        candidates |= chunk
                console.print(f"[dim]passive: {len(candidates)} nama[/dim]")

            for w in words:
                candidates.add(w if "." in w else f"{w}.{domain}")

            # filter: hanya yang berakhiran domain ini dan bukan domain itu sendiri
            candidates = {
                c for c in candidates
                if (c == domain or c.endswith("." + domain)) and re.fullmatch(r"[a-z0-9._-]+", c)
            }
            candidates.discard(domain)
            console.print(f"[dim]kandidat total: {len(candidates)}[/dim]")

            wild = await wildcard_ips(resolver, domain) if candidates else set()
            if wild:
                console.print(f"[yellow]wildcard DNS terdeteksi -> {sorted(wild)}[/yellow]")

            sem = asyncio.Semaphore(args.threads)

            async def check(host: str) -> Result | None:
                async with sem:
                    row = Result(host=host)
                    row.ips, row.cname = await resolver.resolve(host)
                    row.alive_dns = bool(row.ips or row.cname)
                    if not row.alive_dns:
                        return row if args.all else None
                    if wild and set(row.ips) <= wild and not args.all:
                        row.wildcard = True
                        return None
                    return row

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                console=console, transient=True,
            ) as prog:
                task = prog.add_task("dns", total=len(candidates))
                dns_rows: list[Result] = []
                batch = 2000
                cand_list = sorted(candidates)
                for i in range(0, len(cand_list), batch):
                    chunk = cand_list[i:i + batch]
                    for r in await asyncio.gather(*(check(h) for h in chunk)):
                        if r is not None:
                            dns_rows.append(r)
                        prog.advance(task)
                prog.update(task, description="http")

                # probe hanya host yang punya DNS
                alive = [r for r in dns_rows if r.alive_dns]
                task2 = prog.add_task("http", total=len(alive))
                results: list[Result] = []

                async def do_probe(row: Result) -> Result:
                    async with sem:
                        p = await probe(client, row.host, args.ports, args.timeout,
                                        limiter=http_limiter, retries=args.retries)
                        row.status, row.url, row.server = p.status, p.url, p.server
                        row.title, row.redirect, row.length, row.rt_ms = (
                            p.title, p.redirect, p.length, p.rt_ms
                        )
                        prog.advance(task2)
                        return row

                probed = await asyncio.gather(*(do_probe(r) for r in alive)) if alive else []
                results = probed + [r for r in dns_rows if not r.alive_dns]

            results.sort(key=lambda r: (not r.live, r.host))
            all_rows.extend(results)

            table = Table(title=f"{domain} - {sum(1 for r in results if r.live)} hidup / "
                                f"{len(results)} hasil", show_lines=False)
            for col, just in (
                ("subdomain", "left"), ("ip", "left"), ("dns", "center"), ("http", "center"),
                ("server", "left"), ("title", "left"),
            ):
                table.add_column(col, justify=just, overflow="fold")
            for r in results[: args.show]:
                if not r.live and not args.all:
                    continue
                dns_txt = "[green]ok[/green]" if r.alive_dns else "[red]x[/red]"
                if r.wildcard:
                    dns_txt = "[yellow]wild[/yellow]"
                http_txt = (
                    f"[green]{r.status}[/green]" if 200 <= r.status < 300
                    else f"[cyan]{r.status}[/cyan]" if 300 <= r.status < 400
                    else f"[yellow]{r.status}[/yellow]" if r.status
                    else "[red]-[/red]"
                )
                table.add_row(
                    r.host, ",".join(r.ips)[:40], dns_txt, http_txt,
                    r.server or "-", (r.title or r.redirect or "-")[:70],
                )
            console.print(table)

            if args.outdir:
                write_outputs(domain, results, Path(args.outdir))

    if args.json:
        Path(args.json).write_text(json.dumps([asdict(r) for r in all_rows], indent=2), encoding="utf-8")
        console.print(f"[green]+[/green] json -> {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["host", "ips", "cname", "alive_dns", "wildcard", "status",
                        "url", "server", "title", "redirect", "length", "rt_ms"])
            for r in all_rows:
                w.writerow([r.host, ";".join(r.ips), r.cname, r.alive_dns, r.wildcard,
                            r.status, r.url, r.server, r.title, r.redirect, r.length, r.rt_ms])
        console.print(f"[green]+[/green] csv -> {args.csv}")

    live = [r for r in all_rows if r.live]
    console.print(
        f"\n[bold]TOTAL[/bold] {len(all_rows)} hasil, "
        f"[bold green]{len(live)} server hidup[/bold green]"
    )
    for r in live:
        console.print(f"  [green]{r.status:<4}[/green] {r.host:<45} {r.server or '-':<18} {r.title[:50]}")
    console.print(f"[dim]{dns_limiter.stats()} | {http_limiter.stats()}[/dim]")
    return 0


def write_outputs(domain: str, rows: list[Result], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = outdir / f"{domain.replace('.', '_')}_{stamp}"
    base.with_suffix(".json").write_text(
        json.dumps([asdict(r) for r in rows], indent=2), encoding="utf-8"
    )
    base.with_suffix(".txt").write_text(
        "\n".join(f"{r.host}\t{r.status}\t{r.url}\t{r.title}" for r in rows if r.live) + "\n",
        encoding="utf-8",
    )
    console.print(f"[green]+[/green] {base}.json / .txt")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Subdomain finder + live server detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("domains", nargs="*", help="domain target")
    p.add_argument("-l", "--list", help="file berisi daftar domain (satu per baris)")
    p.add_argument("-w", "--wordlist", help="wordlist subdomain (default internal)")
    p.add_argument("-t", "--threads", type=int, default=100, help="concurrency")
    p.add_argument("--timeout", type=float, default=8.0, help="timeout per request/dns (detik)")
    p.add_argument("--rate", type=float, default=25.0,
                   help="limit request HTTP per detik, 0 = tanpa limit")
    p.add_argument("--dns-rate", type=float, default=150.0,
                   help="limit query DNS per detik, 0 = tanpa limit")
    p.add_argument("--retries", type=int, default=2,
                   help="retry saat 429/502/503/504 atau timeout")
    p.add_argument("--ports", default="443,80", help="port HTTP probe, pisah koma")
    p.add_argument("--ns", default="", help="nameserver custom, pisah koma (mis. 1.1.1.1,8.8.8.8)")
    p.add_argument("--no-passive", action="store_true", help="matikan crt.sh/otx/hackertarget")
    p.add_argument("--no-brute", action="store_true", help="matikan wordlist (hanya hasil passive)")
    p.add_argument("--all", action="store_true", help="tampilkan juga host mati/wildcard")
    p.add_argument("--show", type=int, default=200, help="maks baris tabel per domain")
    p.add_argument("--outdir", default="out", help="folder output json+txt per domain")
    p.add_argument("--json", help="simpan semua hasil gabungan ke file json")
    p.add_argument("--csv", help="simpan semua hasil gabungan ke file csv")
    a = p.parse_args(argv)

    if a.list:
        a.domains += [
            ln.strip() for ln in Path(a.list).read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    if not a.domains:
        p.error("butuh minimal satu domain atau -l file")
    a.ports = [int(x) for x in a.ports.split(",") if x.strip()]
    a.ns = [x.strip() for x in a.ns.split(",") if x.strip()] or None
    return a


def main() -> int:
    args = parse_args(sys.argv[1:])
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
