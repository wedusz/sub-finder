# sub-finder

Subdomain enumeration and live-host detection for recon pipelines.
Two independent scanners plus a toolchain self-check, all plain Python with a single
shared `User-Agent` contract.

```
┌─ subfinder_live.py ─ passive enum + brute force + wildcard guard + DNS + HTTP probe + rate limit
├─ subenum.py ──────── passive enum (4 sources) + fast DNS resolve, CSV/TXT output
└─ py_check.py ─────── environment sanity check (python, pip, TLS, UA echo)
```

| File | Style | Deps | Output |
| --- | --- | --- | --- |
| `subfinder_live.py` | async (`asyncio` + `httpx` + `dnspython` + `rich`) | 3 packages | rich table, JSON, CSV, per-domain TXT |
| `subenum.py` | threads (`requests` + `socket`) | 1 package | CSV + plain host lists |
| `py_check.py` | sync | stdlib (+ optional `requests`, `certifi`) | stdout report |

Use `subfinder_live.py` when you need HTTP truth (status/server/title) and polite rate limiting.
Use `subenum.py` when you only need names and A records fast, with near-zero dependencies.

## Install

```bash
pip install dnspython httpx rich requests certifi
```

`subfinder_live.py` needs `dnspython`, `httpx`, `rich`.
`subenum.py` needs only `requests`. `py_check.py` runs on the stdlib alone.

Python 3.10+. On Windows the async script switches to `WindowsSelectorEventLoopPolicy`
because `dnspython` async requires `add_reader`.

---

## subfinder_live.py

```
passive (crt.sh, hackertarget, OTX)  ─┐
                                      ├─▶ filter to *.domain ─▶ wildcard guard ─▶ DNS A/AAAA/CNAME ─▶ HTTP probe ─▶ report
internal / custom wordlist (brute)   ─┘
```

### Features

- **Passive enumeration** — `crt.sh`, `api.hackertarget.com`, AlienVault OTX in parallel, each failing independently.
- **Brute force** — built-in wordlist or your own file via `-w`.
- **DNS resolution** — async `A` / `AAAA` / `CNAME` with optional custom resolvers.
- **Wildcard guard** — probes 3 random labels and drops hosts that resolve only to wildcard IPs.
- **HTTP probing** — `https` then `http`, multiple ports, records status, `Server`, title, redirect, length, latency.
- **Global token-bucket rate limiting** — separate DNS and HTTP budgets, adaptive cooldown on `429/502/503/504`, honors `Retry-After`, exponential backoff with jitter.
- **Outputs** — terminal table, merged `--json` / `--csv`, per-domain `--outdir` JSON + live-host TXT.

### Usage

```bash
python subfinder_live.py example.com
```

```
usage: subfinder_live.py [-h] [-l LIST] [-w WORDLIST] [-t THREADS] [--timeout TIMEOUT]
                         [--rate RATE] [--dns-rate DNS_RATE] [--retries RETRIES]
                         [--ports PORTS] [--ns NS] [--no-passive] [--no-brute]
                         [--all] [--show SHOW] [--outdir OUTDIR] [--json JSON] [--csv CSV]
                         domains ...
```

| Flag | Default | Description |
| --- | --- | --- |
| `domains` | – | One or more target domains (positional). |
| `-l, --list` | – | File of domains, one per line, `#` comments allowed. |
| `-w, --wordlist` | built-in | Custom wordlist (label or FQDN per line). |
| `-t, --threads` | `100` | Concurrency for DNS checks and HTTP probes. |
| `--timeout` | `8.0` | Per-request / per-query timeout (seconds). |
| `--rate` | `25` | HTTP requests per second. `0` = unlimited. |
| `--dns-rate` | `150` | DNS queries per second. `0` = unlimited. |
| `--retries` | `2` | Retries on `429/502/503/504` and timeouts. |
| `--ports` | `443,80` | Comma-separated probe ports (https first, then http). |
| `--ns` | system | Custom nameservers, e.g. `1.1.1.1,8.8.8.8`. |
| `--no-passive` | off | Disable crt.sh / hackertarget / OTX. |
| `--no-brute` | off | Disable wordlist, resolve passive results only. |
| `--all` | off | Also show dead and wildcard hosts. |
| `--show` | `200` | Max table rows printed per domain. |
| `--outdir` | `out` | Per-domain `.json` + `.txt` directory. `""` disables. |
| `--json` | – | Write all results to one JSON file. |
| `--csv` | – | Write all results to one CSV file. |

### Examples

```bash
# passive + brute, default ports
python subfinder_live.py example.com

# custom wordlist, extra ports
python subfinder_live.py example.com -w words.txt -t 200 --ports 443,80,8080,8443

# many domains, export everything
python subfinder_live.py -l domains.txt --json out.json --csv out.csv

# passive only
python subfinder_live.py example.com --no-brute

# polite scanning
python subfinder_live.py example.com --rate 10 --dns-rate 50 --retries 3

# no throttling (own infrastructure only)
python subfinder_live.py example.com --rate 0 --dns-rate 0 -t 400

# explicit resolvers, include dead hosts in the table
python subfinder_live.py example.com --ns 1.1.1.1,9.9.9.9 --all
```

### Output

Terminal: per-domain `rich` table with `subdomain`, `ip`, `dns`, `http`, `server`, `title`,
then a summary of live servers and limiter statistics.

Files:

- `out/<domain>_<YYYYmmdd-HHMMSS>.json` — all results for that domain.
- `out/<domain>_<YYYYmmdd-HHMMSS>.txt` — live hosts, tab-separated `host  status  url  title`.
- `--json` / `--csv` — merged results across all domains.

Record shape:

```json
{
  "host": "api.example.com",
  "ips": ["203.0.113.10"],
  "cname": "",
  "alive_dns": true,
  "wildcard": false,
  "status": 200,
  "url": "https://api.example.com/",
  "server": "nginx",
  "title": "API Gateway",
  "redirect": "",
  "length": 5123,
  "rt_ms": 143,
  "error": ""
}
```

A host is **live** when it resolves via DNS **and** returns an HTTP status code.

### Rate limiting behaviour

`RateLimiter` is a shared token bucket per protocol. On `429/502/503/504`, a connection error,
or a DNS timeout it sets a global `pause_until`, so every worker pauses together instead of
each hammering the target independently. Numeric `Retry-After` is honored; HTTP-date values
fall back to exponential backoff (`base * 2^attempt`, capped at 30 s, ±25% jitter).

---

## subenum.py

Passive-only enumeration with four sources and a fast thread-pool resolver. No `dnspython`,
no async, no HTTP probing — just names, IPs and CNAMEs.

Sources: `hackertarget`, `crtsh`, `rapiddns` (3 pages), `certspotter`.

```bash
python subenum.py target.com -o out/target
python subenum.py target.com -t 64
python subenum.py target.com --resolve-only -i out/target_subs.txt
```

| Flag | Default | Description |
| --- | --- | --- |
| `domain` | – | Target domain (positional). |
| `-o, --out` | `<domain>_` | Output prefix, directories created as needed. |
| `-t, --threads` | `32` | Resolver thread count. |
| `--resolve-only` | off | Skip passive enum, resolve hosts from `-i`. |
| `-i, --input` | – | Host list for `--resolve-only`. |

Outputs (written next to the prefix):

| File | Content |
| --- | --- |
| `<prefix>_dns.csv` | `host, ip, cname, alive, sources` |
| `<prefix>_subs.txt` | every discovered host |
| `<prefix>_live.txt` | hosts that resolved |

`resolve()` uses `socket.gethostbyname` plus `socket.getfqdn`, so CNAME values are best-effort
and may be empty behind CDNs.

---

## py_check.py

Prints the local Python toolchain state and echoes the `User-Agent` back from `httpbin.org`
to prove the UA contract holds end to end.

```bash
python py_check.py
```

```
python  : 3.13.5 AMD64
exe     : C:\...\python.exe
pip     : pip 25.x ...
venv    : available
openssl : OpenSSL 3.x
sqlite  : 3.x
cacert  : C:\...\certifi\cacert.pem
http    : 200 | UA echo: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0
```

Missing optional pieces print `SKIP` or `ERR` instead of failing the run.

---

## User-Agent contract

Every script resolves one UA at import and refuses to run with a tampered value:

```python
UA = os.environ.get("UA") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0"
if not UA.startswith("Mozilla/5.0 (Windows NT 10.0"):
    sys.exit(2)
```

```bash
export UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0'
```

```powershell
$env:UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0'
```

Exit code `2` = bad UA value or missing dependency. `130` = Ctrl+C in `subfinder_live.py`.

## Notes

- TLS verification is disabled in `subfinder_live.py` (`verify=False`) because targets are arbitrary and often self-signed.
- Redirects are not followed; `Location` lands in the `redirect` field.
- Wildcard detection uses 3 random 18-character labels; large rotating wildcard pools can still yield false positives.
- Tune `--rate` / `--dns-rate` to the target's tolerance; `0` removes throttling entirely.
