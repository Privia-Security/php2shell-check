# PHP2Shell Check

A lightweight, read-only detection tool that determines whether a web server runs a PHP version affected by **PHP2Shell** — the critical memory-management vulnerabilities tracked as **CVE-2026-109618** and **CVE-2026-109619**.

- **Read-only**: sends only standard HTTP GET requests and inspects response headers. It never exploits the vulnerability and never sends an RCE payload.
- **No dependencies**: pure Python standard library.
- **Single host or bulk**: one target, a comma-separated list, or a file of targets.
- **No authentication required** to test: it only fingerprints the PHP version.

> **Disclaimer**: Use this tool only against systems you own or have explicit written authorization to test. Unauthorized testing is illegal.

---

## What these vulnerabilities are

PHP2Shell is a family of two critical memory-management flaws in PHP:

| CVE | Root cause | Impact |
|-----|-----------|--------|
| CVE-2026-109618 | Memory corruption during out-of-memory (OOM) handling | Remote code execution (RCE), no auth required |
| CVE-2026-109619 | Use-after-free (UAF) when a request is terminated unexpectedly | RCE and/or information disclosure |

PHP released fixes on 21 October 2026 for all four supported branches. Anything below these versions is affected:

| Branch | Vulnerable | First fixed |
|--------|-----------|-------------|
| 8.5    | <= 8.5.11  | 8.5.12 |
| 8.4    | <= 8.4.26  | 8.4.27 |
| 8.3    | <= 8.3.35  | 8.3.36 |
| 8.2    | <= 8.2.34  | 8.2.35 |
| 8.1 / 8.0 / 7.4 | affected (EOL) | no official fix |
| 7.3 and older | affected (EOL) | no fix |

---

## Requirements

- Python 3.8+ (no third-party packages required)

## Installation

```bash
git clone https://github.com/Privia-Security/php2shell-check.git
cd php2shell-check
```

The tool is a single file. No setup or installation is needed.

## Usage

### Single host

```bash
python php2shell_check.py --rhost example.com
```

Defaults to HTTPS on port 443.

### HTTP (port 80)

```bash
python php2shell_check.py --rhost example.com --rport 80 --ssl false
```

### Bulk (comma-separated list)

```bash
python php2shell_check.py --rhost a.example.com,b.example.com,c.example.com --threads 20
```

### Bulk (targets file)

```bash
python php2shell_check.py --file targets.txt --threads 32
```

`targets.txt` — one target per line, optional `host:port`, `#` starts a comment:

```
example.com
internal.example.com:8080
# this line is ignored
10.0.0.5
```

### TLS certificate issues

For self-signed certificates or hostname mismatches, disable verification (only for your own systems):

```bash
python php2shell_check.py --rhost example.com --ssl-verify false
```

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--rhost` | - | Target host, or a comma-separated list |
| `--file` | - | File with targets (one per line) |
| `--rport` | `443` | Target port |
| `--ssl` | `true` | Use HTTPS (`true` / `false`) |
| `--ssl-verify` | `true` | Verify TLS certificate (`true` / `false`) |
| `--timeout` | `15` | HTTP timeout in seconds |
| `--threads` | `0` | Parallel workers for bulk (0 = auto, up to 32) |

---

## Output and interpretation

Sample run:

```
Host                           Port   PHP        Status       Reason
--------------------------------------------------------------------
example.com                    443    8.2.34     VULNERABLE   PHP 8.2.34 < 8.2.35
```

| Status | Meaning | Action |
|--------|---------|--------|
| `VULNERABLE` | PHP version is below the fix range (or EOL) | Upgrade PHP as soon as possible |
| `SAFE` | PHP version contains the fix | Verify Chain A conditions separately |
| `UNKNOWN` | Version could not be disclosed (CDN / `expose_php=off`) | Treat as at-risk, verify directly |
| `NOT-PHP` | The target is not running PHP (IIS/ASP.NET, ...) | No action |
| `TIMEOUT` | Target unreachable | Check network / firewall |
| `ERROR` | Unexpected error | Inspect the reason |

A bulk run ends with a summary, for example:

```
summary: VULNERABLE=2, SAFE=1, UNKNOWN=5, TIMEOUT=1
```

---

## How it works

The tool requests a small set of common paths (`/`, `/index.php`, `/wp-login.php`, `/xmlrpc.php`, `/wp-json/`) and parses the `X-Powered-By` and `Server` headers for a PHP version string such as `PHP/8.2.35`. The detected version is then compared against the fixed-version table above.

If TLS verification fails, it automatically retries with an unverified connection so that self-signed systems can still be fingerprinted. During bulk runs, DNS resolution runs under its own timeout so that unreachable hosts are marked `TIMEOUT` without stalling the whole scan.

---

## Limitations

- This tool only does **version detection**. A `VULNERABLE` result means the version is in the affected range, not that the server is actively exploitable.
- A `SAFE` result covers the memory-corruption path only. A separate request-level chain (session fixation + `upload_progress` filename injection + LFI) can still apply if the application has a local file inclusion flaw; assess that separately.
- If a CDN masks the origin headers, the version may be `UNKNOWN` from the public surface.

---

## Reference

- PHP security advisory, `security@php.net`, 21 October 2026
- CVE-2026-109618 and CVE-2026-109619 — NVD
- Privia Security — https://www.priviasecurity.com
