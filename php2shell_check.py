#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_check.py - PHP2Shell version detection tool (check-only)

Detects the PHP version running on a target web server and maps it to the known
CVE-2026-109618 / CVE-2026-109619 fix ranges. Read-only, single host or bulk.

Usage:
  python php2shell_check.py --rhost HOST
  python php2shell_check.py --rhost h1,h2,h3 --threads 20
  python php2shell_check.py --file targets.txt
"""
from __future__ import annotations

import argparse
import concurrent.futures
import io
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request

FIX = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
VERSION_RE = re.compile(r"PHP[/\s]?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


class HTTP:
    def __init__(self, host, port, use_ssl, verify, timeout):
        self.host = host
        self.port = port
        self.ssl = use_ssl
        self.verify = verify
        self.timeout = timeout

    def get(self, path):
        scheme = "https" if self.ssl else "http"
        url = f"{scheme}://{self.host}:{self.port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "php2shell-check"})
        ctx = None
        if self.ssl and not self.verify:
            ctx = ssl._create_unverified_context()
        return urllib.request.urlopen(req, timeout=self.timeout, context=ctx)


def parse_version(text):
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def is_vulnerable(ver):
    branch = FIX.get(ver[:2])
    if branch is None:
        if ver[0] < 8 or (ver[0] == 8 and ver[1] < 2):
            return True, f"EOL PHP {ver[0]}.{ver[1]}.{ver[2]} (no official fix - backport required)"
        return True, f"PHP {ver[0]}.{ver[1]}.{ver[2]} below known fix"
    if ver < branch:
        return True, f"PHP {ver[0]}.{ver[1]}.{ver[2]} < {branch[0]}.{branch[1]}.{branch[2]}"
    return False, f"PHP {ver[0]}.{ver[1]}.{ver[2]} >= fix (PATCHED)"


def check_host(host, port, use_ssl, verify, timeout):
    h = HTTP(host, port, use_ssl, verify, timeout)
    paths = ["/", "/index.php", "/wp-login.php", "/xmlrpc.php", "/wp-json/"]
    ssl_err = False
    for p in paths:
        try:
            r = h.get(p)
            code = r.getcode()
            xpb = r.headers.get("X-Powered-By", "")
            srv = r.headers.get("Server", "")
            body = ""
            try:
                body = r.read(65536).decode("utf-8", "replace")
            except Exception:
                pass
        except urllib.error.HTTPError as e:
            code = e.code
            xpb = e.headers.get("X-Powered-By", "")
            srv = e.headers.get("Server", "")
            body = ""
        except Exception as e:
            if "CERTIFICATE" in str(e) or "SSL" in str(e):
                ssl_err = True
            continue

        ver = parse_version(xpb or srv) or parse_version(body)
        if ver:
            vuln, reason = is_vulnerable(ver)
            return {
                "host": host, "port": port,
                "php": f"{ver[0]}.{ver[1]}.{ver[2]}",
                "status": "VULNERABLE" if vuln else "SAFE",
                "reason": reason,
            }

    if ssl_err and verify:
        return check_host(host, port, use_ssl, False, timeout)

    servers = (srv if 'srv' in locals() else "").lower()
    if any(x in servers for x in ("microsoft", "asp.net", "express", "arr", "httpapi")):
        return {"host": host, "port": port, "php": None, "status": "NOT-PHP",
                "reason": "not PHP (IIS/ASP.NET/Express)"}
    return {"host": host, "port": port, "php": None, "status": "UNKNOWN",
            "reason": "version not disclosed (CDN/proxy or expose_php off)"}


def run_host(host, port, use_ssl, verify, timeout):
    try:
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            ex.submit(socket.getaddrinfo, host, None).result(timeout=timeout)
    except Exception:
        return {"host": host, "port": port, "php": None, "status": "TIMEOUT",
                "reason": "DNS resolution failed"}
    return check_host(host, port, use_ssl, verify, timeout)


def main():
    ap = argparse.ArgumentParser(description="PHP2Shell version detection (check-only)")
    ap.add_argument("--rhost", help="target host or comma-separated list")
    ap.add_argument("--file", help="file with targets (one per line, # comments)")
    ap.add_argument("--rport", type=int, default=443)
    ap.add_argument("--ssl", choices=["true", "false"], default="true")
    ap.add_argument("--ssl-verify", choices=["true", "false"], default="true")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--threads", type=int, default=0)
    args = ap.parse_args()

    targets = []
    if args.rhost:
        for h in args.rhost.split(","):
            h = h.strip()
            if not h:
                continue
            host, _, port = h.rpartition(":")
            if port.isdigit():
                targets.append((host, int(port)))
            else:
                targets.append((h, args.rport))
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host, _, port = line.rpartition(":")
                if port.isdigit():
                    targets.append((host, int(port)))
                else:
                    targets.append((line, args.rport))

    if not targets:
        print("No targets. Use --rhost host[,host2] or --file list.txt")
        sys.exit(1)

    use_ssl = args.ssl == "true"
    verify = args.ssl_verify == "true"
    threads = args.threads or min(32, len(targets))

    results = []
    if len(targets) == 1:
        results.append(run_host(targets[0][0], targets[0][1], use_ssl, verify, args.timeout))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(run_host, h, p, use_ssl, verify, args.timeout): (h, p)
                    for h, p in targets}
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())

    header = f"{'Host':<30} {'Port':<6} {'PHP':<10} {'Status':<12} Reason"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['host']:<30} {r['port']:<6} {(r['php'] or '-'):<10} "
              f"{r['status']:<12} {r['reason']}")

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print()
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
