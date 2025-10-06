#!/usr/bin/env python3
"""
vt-recon.py — Automate recon pivots with VirusTotal API v3 (public-friendly)

Features
- Pull recent URLs seen for a domain
- Try to list subdomains (VT v3 endpoint; may require higher tier — handled gracefully)
- Resolve domain → IPs via VT
- Extract JavaScript URLs from VT URL feed; fetch and scan for secrets & endpoints
- Grep all discovered content for API keys, cloud buckets, auth tokens, and common endpoints
- Export CSV + JSON results

Requirements
    pip install requests tldextract rich

Usage
    export VT_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxx
    python vt-recon.py --domain example.com --out outdir

Notes
- VT public API is rate-limited (~4 req/min). This tool auto-throttles with a token bucket.
- Some VT relationships (e.g., subdomains) may require premium; the script falls back and continues.
- Be nice: don't hammer target sites when fetching JS; default is conservative.
"""

from __future__ import annotations
import os
import re
import sys
import json
import csv
import time
import math
import queue
import argparse
import pathlib
from typing import Dict, Any, Iterable, List, Optional

import requests
import tldextract
from rich.console import Console
from rich.table import Table
from rich.progress import track

API_BASE = "https://www.virustotal.com/api/v3"
VT_KEY = os.getenv("VT_API_KEY", "")
HEADERS = {"x-apikey": VT_KEY}
console = Console()

# ---------- Helpers ----------
class RateLimiter:
    def __init__(self, rpm: int = 4):
        self.tokens = rpm
        self.capacity = rpm
        self.refill = rpm
        self.last = time.time()

    def wait(self):
        now = time.time()
        elapsed = now - self.last
        add = elapsed * (self.refill / 60.0)
        self.tokens = min(self.capacity, self.tokens + add)
        if self.tokens < 1:
            sleep_for = (1 - self.tokens) * (60.0 / self.refill)
            time.sleep(max(0.25, sleep_for))
            self.tokens = 0
        self.tokens -= 1
        self.last = time.time()

rl = RateLimiter()

def vt_get(path: str, params: Dict[str, Any] | None = None) -> Optional[Dict[str, Any]]:
    if not VT_KEY:
        console.print("[red]Missing VT_API_KEY environment variable[/red]")
        sys.exit(2)
    rl.wait()
    url = f"{API_BASE}{path}"
    for attempt in range(3):
        r = requests.get(url, headers=HEADERS, params=params, timeout=30)
        if r.status_code == 429:
            # hard backoff
            time.sleep(20)
            continue
        if r.status_code == 403:
            return {"error": {"code": 403, "message": "Forbidden (plan limitation)"}}
        if r.ok:
            return r.json()
        time.sleep(2 * (attempt + 1))
    return None

# ---------- VT Queries ----------

def vt_domain_urls(domain: str, limit: int = 200) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    cursor = None
    fetched = 0
    while fetched < limit:
        params = {"limit": min(40, limit - fetched)}
        if cursor:
            params["cursor"] = cursor
        resp = vt_get(f"/domains/{domain}/urls", params)
        if not resp or "data" not in resp:
            break
        data.extend(resp.get("data", []))
        fetched += len(resp.get("data", []))
        cursor = resp.get("meta", {}).get("cursor")
        if not cursor:
            break
    return data


def vt_domain_resolutions(domain: str, limit: int = 200) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    cursor = None
    while len(data) < limit:
        params = {"limit": min(40, limit - len(data))}
        if cursor:
            params["cursor"] = cursor
        resp = vt_get(f"/domains/{domain}/resolutions", params)
        if not resp or "data" not in resp:
            break
        data.extend(resp["data"])
        cursor = resp.get("meta", {}).get("cursor")
        if not cursor:
            break
    return data


def vt_domain_subdomains(domain: str, limit: int = 200) -> List[str]:
    # May require premium. Handle 403 gracefully.
    items: List[str] = []
    cursor = None
    while len(items) < limit:
        params = {"limit": min(40, limit - len(items))}
        if cursor:
            params["cursor"] = cursor
        resp = vt_get(f"/domains/{domain}/subdomains", params)
        if not resp:
            break
        if "error" in resp and resp["error"].get("code") == 403:
            console.print("[yellow]Subdomains endpoint forbidden by plan; skipping.[/yellow]")
            return []
        chunk = [d.get("id") for d in resp.get("data", []) if d.get("id")]
        items.extend(chunk)
        cursor = resp.get("meta", {}).get("cursor")
        if not cursor:
            break
    return items

# ---------- Content Analysis ----------
JS_EXT = re.compile(r"\.js(\?.*)?$")
BUCKET_RX = re.compile(r"\b(?:(?:s3|s3[-.]dualstack)://|https?://[^/]*?s3[.-][^/]+/|https?://storage\.googleapis\.com/|https?://[^/]*\.blob\.core\.windows\.net/)[^\s'\"]+", re.I)
API_KEY_RX = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35}|[A-Za-z0-9_]{20,40}:[A-Za-z0-9_\-]{20,40})\b")
JWT_RX = re.compile(r"eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+")
ENDPOINT_RX = re.compile(r"\b/(api|v\d+|auth|graphql|internal|admin)(/[^\s'\"<>)]*)?\b")

USER_AGENT = "vt-recon/1.0 (+https://example.local)"

def safe_get(url: str, timeout: int = 20) -> Optional[str]:
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
        if r.status_code in (200, 203) and r.text:
            return r.text
    except Exception:
        return None
    return None

# ---------- Export ----------

def write_json(path: pathlib.Path, obj: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def write_csv(path: pathlib.Path, rows: List[Dict[str, Any]]):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = sorted({k for row in rows for k in row.keys()})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

# ---------- Main Workflow ----------

def pivot_from_domain(domain: str, outdir: pathlib.Path, js_fetch_max: int = 30) -> Dict[str, Any]:
    ext = tldextract.extract(domain)
    # tldextract>=5 deprecates `.registered_domain`; use `.top_domain_under_public_suffix`.
    root = getattr(ext, "top_domain_under_public_suffix", None) or (f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain)

    console.rule(f"[bold cyan]VirusTotal Recon for {root}")

    urls = vt_domain_urls(root, limit=200)
    url_rows = []
    js_urls = []
    for item in urls:
        attrs = item.get("attributes", {})
        u = attrs.get("url") or attrs.get("last_http_response_content_url")
        if not u:
            continue
        row = {
            "url": u,
            "last_analysis_date": attrs.get("last_final_url"),
            "http_code": attrs.get("last_http_response_code"),
            "threat": (attrs.get("last_analysis_stats") or {}).get("malicious"),
        }
        url_rows.append(row)
        if JS_EXT.search(u):
            js_urls.append(u)

    write_csv(outdir / "urls.csv", url_rows)

    # Resolutions
    resolutions = vt_domain_resolutions(root, limit=200)
    res_rows = []
    for r in resolutions:
        attrs = r.get("attributes", {})
        res_rows.append({
            "host": attrs.get("host_name"),
            "ip": attrs.get("ip_address"),
            "first_seen": attrs.get("date")
        })
    write_csv(outdir / "resolutions.csv", res_rows)

    # Subdomains (best effort)
    subs = vt_domain_subdomains(root, limit=400)
    write_json(outdir / "subdomains.json", subs)

    # JS fetch and scan
    findings: List[Dict[str, Any]] = []
    for js in track(js_urls[:js_fetch_max], description="Fetching JS"):
        text = safe_get(js)
        if not text:
            continue
        for rx, tag in [
            (BUCKET_RX, "bucket"),
            (API_KEY_RX, "api_key"),
            (JWT_RX, "jwt"),
            (ENDPOINT_RX, "endpoint"),
        ]:
            for m in rx.finditer(text):
                val = m.group(0)[:512]
                findings.append({"source": js, "type": tag, "match": val})

    write_csv(outdir / "findings.csv", findings)

    return {
        "domain": root,
        "urls_count": len(url_rows),
        "js_seen": len(js_urls),
        "resolutions": len(res_rows),
        "subdomains": len(subs),
        "findings": len(findings),
    }


def print_summary(stats: Dict[str, Any]):
    table = Table(title=f"Summary for {stats['domain']}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for k in ["urls_count", "js_seen", "resolutions", "subdomains", "findings"]:
        table.add_row(k, str(stats.get(k, 0)))
    console.print(table)


def main():
    p = argparse.ArgumentParser(description="VirusTotal recon automation tool")
    p.add_argument("--domain", required=True, help="Root domain to pivot from (e.g., example.com)")
    p.add_argument("--out", dest="outdir", default="vt-out", help="Output directory")
    p.add_argument("--js-max", dest="jsmax", type=int, default=30, help="Max JS files to fetch and scan")
    args = p.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    stats = pivot_from_domain(args.domain, outdir, js_fetch_max=args.jsmax)
    print_summary(stats)
    console.print(f"[green]Done. Outputs in {outdir.resolve()}[/green]")

if __name__ == "__main__":
    main()
