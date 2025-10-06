#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Download WordPress.org plugins with active installs in [min, max) range
Default: min=100_000, max=500_000 (exclusive upper bound)
- Fetches via Plugins API (query_plugins) with pagination
- Filters by active_installs
- Downloads ZIP for each plugin (versioned URL first, fallback generic)
- Saves manifest CSV & JSON

Usage:
  python download_wp_plugins_range.py \
      --min-installs 100000 \
      --max-installs 500000 \
      --out-dir ./wp-plugins-100k-500k \
      --concurrency 12
"""

import argparse
import asyncio
import csv
import json
import math
import os
import sys
import time
from typing import Any, Dict, List, Tuple, Optional

import aiohttp

API_URL = "https://api.wordpress.org/plugins/info/1.2/"
DL_BASE = "https://downloads.wordpress.org/plugin"
UA = "WP-Plugin-Downloader/1.1 (+for research & security testing)"

def parse_args():
    ap = argparse.ArgumentParser(description="Download WordPress plugins by active install range.")
    ap.add_argument("--min-installs", type=int, default=100_000, help="Inclusive lower bound (default: 100000)")
    ap.add_argument("--max-installs", type=int, default=500_000, help="Exclusive upper bound (default: 500000)")
    ap.add_argument("--per-page", type=int, default=100, help="API page size (max ~100)")
    ap.add_argument("--max-pages", type=int, default=None, help="Limit pages fetched (for testing)")
    ap.add_argument("--out-dir", default="wp-plugins-100k-500k", help="Directory to save ZIPs and manifests")
    ap.add_argument("--concurrency", type=int, default=10, help="Max concurrent downloads (default: 10)")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite if file already exists")
    ap.add_argument("--timeout", type=int, default=45, help="HTTP timeout seconds (default: 45)")
    return ap.parse_args()

async def fetch_json(session: aiohttp.ClientSession, url: str, params: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    async with session.get(url, params=params, timeout=timeout) as r:
        r.raise_for_status()
        return await r.json()

async def fetch_page(session: aiohttp.ClientSession, page: int, per_page: int, timeout: int) -> Dict[str, Any]:
    params = {
        "action": "query_plugins",
        "request[page]": page,
        "request[per_page]": per_page,
        "request[fields][slug]": 1,
        "request[fields][name]": 1,
        "request[fields][version]": 1,
        "request[fields][active_installs]": 1,
        "request[fields][last_updated]": 1,
        "request[fields][rating]": 1,
        "request[fields][num_ratings]": 1,
        "request[fields][downloaded]": 1,
        "request[fields][requires]": 1,
        "request[fields][tested]": 1,
        "request[fields][homepage]": 1,
        "request[fields][short_description]": 1,
    }
    return await fetch_json(session, API_URL, params, timeout)

async def gather_all_plugins(per_page: int, max_pages: Optional[int], timeout: int) -> Tuple[List[Dict[str, Any]], int]:
    all_plugins: List[Dict[str, Any]] = []
    conn = aiohttp.TCPConnector(limit=8, ssl=False)
    async with aiohttp.ClientSession(headers={"User-Agent": UA}, connector=conn) as session:
        page = 1
        total_pages = None
        retries = 0
        while True:
            if max_pages is not None and page > max_pages:
                break
            try:
                data = await fetch_page(session, page, per_page, timeout)
                retries = 0
            except Exception as e:
                retries += 1
                if retries <= 5:
                    delay = min(2 ** retries, 30)
                    print(f"[warn] Page {page} error: {e} — retry {retries}/5 in {delay}s", file=sys.stderr)
                    await asyncio.sleep(delay)
                    continue
                print(f"[error] Page {page} failed after retries, stop.", file=sys.stderr)
                break

            plugins = data.get("plugins", []) or []
            info = data.get("info", {}) or {}
            if total_pages is None:
                total_pages = info.get("pages") or None

            if not plugins:

                break

            all_plugins.extend(plugins)
            print(f"[info] fetched page {page} ({len(plugins)} plugins)", file=sys.stderr)

            page += 1
  
            if total_pages and page > total_pages:
                break

    return all_plugins, (total_pages or (math.ceil(len(all_plugins) / per_page)))

def filter_range(plugins: List[Dict[str, Any]], min_installs: int, max_installs: int) -> List[Dict[str, Any]]:
    out = []
    for p in plugins:
        ai = p.get("active_installs")
        try:
            ai = int(ai) if ai is not None else None
        except (TypeError, ValueError):
            ai = None
        if ai is None:
            continue
        if ai >= min_installs and ai < max_installs:
            out.append(p)
    # urutkan dari terbesar
    out.sort(key=lambda x: int(x.get("active_installs", 0) or 0), reverse=True)
    return out

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def safe_name(slug: str, version: str) -> str:
    v = (version or "latest").replace("/", "_")
    return f"{slug}-{v}.zip"

def url_candidates(slug: str, version: Optional[str]) -> List[str]:
    c = []
    if version:
        c.append(f"{DL_BASE}/{slug}.{version}.zip")     
    c.append(f"{DL_BASE}/{slug}.zip")                  
    return c

async def download_one(session: aiohttp.ClientSession, sem: asyncio.Semaphore, plugin: Dict[str, Any], out_dir: str, overwrite: bool, timeout: int) -> Tuple[str, str, bool, Optional[str]]:
    slug = plugin.get("slug")
    version = plugin.get("version")
    filename = safe_name(slug, version)
    path = os.path.join(out_dir, filename)
    if os.path.exists(path) and not overwrite:
        return (slug, filename, True, None)

    async with sem:
        tried = []
        for url in url_candidates(slug, version):
            try:
                async with session.get(url, timeout=timeout) as r:
                    if r.status == 200:
                        with open(path, "wb") as f:
                            while True:
                                chunk = await r.content.read(1024 * 64)
                                if not chunk:
                                    break
                                f.write(chunk)
                        return (slug, filename, False, None)
                    else:
                        tried.append(f"{url} -> HTTP {r.status}")
            except Exception as e:
                tried.append(f"{url} -> {e!r}")
                await asyncio.sleep(1.0)

        return (slug, filename, False, "; ".join(tried))

async def download_all(plugins: List[Dict[str, Any]], out_dir: str, concurrency: int, overwrite: bool, timeout: int) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]:
    ensure_dir(out_dir)
    sem = asyncio.Semaphore(concurrency)
    conn = aiohttp.TCPConnector(limit=concurrency * 2, ssl=False)
    successes: List[Tuple[str, str]] = []
    failures: List[Tuple[str, str, str]] = []
    async with aiohttp.ClientSession(headers={"User-Agent": UA}, connector=conn) as session:
        tasks = [download_one(session, sem, p, out_dir, overwrite, timeout) for p in plugins]
        for fut in asyncio.as_completed(tasks):
            slug, filename, skipped, err = await fut
            if err:
                print(f"[fail] {slug}: {err}", file=sys.stderr)
                failures.append((slug, filename, err))
            else:
                if skipped:
                    print(f"[skip] {slug} -> {filename}", file=sys.stderr)
                else:
                    print(f"[ok]   {slug} -> {filename}", file=sys.stderr)
                successes.append((slug, filename))
    return successes, failures

def save_manifest(out_dir: str, plugins: List[Dict[str, Any]]):
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(plugins, f, ensure_ascii=False, indent=2)
    csv_path = os.path.join(out_dir, "manifest.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "active_installs", "version", "last_updated", "rating", "num_ratings", "downloaded", "requires", "tested", "homepage"])
        for p in plugins:
            w.writerow([
                p.get("slug",""),
                p.get("name",""),
                p.get("active_installs",""),
                p.get("version",""),
                p.get("last_updated",""),
                p.get("rating",""),
                p.get("num_ratings",""),
                p.get("downloaded",""),
                p.get("requires",""),
                p.get("tested",""),
                p.get("homepage",""),
            ])

async def main_async(args):
    print("[info] Fetching plugin index from WordPress.org API …", file=sys.stderr)
    all_plugins, total_pages = await gather_all_plugins(args.per_page, args.max_pages, args.timeout)
    print(f"[info] Collected {len(all_plugins)} entries across ~{total_pages} pages", file=sys.stderr)

    filtered = filter_range(all_plugins, args.min_installs, args.max_installs)
    print(f"[info] In range [{args.min_installs}, {args.max_installs}): {len(filtered)} plugins", file=sys.stderr)


    ensure_dir(args.out_dir)
    save_manifest(args.out_dir, filtered)

    if not filtered:
        print("[done] Nothing to download for this range.", file=sys.stderr)
        return

    print(f"[info] Downloading with concurrency={args.concurrency} into: {args.out_dir}", file=sys.stderr)
    successes, failures = await download_all(filtered, args.out_dir, args.concurrency, args.overwrite, args.timeout)

    print(f"\n[summary] downloaded/verified: {len(successes)} | failed: {len(failures)}", file=sys.stderr)
    if failures:

        fail_path = os.path.join(args.out_dir, "download_failures.txt")
        with open(fail_path, "w", encoding="utf-8") as f:
            for slug, filename, err in failures:
                f.write(f"{slug}\t{filename}\t{err}\n")
        print(f"[summary] failure log -> {fail_path}", file=sys.stderr)

def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[warn] Interrupted by user.", file=sys.stderr)

if __name__ == "__main__":
    main()
