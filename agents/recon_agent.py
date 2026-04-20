"""
agents/recon_agent.py — Phase 1: Full reconnaissance.

Runs: subfinder → httpx → katana + gau + waybackurls → ffuf → JS analysis
Collects all subdomains, live hosts, URLs, endpoints, JS files, directories.

HOW TO ADD A RECON TOOL:
  1. Add async function to tools/recon.py
  2. Import and call it in recon_node() below
  3. Merge its output into the state
"""

import asyncio
from loguru import logger

from core.state import BugHunterState
from core.http_client import HTTPClient
from tools.recon import (
    run_subfinder, run_httpx, run_katana,
    run_gau, run_waybackurls, run_ffuf,
    parse_urls_to_endpoints,
)
from tools.js_analyzer import analyze_js_files_bulk
from tools.scope_checker import filter_in_scope
import config


async def recon_node(state: dict) -> dict:
    target = state["target"]
    scope  = state["scope"]
    logger.info(f"━━━ PHASE 1: RECON — {target} ━━━")

    # ── Step 1: Subdomain Enumeration ─────────────────────────────
    subdomains = await run_subfinder(target)
    # Always include the target itself
    if target not in subdomains:
        subdomains.insert(0, target)
    logger.info(f"Total subdomains: {len(subdomains)}")

    # ── Step 2: Live Host Check ────────────────────────────────────
    live_hosts = await run_httpx(subdomains)
    live_urls  = [h.get("url", "") for h in live_hosts if h.get("url")]
    logger.info(f"Live hosts: {len(live_urls)}")

    # ── Step 3: Crawl + URL Collection (parallel per host) ────────
    http = HTTPClient()
    all_urls    = []
    all_js      = []
    all_dirs    = []

    # Crawl top N hosts in parallel
    crawl_targets = live_urls[:40]  # don't crawl everything

    async def crawl_host(url):
        results = []
        # Katana crawl
        crawled = await run_katana(url)
        for item in crawled:
            ep = item.get("request", {}).get("endpoint", "")
            if ep:
                results.append(ep)
        return results

    # Run katana on all live hosts in parallel
    crawl_tasks   = [crawl_host(u) for u in crawl_targets]
    gau_tasks     = [run_gau(h.get("host", "")) for h in live_hosts[:20]]
    wb_tasks      = [run_waybackurls(h.get("host", "")) for h in live_hosts[:10]]
    ffuf_tasks    = [run_ffuf(u) for u in live_urls[:10]]

    all_crawl = await asyncio.gather(*crawl_tasks, return_exceptions=True)
    all_gau   = await asyncio.gather(*gau_tasks, return_exceptions=True)
    all_wb    = await asyncio.gather(*wb_tasks, return_exceptions=True)
    all_ffuf  = await asyncio.gather(*ffuf_tasks, return_exceptions=True)

    for r in all_crawl:
        if isinstance(r, list): all_urls.extend(r)
    for r in all_gau:
        if isinstance(r, list): all_urls.extend(r)
    for r in all_wb:
        if isinstance(r, list): all_urls.extend(r)
    for r in all_ffuf:
        if isinstance(r, list): all_dirs.extend(r)

    # ── Step 4: JS File Analysis ───────────────────────────────────
    js_files = list(set([
        u for u in all_urls
        if u.endswith(".js") or ".js?" in u
    ]))
    logger.info(f"JS files found: {len(js_files)}")
    js_endpoints, js_secrets = await analyze_js_files_bulk(js_files, http)
    all_urls.extend(js_endpoints)
    logger.info(f"JS endpoints extracted: {len(js_endpoints)}")
    if js_secrets:
        logger.warning(f"⚠  Secrets found in JS files: {len(js_secrets)}")
        for s in js_secrets[:5]:
            logger.warning(f"   [{s['type']}] {s['value'][:40]}...")

    # ── Step 5: Scope Filter + Parse to Endpoints ─────────────────
    all_urls = list(set(filter(None, all_urls)))
    in_scope = filter_in_scope(all_urls, scope)

    endpoints = parse_urls_to_endpoints(in_scope, source="recon")
    ffuf_eps  = parse_urls_to_endpoints(all_dirs,  source="ffuf")
    endpoints = _dedupe_endpoints(endpoints + ffuf_eps)

    # Cap to avoid huge runs
    endpoints = endpoints[:config.MAX_ENDPOINTS_TEST]

    # ── Step 6: Enrich endpoints with sample responses ─────────────
    logger.info(f"Enriching sample responses for {min(50, len(endpoints))} endpoints...")
    enrich_tasks = [_enrich_endpoint(ep, http) for ep in endpoints[:50]]
    enriched = await asyncio.gather(*enrich_tasks, return_exceptions=True)
    for i, r in enumerate(enriched):
        if isinstance(r, dict):
            endpoints[i] = r

    await http.close()

    logger.success(f"━━━ RECON COMPLETE ━━━")
    logger.success(f"  Subdomains : {len(subdomains)}")
    logger.success(f"  Live hosts : {len(live_hosts)}")
    logger.success(f"  Endpoints  : {len(endpoints)}")
    logger.success(f"  JS files   : {len(js_files)}")
    logger.success(f"  Directories: {len(all_dirs)}")

    return {
        **state,
        "subdomains":    subdomains,
        "live_hosts":    live_hosts,
        "endpoints":     endpoints,
        "js_files":      js_files,
        "api_endpoints": [e["url"] for e in endpoints if "/api/" in e["url"]],
        "directories":   all_dirs,
        "current_phase": "test",
    }


async def _enrich_endpoint(ep: dict, http: HTTPClient) -> dict:
    """Fetch the endpoint to get a real sample response."""
    try:
        resp = await http.get(ep["url"])
        if resp and not resp.get("error"):
            ep["response_sample"] = resp["body"][:500]
            ep["content_type"]    = resp["headers"].get("Content-Type", "")
    except Exception:
        pass
    return ep


def _dedupe_endpoints(endpoints: list) -> list:
    """Deduplicate endpoints by URL."""
    seen = set()
    result = []
    for ep in endpoints:
        url = ep.get("url", "")
        if url and url not in seen:
            seen.add(url)
            result.append(ep)
    return result
