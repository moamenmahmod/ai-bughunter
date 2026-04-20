"""
tools/recon.py — Async wrappers for all recon tools.

HOW TO ADD A NEW TOOL:
  1. Write an async function that runs the tool via asyncio.create_subprocess_exec
  2. Parse its output (usually JSON lines) into a list of strings or dicts
  3. Call it in agents/recon_agent.py in the appropriate phase

HOW TO CONFIGURE TOOL BEHAVIOUR:
  - Thread counts, depth, wordlists → config.py
  - API keys for subfinder → injected via env vars below
"""

import asyncio
import json
import os
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from loguru import logger
import config


# ── Helpers ────────────────────────────────────────────────────────
async def _run(cmd: List[str], input_data: bytes = None) -> str:
    """Run a subprocess and return stdout as string."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(input=input_data)
    if stderr and proc.returncode != 0:
        logger.debug(f"[{cmd[0]}] stderr: {stderr.decode()[:200]}")
    return stdout.decode(errors="replace")


def _parse_jsonlines(text: str) -> List[dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return results


# ── Subfinder ─────────────────────────────────────────────────────
async def run_subfinder(domain: str) -> List[str]:
    """Enumerate subdomains using subfinder with all sources."""
    logger.info(f"  subfinder → {domain}")

    env = {**os.environ}
    if config.SHODAN_API_KEY:
        env["SHODAN_API_KEY"] = config.SHODAN_API_KEY
    if config.CENSYS_API_ID:
        env["CENSYS_API_ID"]     = config.CENSYS_API_ID
        env["CENSYS_API_SECRET"] = config.CENSYS_API_SECRET
    if config.CHAOS_KEY:
        env["CHAOS_KEY"] = config.CHAOS_KEY

    # Write env to temp config for subfinder
    cmd = [
        "subfinder", "-d", domain,
        "-silent", "-all",
        "-t", "50",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        results = [l.strip() for l in stdout.decode().splitlines() if l.strip()]
        logger.success(f"  subfinder → {len(results)} subdomains")
        return results[:config.MAX_RECON_SUBDOMAINS]
    except asyncio.TimeoutError:
        logger.warning("subfinder timed out")
        return []
    except FileNotFoundError:
        logger.error("subfinder not found — run setup.sh")
        return [domain]


# ── Waybackurls ───────────────────────────────────────────────────
async def run_waybackurls(domain: str) -> List[str]:
    """Get historical URLs from Wayback Machine."""
    logger.info(f"  waybackurls → {domain}")
    try:
        out = await asyncio.wait_for(
            _run(["waybackurls", domain]), timeout=60
        )
        urls = [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
        logger.success(f"  waybackurls → {len(urls)} URLs")
        return urls
    except (asyncio.TimeoutError, FileNotFoundError):
        logger.warning("waybackurls not available or timed out")
        return []


# ── httpx ─────────────────────────────────────────────────────────
async def run_httpx(hosts: List[str]) -> List[Dict]:
    """Check which hosts are live and collect tech stack info."""
    if not hosts:
        return []
    logger.info(f"  httpx → probing {len(hosts)} hosts")

    input_data = "\n".join(hosts).encode()
    cmd = [
        "httpx", "-silent", "-json",
        "-title", "-tech-detect", "-status-code",
        "-content-length", "-follow-redirects",
        "-threads", "50",
        "-timeout", "10",
    ]
    try:
        out = await asyncio.wait_for(
            _run(cmd, input_data=input_data), timeout=180
        )
        results = _parse_jsonlines(out)
        logger.success(f"  httpx → {len(results)} live hosts")
        return results
    except (asyncio.TimeoutError, FileNotFoundError):
        logger.warning("httpx not available or timed out")
        return []


# ── Katana ────────────────────────────────────────────────────────
async def run_katana(url: str) -> List[Dict]:
    """Crawl a URL and return discovered endpoints."""
    logger.info(f"  katana → {url}")
    cmd = [
        "katana", "-u", url,
        "-silent", "-json",
        "-jc",            # JS crawling
        "-kf", "all",     # known files
        "-d", "3",        # depth
        "-c", "10",       # concurrency
        "-timeout", "10",
        "-xhr",           # include XHR requests
    ]
    try:
        out = await asyncio.wait_for(_run(cmd), timeout=120)
        results = _parse_jsonlines(out)
        logger.success(f"  katana → {len(results)} endpoints from {url}")
        return results
    except (asyncio.TimeoutError, FileNotFoundError):
        logger.warning(f"katana failed on {url}")
        return []


# ── GAU ───────────────────────────────────────────────────────────
async def run_gau(domain: str) -> List[str]:
    """Get all known URLs from multiple sources (archive, commonCrawl, etc)."""
    logger.info(f"  gau → {domain}")
    cmd = ["gau", "--threads", "5", "--timeout", "30", domain]
    try:
        out = await asyncio.wait_for(_run(cmd), timeout=90)
        urls = [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
        logger.success(f"  gau → {len(urls)} URLs")
        return urls
    except (asyncio.TimeoutError, FileNotFoundError):
        logger.warning("gau not available or timed out")
        return []


# ── FFUF ──────────────────────────────────────────────────────────
async def run_ffuf(url: str, wordlist: str = None) -> List[str]:
    """Directory and file fuzzing."""
    if wordlist is None:
        wordlist = config.WORDLIST_PATH
    if not os.path.exists(wordlist):
        logger.warning(f"Wordlist not found: {wordlist}")
        return []

    output_file = f"/tmp/ffuf_{url.replace('/', '_')[:50]}.json"
    logger.info(f"  ffuf → {url}")
    cmd = [
        "ffuf",
        "-u", f"{url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-silent",
        "-mc", "200,201,301,302,401,403,405",
        "-o", output_file,
        "-of", "json",
        "-t", str(config.FFUF_THREADS),
        "-timeout", "10",
        "-rate", "100",
    ]
    try:
        await asyncio.wait_for(_run(cmd), timeout=120)
        if os.path.exists(output_file):
            with open(output_file) as f:
                data = json.load(f)
            found = [r["url"] for r in data.get("results", [])]
            logger.success(f"  ffuf → {len(found)} paths on {url}")
            os.remove(output_file)
            return found
        return []
    except (asyncio.TimeoutError, FileNotFoundError, json.JSONDecodeError):
        logger.warning(f"ffuf failed on {url}")
        return []


# ── URL Parser ────────────────────────────────────────────────────
def parse_urls_to_endpoints(urls: List[str], source: str = "unknown") -> List[dict]:
    """Convert a list of raw URLs into endpoint dicts for testing."""
    seen = set()
    endpoints = []

    for url in urls:
        if not url or not url.startswith("http"):
            continue
        # Deduplicate by URL (ignore query string variation beyond first)
        base = url.split("?")[0]
        if base in seen:
            continue
        seen.add(base)

        try:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # Skip obvious static files
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in [
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".css", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ]):
                continue

            endpoints.append({
                "url":             url,
                "method":          "GET",
                "params":          params,
                "body_params":     {},
                "headers":         {},
                "cookies":         {},
                "response_sample": "",
                "content_type":    "",
                "source":          source,
            })
        except Exception:
            pass

    return endpoints
