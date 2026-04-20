"""
tools/js_analyzer.py — Extract endpoints, secrets, and API paths from JS files.

Uses Gemini 2.5 Pro (1M context) to analyze large/obfuscated JS files.
Falls back to regex extraction if Gemini is unavailable.

HOW TO ADD MORE PATTERNS:
  Add regex patterns to ENDPOINT_PATTERNS or SECRET_PATTERNS below.
"""

import re
import asyncio
from typing import List, Tuple
from loguru import logger
from core.llm import gemini_analyze
from core.http_client import HTTPClient


# ── Regex patterns for quick extraction ──────────────────────────
ENDPOINT_PATTERNS = [
    r'''["'`](/api/[^"'`\s]{3,100})["'`]''',
    r'''["'`](/v\d+/[^"'`\s]{3,100})["'`]''',
    r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]''',
    r'''axios\.\w+\s*\(\s*["'`]([^"'`]+)["'`]''',
    r'''\$\.(?:get|post|ajax)\s*\(\s*["'`]([^"'`]+)["'`]''',
    r'''url\s*:\s*["'`]([^"'`]{5,200})["'`]''',
    r'''endpoint\s*[=:]\s*["'`]([^"'`]{5,200})["'`]''',
    r'''href\s*=\s*["'`]([^"'`]{5,200})["'`]''',
    r'''["'`](https?://[^"'`\s]{5,200})["'`]''',
]

SECRET_PATTERNS = [
    (r'''(?:api[_-]?key|apikey)\s*[=:]\s*["'`]([^"'`]{10,60})["'`]''',  "API Key"),
    (r'''(?:secret|token)\s*[=:]\s*["'`]([^"'`]{10,80})["'`]''',         "Secret/Token"),
    (r'''(?:password|passwd|pwd)\s*[=:]\s*["'`]([^"'`]{4,50})["'`]''',   "Password"),
    (r'''(?:private[_-]?key)\s*[=:]\s*["'`]([^"'`]{10,100})["'`]''',     "Private Key"),
    (r'''Bearer\s+([A-Za-z0-9\-_\.]{20,200})''',                          "Bearer Token"),
    (r'''eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+''',    "JWT"),
    (r'''AIza[0-9A-Za-z\-_]{35}''',                                        "Google API Key"),
    (r'''AKIA[0-9A-Z]{16}''',                                              "AWS Access Key"),
    (r'''(?:aws[_-]?secret)\s*[=:]\s*["'`]([^"'`]{20,60})["'`]''',       "AWS Secret"),
]


async def analyze_js_file(js_url: str, http: HTTPClient) -> dict:
    """
    Fetch a JS file and extract endpoints, secrets, and interesting data.
    Returns {endpoints: [], secrets: [], raw_url: js_url}
    """
    resp = await http.get(js_url)
    if not resp or resp.get("error") or resp.get("status", 0) not in range(200, 300):
        return {"endpoints": [], "secrets": [], "raw_url": js_url}

    content = resp["body"]
    if not content:
        return {"endpoints": [], "secrets": [], "raw_url": js_url}

    # Quick regex extraction
    endpoints = _extract_endpoints_regex(content)
    secrets   = _extract_secrets_regex(content)

    # If file is big/obfuscated → ask Gemini for deeper analysis
    if len(content) > 5000 or _looks_obfuscated(content):
        logger.info(f"  Gemini analyzing JS: {js_url[:60]}")
        try:
            gemini_result = gemini_analyze(
                content[:500_000],  # cap at 500k chars
                task="""Analyze this JavaScript file for a security researcher.
Extract and list:
1. All API endpoints (paths like /api/..., /v1/..., full URLs)
2. Any hardcoded secrets, tokens, API keys, passwords
3. Any interesting parameters or authentication patterns
4. Any internal service URLs or IPs

Format as JSON:
{
  "endpoints": ["list of paths/URLs"],
  "secrets": [{"type": "...", "value": "..."}],
  "notes": "any other interesting observations"
}"""
            )
            parsed = _parse_gemini_js(gemini_result)
            endpoints = list(set(endpoints + parsed.get("endpoints", [])))
            secrets   = secrets + parsed.get("secrets", [])
        except Exception as e:
            logger.warning(f"Gemini JS analysis failed: {e}")

    if endpoints or secrets:
        logger.info(f"  JS {js_url[:50]}: {len(endpoints)} endpoints, {len(secrets)} secrets")

    return {
        "endpoints": endpoints[:100],
        "secrets":   secrets[:20],
        "raw_url":   js_url,
    }


async def analyze_js_files_bulk(js_urls: List[str], http: HTTPClient) -> Tuple[List[str], List[dict]]:
    """Analyze multiple JS files and return (all_endpoints, all_secrets)."""
    tasks = [analyze_js_file(url, http) for url in js_urls[:30]]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_endpoints = []
    all_secrets   = []
    for r in results:
        if isinstance(r, dict):
            all_endpoints.extend(r.get("endpoints", []))
            all_secrets.extend(r.get("secrets", []))

    return list(set(all_endpoints)), all_secrets


# ── Helpers ────────────────────────────────────────────────────────
def _extract_endpoints_regex(content: str) -> List[str]:
    found = []
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, content)
        found.extend(matches)
    # Filter noise
    return [e for e in set(found) if len(e) > 3 and len(e) < 200]


def _extract_secrets_regex(content: str) -> List[dict]:
    found = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches:
            val = m if isinstance(m, str) else m[0]
            if len(val) > 6:
                found.append({"type": label, "value": val[:80]})
    return found


def _looks_obfuscated(content: str) -> bool:
    """Heuristic: if avg word length > 20, probably obfuscated."""
    words = content.split()
    if not words:
        return False
    avg = sum(len(w) for w in words[:200]) / min(len(words), 200)
    return avg > 20


def _parse_gemini_js(text: str) -> dict:
    import json
    try:
        start = text.find('{')
        end   = text.rfind('}')
        if start != -1 and end != -1:
            return json.loads(text[start:end+1])
    except Exception:
        pass
    return {}
