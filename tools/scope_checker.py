"""
tools/scope_checker.py — Validates URLs against the defined scope.

HOW TO CONFIGURE SCOPE:
  Pass scope as a list to main.py:
    python main.py --target example.com --scope "*.example.com" "api.example.com"
  Or leave it as default (anything under *.target.com)
"""

import re
from urllib.parse import urlparse
from loguru import logger


def is_in_scope(url: str, scope: list) -> bool:
    """Check if a URL falls within the defined scope patterns."""
    if not url or not url.startswith("http"):
        return False
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return False

    for pattern in scope:
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com and example.com
            domain = pattern[2:]
            if host == domain or host.endswith("." + domain):
                return True
        elif pattern == host:
            return True
        elif re.match(pattern.replace(".", r"\.").replace("*", r"[^.]+"), host):
            return True

    return False


def filter_in_scope(urls: list, scope: list) -> list:
    """Filter a list of URLs to only those in scope."""
    in_scope = [u for u in urls if is_in_scope(u, scope)]
    out_count = len(urls) - len(in_scope)
    if out_count:
        logger.debug(f"Scope filter: removed {out_count} out-of-scope URLs")
    return in_scope
