"""
core/state.py — Shared state schema for the entire system.

HOW TO ADD A NEW FIELD:
  Add it to BugHunterState TypedDict and to the default_state() function.
  Any agent can then read/write it via the state dict.
"""

from typing import TypedDict, List, Dict, Any, Optional


class Endpoint(TypedDict):
    url: str
    method: str
    params: Dict[str, str]        # URL query parameters
    body_params: Dict[str, str]   # POST body parameters
    headers: Dict[str, str]       # Notable headers seen
    cookies: Dict[str, str]       # Cookies
    response_sample: str          # First 500 chars of a sample response
    content_type: str             # Response content type
    source: str                   # Where it was found (katana/gau/ffuf/js)


class Finding(TypedDict):
    vuln_type: str
    severity: str                 # Critical / High / Medium / Low / Info
    url: str
    param: str
    payload: str
    evidence: str                 # What in the response proves it
    reasoning_chain: str          # Full agent thinking chain
    poc_steps: List[str]          # Numbered reproduction steps
    cvss: float
    verified: bool
    verification_note: str


class BugHunterState(TypedDict):
    # Target
    target: str
    scope: List[str]              # e.g. ["*.target.com", "target.com"]

    # Recon phase output
    subdomains: List[str]
    live_hosts: List[Dict]        # httpx JSON output
    endpoints: List[Endpoint]
    js_files: List[str]
    api_endpoints: List[str]
    directories: List[str]

    # Crawl phase output
    crawled_requests: List[Dict]  # Full req/res pairs
    interesting_params: List[str] # Params worth testing

    # Testing output
    findings: List[Finding]
    tested_count: int

    # Control
    current_phase: str
    errors: List[str]
    logs: List[str]


def default_state(target: str, scope: List[str] = None) -> BugHunterState:
    """Returns a clean initial state for a new run."""
    return BugHunterState(
        target=target,
        scope=scope or [f"*.{target}", target],
        subdomains=[],
        live_hosts=[],
        endpoints=[],
        js_files=[],
        api_endpoints=[],
        directories=[],
        crawled_requests=[],
        interesting_params=[],
        findings=[],
        tested_count=0,
        current_phase="recon",
        errors=[],
        logs=[],
    )
