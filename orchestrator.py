"""
orchestrator.py — LangGraph workflow with auth as Phase 0.

Phases:
  0. Auth     — sign up / log in, capture session
  1. Recon    — subdomains, endpoints, JS, directories
  2. Test     — all vuln agents in parallel per endpoint
  3. Verify   — filter false positives
  4. Report   — markdown + Discord

HOW TO ADD A NEW VULNERABILITY:
  1. Create agents/my_vuln_agent.py extending ReasoningAgent
  2. Import below
  3. Add to AGENT_MAP and VULN_RELEVANCE

HOW TO SKIP AUTH:
  python main.py --target x.com --no-auth
  Or set AUTH_COOKIE in .env for a pre-existing session.

HOW TO DISABLE A SPECIFIC VULN:
  Comment out its entry in VULN_RELEVANCE.
"""

import asyncio
from loguru import logger
from langgraph.graph import StateGraph, END

from core.state import BugHunterState
from core.http_client import HTTPClient, set_auth_session
from agents.auth_agent import AuthAgent
from agents.recon_agent import recon_node
from agents.verifier_agent import verify_all_findings

from agents.xss_agent            import XSSAgent
from agents.sqli_agent           import SQLiAgent
from agents.xxe_agent            import XXEAgent
from agents.rce_agent            import RCEAgent
from agents.ssti_agent           import SSTIAgent
from agents.cors_agent           import CORSAgent
from agents.csrf_agent           import CSRFAgent
from agents.open_redirect_agent  import OpenRedirectAgent
from agents.ssrf_agent           import SSRFAgent
from agents.oauth_agent          import OAuthAgent
from agents.info_disclosure_agent import InfoDisclosureAgent

import config


# ── Agent Registry ─────────────────────────────────────────────────
AGENT_MAP = {
    "XSS":            XSSAgent,
    "SQLi":           SQLiAgent,
    "XXE":            XXEAgent,
    "RCE":            RCEAgent,
    "SSTI":           SSTIAgent,
    "CORS":           CORSAgent,
    "CSRF":           CSRFAgent,
    "OpenRedirect":   OpenRedirectAgent,
    "SSRF":           SSRFAgent,
    "OAuth":          OAuthAgent,
    "InfoDisclosure": InfoDisclosureAgent,
}

# ── Relevance Rules ────────────────────────────────────────────────
def _has_params(ep):
    return bool(ep.get("params") or ep.get("body_params"))

def _has_url_param(ep):
    keys = list(ep.get("params", {}).keys()) + list(ep.get("body_params", {}).keys())
    url_kw = ["url","path","src","href","redirect","next","target","host",
               "link","callback","fetch","image","avatar","webhook","proxy","resource"]
    return any(k.lower() in url_kw for k in keys)

def _is_oauth(ep):
    url = ep.get("url","").lower()
    return any(k in url for k in ["oauth","auth","callback","token","authorize",
                                   "login","connect","openid","sso","jwt"])

VULN_RELEVANCE = {
    "XSS":            lambda ep: _has_params(ep),
    "SQLi":           lambda ep: _has_params(ep),
    "XXE":            lambda ep: "xml" in ep.get("content_type","").lower() or _has_params(ep),
    "RCE":            lambda ep: _has_params(ep),
    "SSTI":           lambda ep: _has_params(ep),
    "CORS":           lambda ep: True,
    "CSRF":           lambda ep: ep.get("method","GET").upper() in ("POST","PUT","DELETE","PATCH"),
    "OpenRedirect":   lambda ep: _has_url_param(ep),
    "SSRF":           lambda ep: _has_url_param(ep),
    "OAuth":          lambda ep: _is_oauth(ep),
    "InfoDisclosure": lambda ep: True,
}


# ── Phase 0: Authentication ────────────────────────────────────────
async def auth_node(state: dict) -> dict:
    """
    Phase 0: Sign up and log in to the target.
    Captured session is injected globally into HTTPClient.
    All subsequent requests in all agents carry the session automatically.
    """
    if state.get("skip_auth"):
        logger.info("━━━ PHASE 0: AUTH — Skipped (--no-auth) ━━━")
        return {**state, "auth_status": "skipped", "current_phase": "recon"}

    logger.info(f"━━━ PHASE 0: AUTH — {state['target']} ━━━")

    http    = HTTPClient()
    agent   = AuthAgent(state["target"], http)
    session = await agent.run()

    # Inject session globally — all future HTTPClient.send() calls carry it
    set_auth_session(session)

    await http.close()

    auth_info = {
        "authenticated": session.authenticated,
        "method":        session.method,
        "email":         session.user_email,
        "notes":         session.notes,
    }

    if session.authenticated:
        logger.success(
            f"━━━ AUTH COMPLETE — {session.user_email} "
            f"({session.method}) ━━━"
        )
    else:
        logger.warning("━━━ AUTH FAILED — testing unauthenticated ━━━")
        if session.notes:
            logger.warning(f"     Reason: {session.notes}")

    return {
        **state,
        "auth_info":     auth_info,
        "current_phase": "recon",
    }


# ── Per-endpoint parallel testing ─────────────────────────────────
async def test_endpoint(endpoint: dict, http: HTTPClient) -> list:
    tasks  = []
    labels = []

    for vuln_type, is_relevant in VULN_RELEVANCE.items():
        if is_relevant(endpoint):
            agent = AGENT_MAP[vuln_type](endpoint, http)
            tasks.append(agent.run())
            labels.append(vuln_type)

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for vuln_type, result in zip(labels, results):
        if isinstance(result, Exception):
            logger.warning(f"[{vuln_type}] Exception: {result}")
        elif result is not None:
            findings.append(result)

    return findings


# ── Phase 2: Vuln testing ──────────────────────────────────────────
async def testing_node(state: dict) -> dict:
    endpoints = state["endpoints"]
    logger.info(f"━━━ PHASE 2: TESTING — {len(endpoints)} endpoints ━━━")

    auth_info = state.get("auth_info", {})
    if auth_info.get("authenticated"):
        logger.info(f"     Running as: {auth_info.get('email')} ({auth_info.get('method')})")
    else:
        logger.info("     Running unauthenticated")

    http      = HTTPClient()
    semaphore = asyncio.Semaphore(config.PARALLEL_ENDPOINT_CAP)

    async def bounded(ep):
        async with semaphore:
            return await test_endpoint(ep, http)

    all_results = await asyncio.gather(
        *[bounded(ep) for ep in endpoints],
        return_exceptions=True
    )

    findings = []
    for r in all_results:
        if isinstance(r, list):
            findings.extend(r)

    await http.close()
    logger.success(f"━━━ TESTING COMPLETE — {len(findings)} raw findings ━━━")

    return {**state, "findings": findings, "tested_count": len(endpoints), "current_phase": "verify"}


# ── Phase 3: Verification ──────────────────────────────────────────
async def verification_node(state: dict) -> dict:
    logger.info("━━━ PHASE 3: VERIFICATION ━━━")
    http     = HTTPClient()
    verified = await verify_all_findings(state["findings"], http)
    await http.close()
    return {**state, "findings": verified, "current_phase": "report"}


# ── LangGraph graph ────────────────────────────────────────────────
def build_graph():
    from reporter import reporting_node

    graph = StateGraph(dict)
    graph.add_node("auth",   auth_node)
    graph.add_node("recon",  recon_node)
    graph.add_node("test",   testing_node)
    graph.add_node("verify", verification_node)
    graph.add_node("report", reporting_node)

    graph.set_entry_point("auth")
    graph.add_edge("auth",   "recon")
    graph.add_edge("recon",  "test")
    graph.add_edge("test",   "verify")
    graph.add_edge("verify", "report")
    graph.add_edge("report",  END)

    return graph.compile()