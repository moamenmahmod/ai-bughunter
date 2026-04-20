"""
main.py — Entry point.

USAGE:
  # Full scan — auto register + login, then test
  python main.py --target example.com

  # Skip auth (test unauthenticated)
  python main.py --target example.com --no-auth

  # Use your own account (set in .env or directly)
  python main.py --target example.com --auth-email you@email.com --auth-password Passw0rd

  # Use a pre-captured cookie string
  python main.py --target example.com --auth-cookie "session=abc123; csrf=xyz"

  # Use a Bearer token
  python main.py --target example.com --auth-token "eyJhbGci..."

  # Scope + specific vulns
  python main.py --target example.com --scope "*.example.com" --vulns xss sqli ssrf
"""

import asyncio
import argparse
import sys
import os
from datetime import datetime
from loguru import logger
from rich.console import Console
from rich.panel import Panel

from core.state import default_state
from config import validate_config
from orchestrator import build_graph

console = Console()


def parse_args():
    p = argparse.ArgumentParser(
        description="AI Bug Hunter — Autonomous authenticated security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target",      "-t", required=True, help="Target domain")
    p.add_argument("--scope",       "-s", nargs="+",     help="Scope patterns")
    p.add_argument("--no-auth",     action="store_true", help="Skip authentication phase")
    p.add_argument("--auth-email",        default=None,  help="Use this email to register/login")
    p.add_argument("--auth-password",     default=None,  help="Use this password")
    p.add_argument("--auth-cookie",       default=None,  help="Pre-captured cookie string")
    p.add_argument("--auth-token",        default=None,  help="Pre-captured Bearer token")
    p.add_argument("--vulns",       nargs="+",
                   choices=["xss","sqli","xxe","rce","ssti","cors","csrf",
                            "openredirect","ssrf","oauth","infodisclosure"],
                   help="Only test these vuln types")
    p.add_argument("--no-verify",   action="store_true", help="Skip verification phase")
    p.add_argument("--max-endpoints", type=int, default=None)
    p.add_argument("--output-dir",    default=None)
    return p.parse_args()


def banner():
    console.print(Panel.fit(
        "[bold red]AI Bug Hunter[/bold red]\n"
        "[dim]Autonomous authenticated vulnerability research[/dim]\n"
        "[dim]Stack: DeepSeek V3.1 · Qwen3-235B · Gemini 2.5 Pro[/dim]",
        border_style="red",
    ))


async def run(args):
    banner()
    validate_config()

    import config as cfg

    # ── Apply overrides ────────────────────────────────────────────
    if args.max_endpoints:
        cfg.MAX_ENDPOINTS_TEST = args.max_endpoints
    if args.output_dir:
        cfg.OUTPUT_DIR = args.output_dir
        os.makedirs(cfg.OUTPUT_DIR, exist_ok=True)

    # ── Inject manual auth credentials into env ────────────────────
    if args.auth_email:
        os.environ["AUTH_EMAIL"]    = args.auth_email
    if args.auth_password:
        os.environ["AUTH_PASSWORD"] = args.auth_password
    if args.auth_cookie:
        os.environ["AUTH_COOKIE"]   = args.auth_cookie
    if args.auth_token:
        os.environ["AUTH_TOKEN"]    = args.auth_token

    if args.vulns:
        _filter_vulns(args.vulns)

    if args.no_verify:
        _disable_verification()

    # ── Build state ────────────────────────────────────────────────
    scope = args.scope or [f"*.{args.target}", args.target]
    state = {
        **default_state(target=args.target, scope=scope),
        "skip_auth": args.no_auth,
        "auth_info": {},
    }

    logger.info(f"Target    : {args.target}")
    logger.info(f"Scope     : {scope}")
    logger.info(f"Auth mode : {'disabled' if args.no_auth else 'auto'}")
    logger.info(f"Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    graph = build_graph()

    try:
        final_state = await graph.ainvoke(state)
        count = len(final_state.get("findings", []))
        logger.success(f"Done. {count} confirmed findings.")
        return 0
    except KeyboardInterrupt:
        logger.warning("Interrupted")
        return 130
    except Exception as e:
        logger.exception(f"Fatal: {e}")
        return 1


def _filter_vulns(requested: list):
    import orchestrator
    norm = [v.lower().replace("_","") for v in requested]
    vmap = {
        "xss":"XSS","sqli":"SQLi","xxe":"XXE","rce":"RCE","ssti":"SSTI",
        "cors":"CORS","csrf":"CSRF","openredirect":"OpenRedirect",
        "ssrf":"SSRF","oauth":"OAuth","infodisclosure":"InfoDisclosure",
    }
    enabled = {vmap[v] for v in norm if v in vmap}
    for key in list(orchestrator.VULN_RELEVANCE.keys()):
        if key not in enabled:
            orchestrator.VULN_RELEVANCE[key] = lambda ep: False


def _disable_verification():
    import orchestrator
    async def passthrough(state):
        logger.info("Verification skipped")
        return {**state, "current_phase": "report"}
    orchestrator.verification_node = passthrough


if __name__ == "__main__":
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
        level="INFO", colorize=True,
    )
    os.makedirs("output", exist_ok=True)
    logger.add(
        f"output/run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
        level="DEBUG", rotation="50 MB",
    )
    sys.exit(asyncio.run(run(parse_args())))