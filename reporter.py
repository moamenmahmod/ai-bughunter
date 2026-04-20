"""
reporter.py — Builds the final report and sends to Discord.

Output:
  1. output/YYYY-MM-DD_target_report.md — full markdown report
  2. Discord embed per confirmed finding
  3. Discord summary message at the end

HOW TO CUSTOMISE DISCORD MESSAGES:
  Edit _build_embed() below.

HOW TO CUSTOMISE THE MARKDOWN REPORT:
  Edit generate_markdown_report() below.

HOW TO ADD MORE OUTPUT FORMATS (HTML, JSON, etc.):
  Add a new function and call it from reporting_node().
"""

import os
import json
import asyncio
import aiohttp
from datetime import datetime
from loguru import logger
import config


# ── Discord Sender ─────────────────────────────────────────────────
async def send_discord_embed(embed: dict, webhook_url: str):
    """Send a single embed to Discord."""
    if not webhook_url:
        return
    try:
        async with aiohttp.ClientSession() as session:
            resp = await session.post(webhook_url, json={"embeds": [embed]})
            if resp.status not in (200, 204):
                logger.warning(f"Discord webhook returned {resp.status}")
            await asyncio.sleep(1)  # avoid Discord rate limits
    except Exception as e:
        logger.warning(f"Discord send failed: {e}")


async def send_discord_message(content: str, webhook_url: str):
    """Send a plain text message to Discord."""
    if not webhook_url:
        return
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(webhook_url, json={"content": content})
    except Exception as e:
        logger.warning(f"Discord message failed: {e}")


def _build_embed(finding: dict) -> dict:
    """Build a rich Discord embed for one finding."""
    severity = finding.get("severity", "Unknown")
    color    = config.SEVERITY_COLORS.get(severity, 0xAAAAAA)
    cvss     = finding.get("cvss", 0.0)

    # Build PoC steps
    poc_steps = finding.get("poc_steps", [])
    poc_text  = "\n".join([f"{i+1}. {s}" for i, s in enumerate(poc_steps[:5])])
    if not poc_text:
        poc_text = "See reasoning chain."

    # Truncate long fields for Discord's 1024-char field limit
    evidence  = (finding.get("evidence",        "") or "")[:900]
    reasoning = (finding.get("reasoning_chain", "") or "")[:600]
    payload   = (finding.get("payload",         "") or "")[:400]
    url       = (finding.get("url",             "") or "")[:200]
    param     = (finding.get("param",           "") or "")[:100]

    return {
        "title": f"🐛 [{severity}] {finding['vuln_type']} — CVSS {cvss:.1f}",
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "fields": [
            {
                "name":   "📍 URL",
                "value":  f"```{url}```",
                "inline": False,
            },
            {
                "name":   "🎯 Parameter",
                "value":  f"`{param}`" if param else "N/A",
                "inline": True,
            },
            {
                "name":   "📊 CVSS Score",
                "value":  str(cvss),
                "inline": True,
            },
            {
                "name":   "💉 Payload",
                "value":  f"```{payload}```" if payload else "See PoC steps",
                "inline": False,
            },
            {
                "name":   "🔍 Evidence",
                "value":  evidence or "See reasoning chain.",
                "inline": False,
            },
            {
                "name":   "📋 PoC Steps",
                "value":  poc_text,
                "inline": False,
            },
            {
                "name":   "🧠 Agent Reasoning",
                "value":  reasoning or "Not available",
                "inline": False,
            },
        ],
        "footer": {
            "text": f"AI Bug Hunter • Verified ✅ • {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        },
    }


async def send_findings_to_discord(findings: list, target: str, webhook_url: str):
    """Send all confirmed findings to Discord."""
    if not webhook_url or not findings:
        return

    # Header message
    await send_discord_message(
        f"🎯 **AI Bug Hunter — {target}**\n"
        f"Found **{len(findings)} confirmed vulnerabilities**",
        webhook_url,
    )
    await asyncio.sleep(1)

    # One embed per finding (sorted by CVSS descending)
    sorted_findings = sorted(findings, key=lambda x: x.get("cvss", 0), reverse=True)
    for finding in sorted_findings:
        embed = _build_embed(finding)
        await send_discord_embed(embed, webhook_url)


# ── Markdown Report ────────────────────────────────────────────────
def generate_markdown_report(state: dict) -> str:
    """Generate a full markdown report and save it to output/."""
    target   = state.get("target", "unknown")
    findings = state.get("findings", [])
    ts       = datetime.now().strftime("%Y-%m-%d_%H-%M")

    # Make output directory
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(config.OUTPUT_DIR, f"{ts}_{target}_report.md")

    sorted_findings = sorted(findings, key=lambda x: x.get("cvss", 0), reverse=True)

    # Count by severity
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        f"# Bug Hunting Report — {target}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Total confirmed findings:** {len(findings)}  ",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")

    lines += [
        "",
        "## Recon Summary",
        "",
        f"- **Target:** {target}",
        f"- **Subdomains found:** {len(state.get('subdomains', []))}",
        f"- **Live hosts:** {len(state.get('live_hosts', []))}",
        f"- **Endpoints tested:** {state.get('tested_count', 0)}",
        f"- **JS files analyzed:** {len(state.get('js_files', []))}",
        "",
        "## Vulnerabilities",
        "",
    ]

    for i, finding in enumerate(sorted_findings, 1):
        severity = finding.get("severity", "Unknown")
        vuln     = finding.get("vuln_type", "Unknown")
        url      = finding.get("url", "")
        param    = finding.get("param", "")
        payload  = finding.get("payload", "")
        evidence = finding.get("evidence", "")
        cvss     = finding.get("cvss", 0.0)
        poc_steps= finding.get("poc_steps", [])
        reasoning= finding.get("reasoning_chain", "")
        note     = finding.get("verification_note", "")

        lines += [
            f"### {i}. {vuln} [{severity}] — CVSS {cvss:.1f}",
            "",
            f"**URL:** `{url}`  ",
            f"**Parameter:** `{param}`  ",
            f"**Severity:** {severity}  ",
            f"**CVSS:** {cvss:.1f}  ",
            "",
            "**Payload:**",
            "```",
            payload or "See PoC steps",
            "```",
            "",
            f"**Evidence:** {evidence}",
            "",
        ]

        if poc_steps:
            lines.append("**Steps to Reproduce:**")
            for j, step in enumerate(poc_steps, 1):
                lines.append(f"{j}. {step}")
            lines.append("")

        if reasoning:
            lines += [
                "<details>",
                "<summary>Agent Reasoning Chain</summary>",
                "",
                reasoning[:3000],
                "",
                "</details>",
                "",
            ]

        if note:
            lines += [f"**Verification Note:** {note}", ""]

        lines.append("---")
        lines.append("")

    report_text = "\n".join(lines)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)

    logger.success(f"Report saved: {filename}")
    return filename


# ── JSON Export ────────────────────────────────────────────────────
def save_json_results(state: dict):
    """Save raw findings as JSON for further processing."""
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    target   = state.get("target", "unknown")
    ts       = datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = os.path.join(config.OUTPUT_DIR, f"{ts}_{target}_findings.json")

    export = {
        "target":          state.get("target"),
        "timestamp":       ts,
        "subdomains":      state.get("subdomains", []),
        "live_hosts":      [h.get("url") for h in state.get("live_hosts", [])],
        "endpoints_tested":state.get("tested_count", 0),
        "findings":        state.get("findings", []),
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, default=str)

    logger.success(f"JSON saved: {filename}")
    return filename


# ── LangGraph Node ─────────────────────────────────────────────────
async def reporting_node(state: dict) -> dict:
    """Phase 4: Build reports and send notifications."""
    logger.info("━━━ PHASE 4: REPORTING ━━━")
    findings = state.get("findings", [])

    # Generate markdown report
    md_file   = generate_markdown_report(state)
    json_file = save_json_results(state)

    # Send to Discord
    webhook = config.DISCORD_WEBHOOK
    if webhook:
        await send_findings_to_discord(findings, state["target"], webhook)
        logger.success("Discord notifications sent")
    else:
        logger.info("No DISCORD_WEBHOOK set — skipping Discord")

    # Print summary to terminal
    _print_summary(state, md_file)

    return {**state, "current_phase": "done"}


def _print_summary(state: dict, report_path: str):
    """Print a clean summary table to terminal."""
    findings = state.get("findings", [])
    target   = state.get("target", "unknown")

    print("\n" + "━" * 55)
    print(f"  AI Bug Hunter — Run Complete")
    print(f"  Target: {target}")
    print("━" * 55)
    print(f"  Subdomains    : {len(state.get('subdomains', []))}")
    print(f"  Live Hosts    : {len(state.get('live_hosts', []))}")
    print(f"  Endpoints     : {state.get('tested_count', 0)}")
    print(f"  JS Files      : {len(state.get('js_files', []))}")
    print(f"  Findings      : {len(findings)}")
    print("━" * 55)

    if findings:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_f  = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Info"), 5))
        for f in sorted_f:
            sev  = f.get("severity", "?")
            vt   = f.get("vuln_type", "?")
            url  = f.get("url", "")[:50]
            cvss = f.get("cvss", 0.0)
            print(f"  [{sev:8s}] {vt:15s} CVSS {cvss:.1f} — {url}")

    print("━" * 55)
    print(f"  Report: {report_path}")
    print("━" * 55 + "\n")
