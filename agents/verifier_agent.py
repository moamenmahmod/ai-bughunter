"""
agents/verifier_agent.py — Confirms findings are true positives.

Uses Qwen3-235B to critically analyze each finding before reporting.
Filters out false positives and assigns accurate severity/CVSS.

HOW TO TUNE VERIFICATION STRICTNESS:
  Modify VERIFIER_SYSTEM below.
  Make it stricter (less false positives) or looser (catch borderline cases).
"""

import json
from loguru import logger
from core.llm import vuln_think
from core.http_client import HTTPClient


VERIFIER_SYSTEM = """
You are a senior security engineer reviewing vulnerability reports for accuracy.
Your job: determine if a finding is a TRUE POSITIVE or FALSE POSITIVE.

Be CRITICAL and SKEPTICAL. Bug bounty programs hate false positives.

For each finding, analyze:
1. Is the evidence conclusive? Does it actually prove exploitation?
2. Is this exploitable in a real attack scenario?
3. Are there security controls that mitigate this (CSP, SameSite, WAF)?
4. What is the realistic impact?

Common false positives to catch:
- XSS: reflection in HTML source ≠ execution. Check for CSP. Check if it's in a comment.
- SSRF: DNS resolution only ≠ full SSRF if response isn't returned
- CORS: wildcard without credentials is usually low risk
- Info disclosure: version numbers alone are usually low severity
- Open Redirect: only to same domain is not a real open redirect

Respond ONLY in this exact JSON format:
{
  "verdict": "true_positive | false_positive | needs_manual_review",
  "confidence": 0-100,
  "severity": "Critical | High | Medium | Low | Info",
  "cvss": 0.0,
  "is_exploitable": true,
  "reasoning": "concise explanation of your verdict",
  "what_makes_it_real": "what evidence proves this is real (if true positive)",
  "why_false_positive": "why this is a FP (if false positive)",
  "recommended_additional_test": "one more test to confirm if unsure"
}
"""


async def verify_finding(finding: dict, http: HTTPClient) -> dict:
    """
    Takes a raw finding from a vuln agent and verifies it.
    Returns the finding with verified=True/False and updated severity/CVSS.
    """
    vuln_type = finding.get("vuln_type", "Unknown")
    logger.info(f"[Verifier] Checking {vuln_type} on {finding.get('url', '')[:60]}")

    # Build verification context
    context = f"""
FINDING TO VERIFY:
  Type:     {finding['vuln_type']}
  URL:      {finding['url']}
  Param:    {finding['param']}
  Payload:  {finding['payload']}
  Evidence: {finding['evidence']}
  Reported Severity: {finding.get('severity', 'Unknown')}

AGENT'S REASONING CHAIN (how it was found):
{finding.get('reasoning_chain', 'Not available')[:2000]}

PoC Steps:
{chr(10).join(finding.get('poc_steps', ['None provided']))}

Is this a real, exploitable vulnerability? Be critical and honest.
"""

    messages = [{"role": "user", "content": context}]

    try:
        raw = vuln_think(messages, VERIFIER_SYSTEM, max_tokens=1500)

        # Extract JSON
        start = raw.find('{')
        end   = raw.rfind('}')
        if start == -1 or end == -1:
            raise ValueError("No JSON in response")

        verdict = json.loads(raw[start:end+1])

        finding["verified"]            = verdict.get("verdict") == "true_positive"
        finding["severity"]            = verdict.get("severity", finding["severity"])
        finding["cvss"]                = float(verdict.get("cvss", finding.get("cvss", 0.0)))
        finding["verification_note"]   = verdict.get("reasoning", "")
        finding["is_exploitable"]      = verdict.get("is_exploitable", False)

        status = "✅ CONFIRMED" if finding["verified"] else "❌ FALSE POSITIVE"
        logger.info(f"[Verifier] {status} — {vuln_type} — {verdict.get('reasoning', '')[:100]}")

    except Exception as e:
        logger.warning(f"[Verifier] Failed to parse verdict: {e}")
        # On parse failure, keep the finding but flag for manual review
        finding["verified"]          = False
        finding["verification_note"] = "Verification failed — manual review needed"

    return finding


async def verify_all_findings(findings: list, http: HTTPClient) -> list:
    """Run verifier on all findings. Returns only confirmed true positives."""
    if not findings:
        return []

    logger.info(f"[Verifier] Verifying {len(findings)} findings...")
    verified = []

    for f in findings:
        result = await verify_finding(f, http)
        if result["verified"]:
            verified.append(result)

    logger.success(f"[Verifier] {len(verified)}/{len(findings)} confirmed true positives")
    return verified
