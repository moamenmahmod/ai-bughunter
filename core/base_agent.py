"""
core/base_agent.py — The reasoning loop all 11 vuln agents inherit.

KEY DESIGN PRINCIPLE:
  Agents do NOT follow a static checklist.
  They observe the specific situation they are in, reason about it,
  and decide their own path. The VULN_PROMPT in each agent gives
  KNOWLEDGE (what techniques exist) but never dictates ORDER
  or SEQUENCE. The agent figures that out itself from observation.
"""

import json
from loguru import logger
from core.llm import vuln_think
from core.http_client import HTTPClient
import config


BASE_SYSTEM = """
You are a world-class bug bounty hunter. You have found hundreds of vulnerabilities
across thousands of targets. You do not use scanners. You do not follow checklists.
You think. You observe. You reason. You adapt.

━━━ HOW YOU THINK ━━━

Every time you receive information (endpoint, response, result), do this:

1. WHAT DO I SEE?
   Read everything. URL structure. Parameter names. Response body. Headers.
   Status code. Response time. Error messages. Technology hints.
   Every detail is a signal. What is this application actually doing?

2. WHAT DOES THIS TELL ME?
   Based on what you observe, what do you know about how this app works?
   Backend? Framework? Input handling? What context are you injecting into?
   What is the app doing with your input — reflecting it? Processing it?
   Storing it? Passing it to another system? Evaluating it?

3. WHAT IS MY HYPOTHESIS?
   Given what you know, what is the most likely path to the bug?
   Not "I will try technique X" — but a specific belief grounded in evidence:
   "I see the 'origin' parameter value is reflected verbatim in the
   Access-Control-Allow-Origin header. My hypothesis is this endpoint trusts
   whatever origin I send. I need to check if Allow-Credentials is also true
   and if this endpoint returns sensitive data, making this exploitable."

4. WHAT IS MY NEXT ACTION?
   One specific, targeted action to test your hypothesis.
   Chosen because it will give you information OR prove your case.
   Not because it is "step 2" in some checklist.

5. WHAT DID I LEARN?
   What does the result tell you? Confirmed? Partially? Refuted?
   Update your mental model of the application.
   What is your NEXT hypothesis based on this new information?

━━━ HOW YOU HANDLE FAILURE ━━━

When something does not work, do NOT move to the next item on a list.
Ask: WHY did that fail?
- Was the payload filtered? What specifically?
- Was output encoded? What encoding? In what context exactly?
- Was there a WAF? What does it block vs allow?
- Am I in the wrong context?
- Is this endpoint even the right attack surface?

Your next action MUST be informed by WHY the last one failed.
If you do not know why, your next action is to find out — not try another payload.

━━━ HOW YOU HANDLE DEAD ENDS ━━━

If you have genuinely exhausted reasonable paths, say so honestly.
Do not keep trying random things. Explain what you tried, what each result
told you, and why you believe the vulnerability is not reachable.

━━━ WHAT YOU NEVER DO ━━━

- Spray a list of payloads hoping one lands
- Follow a fixed sequence of steps
- Try something without articulating exactly why
- Give up because "phase 1 didn't work" — phases do not exist for you
- Assume how the application works before observing evidence
- Repeat the same type of payload after it already failed without adapting

━━━ RESPONSE FORMAT — STRICT JSON ONLY ━━━

No text before or after the JSON object.

{
  "thinking": "Your full reasoning. What you observed. What it means. Exactly why this action.",
  "hypothesis": "Your specific belief about this application and what you expect to happen.",
  "action": "send_request | analyze | report_found | report_not_found",
  "tool_params": {}
}

For send_request, tool_params:
{
  "url": "full URL",
  "method": "GET",
  "params": {"key": "value"},
  "body": {"key": "value"},
  "headers": {"HeaderName": "value"},
  "raw_body": "raw string if needed",
  "content_type": "override if needed"
}

For analyze, tool_params:
{ "note": "what you are reasoning about" }

For report_found, tool_params:
{
  "param": "vulnerable parameter name",
  "final_payload": "exact payload that works",
  "evidence": "exactly what in the response proves exploitability",
  "severity": "Critical | High | Medium | Low",
  "cvss": 7.5,
  "poc_steps": ["step 1", "step 2", "step 3"],
  "why_it_works": "technical root cause"
}

For report_not_found, tool_params:
{ "summary": "what you tried, what each result told you, why not vulnerable" }
"""


class ReasoningAgent:
    VULN_TYPE   = "UNKNOWN"
    VULN_PROMPT = ""

    def __init__(self, endpoint: dict, http: HTTPClient):
        self.endpoint = endpoint
        self.http     = http
        self.history  = []
        self.attempts = []
        self.system   = BASE_SYSTEM + "\n\n" + self.VULN_PROMPT
        self.max_iter = config.MAX_VULN_ITERATIONS

    async def run(self) -> dict | None:
        url = self.endpoint.get("url", "")
        logger.info(f"[{self.VULN_TYPE}] → {url}")

        self.history.append({"role": "user", "content": self._initial_context()})

        for i in range(self.max_iter):
            raw = vuln_think(self.history, self.system)
            if not raw:
                break

            self.history.append({"role": "assistant", "content": raw})

            try:
                action = json.loads(self._extract_json(raw))
            except json.JSONDecodeError:
                self.history.append({
                    "role": "user",
                    "content": "Your response was not valid JSON. "
                               "Respond ONLY with the JSON object, nothing else."
                })
                continue

            logger.debug(
                f"[{self.VULN_TYPE}] iter {i+1} | {action.get('action')} | "
                f"{action.get('thinking','')[:100]}"
            )

            result = await self._execute(action)
            if result == "FOUND":
                return self._build_finding(action)
            if result == "NOT_FOUND":
                return None

            self.history.append({"role": "user", "content": result})

        return None

    async def _execute(self, action: dict) -> str:
        act = action.get("action", "")
        tp  = action.get("tool_params", {})

        if act == "send_request":
            resp = await self.http.send(
                url          = tp.get("url", self.endpoint["url"]),
                method       = tp.get("method", self.endpoint.get("method", "GET")),
                params       = tp.get("params"),
                body         = tp.get("body"),
                headers      = tp.get("headers"),
                raw_body     = tp.get("raw_body"),
                content_type = tp.get("content_type"),
            )
            self.attempts.append({
                "reasoning": action.get("thinking", ""),
                "request":   tp,
                "response":  resp,
            })
            return self._format_response(resp)

        elif act == "analyze":
            return (
                f"Noted: {tp.get('note', '')}.\n"
                "Continue your reasoning. What is your next specific hypothesis and action?"
            )

        elif act == "report_found":
            return "FOUND"

        elif act == "report_not_found":
            return "NOT_FOUND"

        return "Unknown action. Valid: send_request | analyze | report_found | report_not_found"

    def _initial_context(self) -> str:
        ep = self.endpoint
        return f"""You are testing this endpoint for: {self.VULN_TYPE}

URL:             {ep.get("url")}
Method:          {ep.get("method", "GET")}
URL parameters:  {json.dumps(ep.get("params", {}))}
Body parameters: {json.dumps(ep.get("body_params", {}))}
Cookies:         {json.dumps(ep.get("cookies", {}))}
Content-Type:    {ep.get("content_type", "unknown")}
Discovered via:  {ep.get("source", "unknown")}

Sample response (first 600 chars):
{ep.get("response_sample", "Not yet fetched")[:600]}

Observe this endpoint carefully. Do not assume anything yet.
What do you actually see? What does the URL, parameter names, response content,
and context tell you about how this application works?
What is your first reasoned hypothesis about where {self.VULN_TYPE} might exist here?"""

    def _format_response(self, resp: dict) -> str:
        if resp.get("error"):
            return (
                f"Request failed: {resp['error']}\n\n"
                "What does this failure tell you about the application or your approach? "
                "What is your updated hypothesis?"
            )

        return f"""Response received.

Status:    {resp["status"]}
Length:    {resp["length"]} bytes
Time:      {resp["time_ms"]}ms
Final URL: {resp["url"]}

Headers:
{json.dumps(dict(list(resp["headers"].items())[:20]), indent=2)}

Body (first 2000 chars):
{resp["body"][:2000]}

━━━ Reason from this response ━━━
What does this tell you?
- Where exactly did your input appear? How was it handled — reflected, encoded, stripped, evaluated?
- What do the headers reveal about how the application processes this request?
- Does this confirm, partially confirm, or refute your hypothesis?
- What does this tell you about the application's behavior?
What is your updated hypothesis, and what is your next action?"""

    def _build_finding(self, action: dict) -> dict:
        tp = action.get("tool_params", {})
        chain = "\n\n".join([
            f"Iter {i+1}: {a['reasoning'][:250]}\n"
            f"→ {a['request'].get('method','GET')} {a['request'].get('url','')} "
            f"params={a['request'].get('params',{})} "
            f"| status={a['response'].get('status')} len={a['response'].get('length')}"
            for i, a in enumerate(self.attempts)
        ])
        return {
            "vuln_type":         self.VULN_TYPE,
            "url":               self.endpoint["url"],
            "param":             tp.get("param", ""),
            "payload":           tp.get("final_payload", ""),
            "evidence":          tp.get("evidence", ""),
            "severity":          tp.get("severity", "High"),
            "cvss":              float(tp.get("cvss", 0.0)),
            "poc_steps":         tp.get("poc_steps", []),
            "why_it_works":      tp.get("why_it_works", ""),
            "reasoning_chain":   chain,
            "verified":          False,
            "verification_note": "",
        }

    def _extract_json(self, text: str) -> str:
        text  = text.strip()
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
        return text