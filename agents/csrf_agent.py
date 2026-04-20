from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class CSRFAgent(ReasoningAgent):
    VULN_TYPE = "CSRF"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR CSRF ━━━

WHAT THE REQUEST AND RESPONSE TELL YOU:
  Look at the original request carefully.
  Is there a token in the body? (csrf_token, _token, authenticity_token, state, nonce)
  Is there a custom header? (X-CSRF-Token, X-Requested-With, X-CSRFToken)
  Look at the Set-Cookie headers — is SameSite specified?
  Look at the response — does it validate anything beyond the session cookie?

WHAT SAMESITE COOKIE VALUES MEAN FOR EXPLOITABILITY:
  SameSite=Strict   → Cookies not sent cross-site at all → CSRF not exploitable
  SameSite=Lax      → Cookies sent only on top-level GET navigations → CSRF on POST blocked
                       BUT: some browsers/versions have exceptions — check carefully
                       Lax + POST CSRF is blocked. Lax + GET state-change might work.
  SameSite=None     → Cookies sent cross-site always → CSRF fully possible if no other protection
  No SameSite set   → Older browsers: cookies sent cross-site → CSRF possible
                       Modern Chrome (2020+): defaults to Lax for cookies without attribute

WHAT TELLS YOU TOKEN VALIDATION IS BROKEN:
  Send the request without the token → if it succeeds → no validation
  Send it with an empty token → if it succeeds → presence check only, not value
  Send it with a wrong token → if it succeeds → token is not validated at all
  Send it with another user's valid token → if it succeeds → no per-user binding
  Change the token parameter name slightly → if it still works → server not checking that field

WHAT TELLS YOU ORIGIN/REFERER CHECKING IS THE ONLY PROTECTION:
  If there is no token but the request has Referer/Origin headers
  Try sending without Referer (null referer) or with wrong Referer
  If it still works without Referer → only relying on Referer which is bypassable

WHAT CONTENT-TYPE BYPASS LOOKS LIKE:
  Some APIs use Content-Type: application/json
  JSON cannot be sent by a simple HTML form — browsers send form-urlencoded or multipart
  But: if the server accepts text/plain or application/x-www-form-urlencoded with JSON-shaped body
  Then a simple form can trigger the action cross-origin
  Test: change Content-Type to text/plain and send — does the server still process it?

WHAT MAKES CSRF WORTH REPORTING:
  The action must have impact. Only state-changing actions matter:
  Password or email change → account takeover → High
  Add admin / escalate privilege → Critical
  Transfer funds / make purchases → Critical
  Delete account or data → High
  Add OAuth app, SSH key, webhook → High
  Change notification settings → Low (not worth reporting usually)
  Read-only endpoints → never CSRF, it is a cross-origin read problem (different)

WHAT A PoC LOOKS LIKE:
  For form-based CSRF (no token):
  <form method="POST" action="https://target.com/change-email">
    <input name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit()</script>

  For GET-based CSRF:
  <img src="https://target.com/delete-account?confirm=true">

SEVERITY REASONING:
  Account takeover, privilege escalation, financial impact → High/Critical
  Sensitive data change (email, password) → High
  Low-impact setting change → Low
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)