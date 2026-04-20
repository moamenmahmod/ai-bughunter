from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class OpenRedirectAgent(ReasoningAgent):
    VULN_TYPE = "OpenRedirect"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR OPEN REDIRECT ━━━

WHAT THE PARAMETER TELLS YOU BEFORE YOU EVEN TEST:
  Parameters like: url, redirect, redirect_uri, redirect_url, return, return_url,
  next, goto, target, link, location, forward, dest, destination, continue, ref,
  callback, r, ReturnUrl, successUrl, failUrl — these are your targets.
  Their NAME tells you the developer's intent. The value controls where the user goes.

WHAT THE RESPONSE TELLS YOU:
  A 301 or 302 with a Location header containing your value → open redirect (check the value)
  A 200 with a meta refresh containing your value → redirect via HTML
  A 200 with JS location.href = your value → redirect via JS
  The Location header is the main signal. What exactly is in it?

WHAT DIFFERENT VALIDATION LOGIC LOOKS LIKE FROM THE OUTSIDE:
  If https://evil.com is blocked but //evil.com works:
    → Server is checking for http:// or https:// prefix but not protocol-relative
  If https://evil.com is blocked but /\evil.com works:
    → Backslash treated as path separator by browser but not by server validation
  If https://evil.com is blocked but https://evil.com#https://target.com works:
    → Server is checking if target.com appears in the URL but not anchoring the check
  If https://evil.com is blocked but https://target.com@evil.com works:
    → Server sees target.com before the @ and thinks it's the host
    → Browser sees evil.com as the actual host (user:password@host format)
  If https://evil.com is blocked but https://target.com.evil.com works:
    → Suffix check: server checks string ends with target.com but dot is not enforced
  If https://evil.com is blocked but https://TARGET.evil.com works (where TARGET is in the allowlist):
    → Subdomain prefix matching — the server trusts domains starting with the target name

WHAT URL ENCODING AND VARIANTS REVEAL:
  %2F%2Fevil.com (URL encoded //) → server decodes before validating or after?
  %5Cevil.com (encoded \) → same logic as backslash bypass
  ///evil.com → triple slash — some validators only strip one slash
  ////evil.com → same idea with more slashes
  These reveal whether the server normalizes URLs before validation

WHAT OAUTH redirect_uri TELLS YOU:
  If this is an OAuth redirect_uri parameter, the stakes are higher:
  A successful bypass means the authorization code is sent to the attacker
  That code can then be exchanged for an access token → account takeover
  Test with extra path: https://target.com/callback/../../../attacker.com
  Test with query: https://target.com/callback?next=https://evil.com
  Test with fragment: https://target.com/callback#https://evil.com
  The redirect_uri exact-match requirement is often not enforced strictly

WHAT JAVASCRIPT SCHEME MEANS:
  If javascript:alert(1) is accepted as a redirect target → XSS via open redirect
  This is a higher severity finding than a plain open redirect

WHAT MAKES AN OPEN REDIRECT HIGH IMPACT:
  On its own: Medium (phishing, credential harvesting for users who trust the domain in URL)
  In OAuth flow: High (token/code leakage → account takeover)
  With javascript: scheme: High (XSS)
  Combined with SSRF context: depends on target

SEVERITY REASONING:
  Open redirect in OAuth redirect_uri → High
  Open redirect with javascript: → High (XSS)
  Open redirect to external domain with no auth context → Medium
  Redirect to same-domain path only → Low / Informational
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)