from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class OAuthAgent(ReasoningAgent):
    VULN_TYPE = "OAuth"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR OAUTH / JWT / AUTH ━━━

WHAT THE ENDPOINT TELLS YOU ABOUT THE AUTH FLOW:
  /oauth/authorize or /authorize → authorization endpoint, look at redirect_uri
  /oauth/token or /token → token endpoint, look at grant_type and code handling
  /oauth/callback or /callback → where codes land, look at state validation
  /.well-known/openid-configuration → lists all endpoints and supported features
  /login?provider=... → social login flow
  JWT tokens (eyJ...) anywhere → JWT-specific attacks apply

WHAT redirect_uri VALIDATION PROBLEMS LOOK LIKE:
  Test by manipulating redirect_uri in the authorization request.
  Exact match enforcement: only https://app.com/callback is valid → hard to bypass
  Path prefix matching: https://app.com/* allowed → try ../../../ path traversal
  Domain suffix matching: anything ending in .app.com → attacker.app.com works
  Contains matching: if app.com appears anywhere → target.com@evil.com or evil.com?x=app.com
  Open redirect chaining: redirect_uri=https://app.com/redirect?next=https://evil.com
    → Code lands on app.com which then sends it to evil.com via open redirect
  Fragment manipulation: some servers ignore fragment, browsers do not
  When bypass works: the authorization code goes to attacker-controlled URL
  The code can then be exchanged for a token → account takeover

WHAT state PARAMETER TELLS YOU:
  No state parameter in the request → CSRF on the OAuth flow is possible
  State present but same across requests → predictable, CSRF possible
  State present and varies → test if server actually validates it
  Test: start auth flow, capture URL, use it in a different browser session
  If it completes authentication → state not validated → CSRF

WHAT JWT STRUCTURE TELLS YOU:
  eyJ... → base64url encoded JSON → decode it
  Header.Payload.Signature format
  Read the header: what algorithm? RS256, HS256, none?
  Read the payload: what claims? sub, role, admin, exp, iss?

  alg:none attack:
  If the server accepts algorithm "none", signature is not verified
  Forge any payload: change sub to victim's ID, change role to admin
  Encode without signature: header.payload. (empty signature)

  RS256 to HS256 confusion:
  If the server uses RS256 (asymmetric), the public key is often exposed
  If you switch alg to HS256 (symmetric) and sign with the public key as the HMAC secret
  A misconfigured server may accept this — it thinks it is HMAC, uses public key as secret

  Weak HS256 secret:
  If algorithm is HS256, try cracking the secret with common passwords
  Common secrets: secret, password, jwt_secret, app name, empty string
  If cracked: forge any payload

  jku/x5u header injection:
  If JWT header has jku field (URL to JWKS), point it to your own JWKS
  Server fetches your public key to verify → you signed with matching private key

  kid injection:
  If JWT header has kid (key ID), and it is used in a SQL query → SQLi
  Or if used in a file path → path traversal (kid=../../dev/null → verify with empty key)

WHAT TELLS YOU EMAIL VERIFICATION IS BROKEN:
  Register with unverified email matching a victim's account email
  Try logging in with Google/GitHub OAuth using an unverified email
  If the app merges accounts by email without verifying ownership → account takeover

WHAT PRE-AUTHENTICATION LOOKS LIKE:
  Start linking an OAuth provider to your account
  Before you complete: capture the OAuth link URL
  Send it to a victim (CSRF-style)
  If they click it while logged in to their account → your OAuth account is linked to theirs

SEVERITY REASONING:
  Account takeover via any of the above → Critical
  Auth bypass via JWT manipulation → Critical
  CSRF on OAuth flow → High
  Token/code leakage via redirect_uri → High
  JWT info disclosure only → Low/Medium
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)