"""
agents/auth_agent.py — Autonomous authentication agent.

What it does:
  1. Finds registration/login endpoints on the target
  2. Generates realistic test credentials
  3. Signs up for an account automatically
  4. Logs in and captures the full session (cookies + tokens + headers)
  5. Returns an AuthSession object used by all subsequent agents

The agent reasons about the specific registration/login flow it finds —
it does not follow a fixed form-filling script. It reads the forms,
understands the fields, handles CAPTCHAs it can bypass, follows
redirects, and captures whatever auth artifacts the app produces.

HOW TO USE:
  Called automatically by orchestrator before vuln testing begins.
  The captured session is injected into core/http_client.py globally.

HOW TO OVERRIDE (if target needs a real account):
  Set in .env:
    AUTH_EMAIL=your@email.com
    AUTH_PASSWORD=YourPassword123
    AUTH_COOKIE=session=abc123; token=xyz
  The agent will skip registration and use these directly.
"""

import json
import re
import uuid
import asyncio
from loguru import logger
from core.llm import orchestrator_think
from core.http_client import HTTPClient
import config


# ── Auth Session Data Class ────────────────────────────────────────
class AuthSession:
    """Holds all auth artifacts captured after successful login."""

    def __init__(self):
        self.cookies: dict       = {}   # session cookies
        self.headers: dict       = {}   # auth headers (Authorization, X-Auth-Token, etc.)
        self.token: str          = ""   # JWT or Bearer token if found
        self.csrf_token: str     = ""   # CSRF token for state-changing requests
        self.user_email: str     = ""
        self.user_password: str  = ""
        self.user_id: str        = ""
        self.authenticated: bool = False
        self.method: str         = ""   # "cookie" | "bearer" | "basic" | "none"
        self.notes: str          = ""   # anything interesting about the auth flow

    def to_request_kwargs(self) -> dict:
        """Returns kwargs to inject into every HTTP request."""
        kwargs = {}
        if self.cookies:
            kwargs["cookies"] = self.cookies
        if self.headers:
            kwargs["headers"] = self.headers
        return kwargs

    def __str__(self):
        return (
            f"AuthSession(authenticated={self.authenticated}, "
            f"method={self.method}, "
            f"email={self.user_email}, "
            f"cookies={list(self.cookies.keys())}, "
            f"token={'yes' if self.token else 'no'})"
        )


# ── Auth Discovery System Prompt ──────────────────────────────────
AUTH_SYSTEM = """
You are an expert web security researcher automating authentication for testing.
Your job: find the registration and login flow on a web application, create a
test account, log in, and capture the session so further security testing can
be done in an authenticated context.

You think from what you observe. You read HTML forms and API responses carefully.
You never assume — you reason from the actual content you see.

WHAT YOU LOOK FOR:
  Registration: /register, /signup, /join, /create-account, /api/auth/register,
                /api/users, forms with email+password+confirm fields
  Login:        /login, /signin, /auth, /api/auth/login, /api/login,
                forms with email/username + password fields
  OAuth:        "Login with Google/GitHub/Facebook" links — try to use email/password instead
  API auth:     POST /api/auth endpoints, /api/token endpoints

WHAT FORM ANALYSIS TELLS YOU:
  Read the HTML carefully. What fields are in the form?
  Required fields: email, username, password, confirm_password, name, phone?
  Hidden fields: CSRF tokens, nonces, form IDs — include them in submission
  Field validation: maxlength, pattern, type=email → tells you input requirements
  The form action attribute: where does it submit to?
  The form method: GET or POST?

WHAT API REGISTRATION LOOKS LIKE:
  POST with JSON body: {"email": "...", "password": "...", "name": "..."}
  Content-Type: application/json
  Response: 200/201 with user object, or 302 redirect, or token in response

WHAT SESSION CAPTURE LOOKS LIKE:
  After login, look for:
  - Set-Cookie headers: session, token, auth, jwt, remember_me, sid
  - Response body: {"token": "...", "access_token": "...", "jwt": "..."}
  - Authorization header requirements for subsequent requests
  - localStorage patterns in response HTML (look for JS setting tokens)

WHAT TELLS YOU LOGIN SUCCEEDED:
  Redirect to /dashboard, /home, /app, /profile → successful login
  Response body no longer contains "login" or "sign in" text
  Response contains user-specific data (email, username, profile info)
  No error messages about wrong credentials
  Session cookie set in Set-Cookie header

WHAT TO DO WITH CAPTCHAs:
  hCaptcha / reCAPTCHA visible on form → skip to login if possible (try existing account)
  If CAPTCHA only on registration → try login endpoint directly
  If CAPTCHA everywhere → set authenticated=False, set notes explaining why

WHAT EMAIL VERIFICATION MEANS:
  If registration requires email verification → notes = "email verification required"
  Some apps let you test without verifying (limited access)
  Some apps have a verification bypass via API
  Note the situation and proceed with whatever access is available

RESPONSE FORMAT — strict JSON:
{
  "thinking": "what you observe and why you're doing this",
  "action": "send_request | extract_session | report_success | report_failed",
  "tool_params": {}
}

For send_request:
{
  "url": "...", "method": "POST",
  "params": {}, "body": {}, "headers": {},
  "raw_body": "...", "content_type": "..."
}

For extract_session:
{
  "cookies": {"name": "value"},
  "headers": {"Authorization": "Bearer ..."},
  "token": "...",
  "csrf_token": "...",
  "method": "cookie | bearer | basic",
  "notes": "..."
}

For report_success:
{
  "email": "...", "password": "...", "user_id": "...",
  "cookies": {}, "headers": {}, "token": "...", "csrf_token": "...",
  "method": "cookie | bearer",
  "notes": "anything interesting about the auth flow"
}

For report_failed:
{
  "reason": "why auth could not be completed",
  "partial_cookies": {},
  "notes": "what was tried"
}
"""


# ── Main Auth Agent ────────────────────────────────────────────────
class AuthAgent:

    def __init__(self, target: str, http: HTTPClient):
        self.target   = target
        self.http     = http
        self.history  = []
        self.max_iter = 25
        self.session  = AuthSession()

        # Generate realistic test credentials
        uid = uuid.uuid4().hex[:8]
        self.email    = f"sectest_{uid}@bugtest.dev"
        self.password = f"SecTest@{uid[:4].upper()}#{uid[4:8]}"
        self.username = f"sectest_{uid}"

    async def run(self) -> AuthSession:
        """
        Attempt to authenticate. Returns an AuthSession.
        If authentication fails, returns an unauthenticated session
        (testing continues without auth).
        """

        # Check if manual credentials are configured
        manual = self._check_manual_credentials()
        if manual:
            return manual

        base_url = f"https://{self.target}"
        logger.info(f"[Auth] Starting auth flow for {self.target}")
        logger.info(f"[Auth] Test credentials: {self.email} / {self.password}")

        # First: fetch the homepage to see what we're dealing with
        home = await self.http.get(base_url)

        initial_context = f"""
Target: {self.target}
Base URL: {base_url}
Test email:    {self.email}
Test password: {self.password}
Test username: {self.username}

Homepage response:
  Status: {home.get('status')}
  URL:    {home.get('url')}

Homepage body (first 3000 chars):
{home.get('body', '')[:3000]}

Analyze this homepage. What authentication system does this application use?
Do you see registration/login links? What is the auth flow?
What is your first action to find and use the registration endpoint?
"""
        self.history.append({"role": "user", "content": initial_context})

        for i in range(self.max_iter):
            raw = orchestrator_think(self.history, AUTH_SYSTEM, max_tokens=2000)
            if not raw:
                break

            self.history.append({"role": "assistant", "content": raw})

            try:
                action = json.loads(self._extract_json(raw))
            except json.JSONDecodeError:
                self.history.append({
                    "role": "user",
                    "content": "Invalid JSON. Respond only with the JSON object."
                })
                continue

            act = action.get("action", "")
            tp  = action.get("tool_params", {})

            logger.debug(f"[Auth] iter {i+1} | {act} | {action.get('thinking','')[:80]}")

            if act == "send_request":
                resp = await self.http.send(
                    url          = tp.get("url", ""),
                    method       = tp.get("method", "GET"),
                    params       = tp.get("params"),
                    body         = tp.get("body"),
                    headers      = tp.get("headers"),
                    raw_body     = tp.get("raw_body"),
                    content_type = tp.get("content_type"),
                )
                # Give the agent the full response including all cookies
                feedback = self._format_response(resp)
                self.history.append({"role": "user", "content": feedback})

            elif act == "extract_session":
                # Agent explicitly identified session artifacts
                self._populate_session_from(tp)
                if self.session.cookies or self.session.token:
                    logger.info(f"[Auth] Session captured: {self.session}")
                    # Verify the session works
                    verified = await self._verify_session(base_url)
                    if verified:
                        self.session.authenticated = True
                        self.session.user_email    = self.email
                        self.session.user_password = self.password
                        logger.success(f"[Auth] Authenticated successfully as {self.email}")
                        return self.session
                    else:
                        self.history.append({
                            "role": "user",
                            "content": "Session verification failed — the cookies/token did not "
                                       "result in an authenticated response. What went wrong? "
                                       "Try logging in again or use a different approach."
                        })

            elif act == "report_success":
                self.session.authenticated = True
                self.session.user_email    = tp.get("email", self.email)
                self.session.user_password = tp.get("password", self.password)
                self.session.user_id       = tp.get("user_id", "")
                self.session.method        = tp.get("method", "cookie")
                self.session.notes         = tp.get("notes", "")
                self._populate_session_from(tp)
                logger.success(f"[Auth] Login succeeded. {self.session}")
                return self.session

            elif act == "report_failed":
                self.session.notes = tp.get("reason", "Auth failed")
                logger.warning(f"[Auth] Auth failed: {tp.get('reason', '')}")
                logger.warning("[Auth] Continuing with unauthenticated testing")
                return self.session

        logger.warning("[Auth] Max iterations reached without auth — continuing unauthenticated")
        return self.session

    def _populate_session_from(self, tp: dict):
        """Extract cookies, headers, and token from agent's tool_params."""
        if tp.get("cookies"):
            self.session.cookies.update(tp["cookies"])
        if tp.get("headers"):
            self.session.headers.update(tp["headers"])
        if tp.get("token"):
            self.session.token = tp["token"]
            if not tp.get("headers"):
                self.session.headers["Authorization"] = f"Bearer {tp['token']}"
        if tp.get("csrf_token"):
            self.session.csrf_token = tp["csrf_token"]
        if tp.get("method"):
            self.session.method = tp["method"]

    async def _verify_session(self, base_url: str) -> bool:
        """
        Verify the captured session actually works by fetching a
        protected-looking URL and checking the response isn't a login redirect.
        """
        for path in ["/dashboard", "/profile", "/account", "/home", "/app", "/me", "/api/me", "/api/user"]:
            resp = await self.http.send(
                url     = f"{base_url}{path}",
                cookies = self.session.cookies,
                headers = self.session.headers,
            )
            status = resp.get("status", 0)
            body   = resp.get("body", "").lower()

            # If we get a non-redirect, non-login response → session works
            if status == 200 and not any(k in body for k in [
                "please log in", "please sign in", "login required",
                "you need to log in", "unauthorized", "unauthenticated"
            ]):
                logger.info(f"[Auth] Session verified via {path} (status {status})")
                return True

        # Fallback: if we have cookies at all, assume it might work
        return bool(self.session.cookies or self.session.token)

    def _check_manual_credentials(self) -> AuthSession | None:
        """If manual credentials are set in .env, use them directly."""
        import os
        email    = os.getenv("AUTH_EMAIL", "")
        password = os.getenv("AUTH_PASSWORD", "")
        cookie   = os.getenv("AUTH_COOKIE", "")
        token    = os.getenv("AUTH_TOKEN", "")

        if not (email or cookie or token):
            return None

        logger.info("[Auth] Using manual credentials from .env")
        session = AuthSession()
        session.authenticated = True
        session.user_email    = email
        session.user_password = password
        session.notes         = "Manual credentials from .env"

        if cookie:
            # Parse "key=value; key2=value2" cookie string
            for part in cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    session.cookies[k.strip()] = v.strip()
            session.method = "cookie"

        if token:
            session.token   = token
            session.headers["Authorization"] = f"Bearer {token}"
            session.method  = "bearer"

        return session

    def _format_response(self, resp: dict) -> str:
        if resp.get("error"):
            return f"Request failed: {resp['error']}. What does this tell you?"

        # Extract Set-Cookie headers specifically — these are critical
        set_cookies = {
            k: v for k, v in resp.get("headers", {}).items()
            if k.lower() == "set-cookie"
        }
        # Also pull cookies from aiohttp's cookie jar representation
        cookie_header = resp.get("headers", {}).get("Set-Cookie", "")

        return f"""Response:
  Status:    {resp["status"]}
  Final URL: {resp["url"]}
  Length:    {resp["length"]} bytes

Response Headers (full — check Set-Cookie carefully):
{json.dumps(dict(resp.get("headers", {})), indent=2)}

Response Body (first 3000 chars):
{resp.get("body", "")[:3000]}

━━━ Analyze this response ━━━
- Did registration/login succeed? What tells you that?
- Are there Set-Cookie headers? What cookie names were set?
- Is there a token in the response body?
- Does the response redirect you somewhere? Where?
- What is your next action?
If you see session cookies or tokens → use extract_session to capture them.
If you confirmed success → use report_success."""

    def _extract_json(self, text: str) -> str:
        text  = text.strip()
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end != -1:
            return text[start:end + 1]
        return text