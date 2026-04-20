"""
core/http_client.py — Async HTTP client with global auth session support.

After AuthAgent runs, call http_client.set_auth_session(session).
Every subsequent request automatically carries the captured cookies/headers.

Individual agents can still override headers/cookies per-request if needed
(e.g. to test unauthenticated behavior for comparison).
"""

import asyncio
import time
import aiohttp
import config
from loguru import logger


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
}

# ── Global auth session (set once after AuthAgent runs) ───────────
_auth_session = None   # type: ignore  # AuthSession | None


def set_auth_session(session) -> None:
    """
    Call this after AuthAgent completes.
    All subsequent HTTP requests will carry the session automatically.
    """
    global _auth_session
    _auth_session = session
    if session and session.authenticated:
        logger.info(
            f"[HTTPClient] Auth session active — "
            f"method={session.method} "
            f"cookies={list(session.cookies.keys())} "
            f"token={'yes' if session.token else 'no'}"
        )


def get_auth_session():
    return _auth_session


class HTTPClient:

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False, limit=20)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=config.REQUEST_TIMEOUT),
                headers=DEFAULT_HEADERS,
            )
        return self._session

    async def send(
        self,
        url:          str,
        method:       str  = "GET",
        params:       dict = None,
        body:         dict = None,
        headers:      dict = None,
        cookies:      dict = None,
        raw_body:     str  = None,
        content_type: str  = None,
        skip_auth:    bool = False,   # set True to test unauthenticated behavior
    ) -> dict:
        """
        Send an HTTP request.

        Auth injection:
          If a global AuthSession is set and skip_auth=False,
          the session's cookies and headers are automatically merged
          into every request. Per-request cookies/headers take priority
          over session ones (so agents can override specific values).
        """
        await asyncio.sleep(config.REQUEST_DELAY)
        session = await self._get_session()

        # ── Build headers ──────────────────────────────────────────
        req_headers = {**DEFAULT_HEADERS}

        # Inject auth session headers first (lowest priority)
        if not skip_auth and _auth_session and _auth_session.authenticated:
            if _auth_session.headers:
                req_headers.update(_auth_session.headers)

        # Then per-request headers override (highest priority)
        if headers:
            req_headers.update(headers)

        if content_type:
            req_headers["Content-Type"] = content_type

        # ── Build cookies ──────────────────────────────────────────
        req_cookies = {}

        # Inject auth session cookies
        if not skip_auth and _auth_session and _auth_session.authenticated:
            if _auth_session.cookies:
                req_cookies.update(_auth_session.cookies)

        # Per-request cookies override
        if cookies:
            req_cookies.update(cookies)

        # ── Build body ─────────────────────────────────────────────
        start = time.monotonic()
        try:
            kwargs = dict(
                method         = method.upper(),
                url            = url,
                params         = params,
                headers        = req_headers,
                cookies        = req_cookies if req_cookies else None,
                allow_redirects= True,
                max_redirects  = 5,
            )

            if raw_body is not None:
                kwargs["data"] = raw_body.encode()
            elif body and content_type and "form" in content_type:
                kwargs["data"] = body
            elif body:
                kwargs["json"] = body

            async with session.request(**kwargs) as resp:
                elapsed = int((time.monotonic() - start) * 1000)
                try:
                    body_text = await resp.text(encoding="utf-8", errors="replace")
                except Exception:
                    body_text = ""

                # Capture any new cookies set during this request
                # (e.g. CSRF token refreshes, session rotation)
                new_cookies = {}
                for cookie_morsel in resp.cookies.values():
                    new_cookies[cookie_morsel.key] = cookie_morsel.value

                return {
                    "status":      resp.status,
                    "body":        body_text,
                    "headers":     dict(resp.headers),
                    "cookies":     new_cookies,
                    "length":      len(body_text),
                    "time_ms":     elapsed,
                    "url":         str(resp.url),
                    "error":       None,
                }

        except asyncio.TimeoutError:
            return _error_result(url, "Request timed out")
        except aiohttp.ClientError as e:
            return _error_result(url, str(e))
        except Exception as e:
            logger.warning(f"HTTP error [{url}]: {e}")
            return _error_result(url, str(e))

    async def get(self, url: str, **kwargs) -> dict:
        return await self.send(url, method="GET", **kwargs)

    async def post(self, url: str, **kwargs) -> dict:
        return await self.send(url, method="POST", **kwargs)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


def _error_result(url: str, error: str) -> dict:
    return {
        "status":  0,
        "body":    "",
        "headers": {},
        "cookies": {},
        "length":  0,
        "time_ms": 0,
        "url":     url,
        "error":   error,
    }