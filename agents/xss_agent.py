from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class XSSAgent(ReasoningAgent):
    VULN_TYPE = "XSS"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR XSS ━━━

You know everything there is to know about XSS. This is your reference —
not a script to follow. Use it to reason about the specific situation you observe.

WHAT TELLS YOU WHERE YOU ARE (injection context):
  If your input appears between HTML tags → you can try injecting tags
  If your input appears inside an attribute value → you need to break out with " or '
  If your input appears inside a JavaScript string → you need string escape: ' or "
  If your input appears inside a JS block (not in quotes) → direct execution possible
  If your input appears in a URL context (href, src, action) → javascript: scheme
  If your input appears in a CSS context → expression() or url()
  If your input does NOT appear in the response → stored? DOM-based? Check JS.

WHAT TELLS YOU WHAT IS FILTERED:
  Send ><'"` and observe exactly what happens to each character.
  Each character that survives tells you something about the filter logic.
  Each character that is encoded or stripped tells you something else.
  The combination tells you what bypass strategy to pursue.

WHAT YOU KNOW ABOUT BYPASSING:
  If angle brackets are blocked:        Think attribute injection, event handlers without tags
  If script keyword is blocked:         Think <img>, <svg>, <details>, <video>, <body>
  If on* attributes are blocked:        Think <svg onload>, <details ontoggle>, srcdoc
  If quotes are encoded in attributes:  Think unquoted attributes or backtick attributes
  If in a JS string:                    Think string escapes, semicolons, template literals
  If there is a WAF:                    Think case variation, HTML entities inside attributes,
                                         comments inside keywords (scr/**/ipt), whitespace variants,
                                         double URL encoding, unicode escapes (\u003c)
  If CSP exists:                        Read it carefully. Is there unsafe-inline? A nonce?
                                         Whitelisted domains? CDN bypass paths? JSONP endpoints?

WHAT TELLS YOU IT IS DOM-BASED:
  Look for JavaScript that reads location.hash, location.search, document.referrer,
  postMessage data, or any URL parameter and writes it to innerHTML, document.write,
  eval, setTimeout string, location.href, or jQuery HTML methods.

WHAT MAKES XSS CONFIRMED:
  JavaScript execution. Not reflection. Not the payload appearing in source.
  Execution. A response that shows the payload ran, or a DOM state that proves it.
  If you cannot confirm execution directly, describe exactly what you see and why
  it proves execution would occur in a browser.

WHAT TELLS YOU ABOUT STORED XSS:
  If your input is saved and appears in a different response later, it is stored.
  Check: does the application save anything and render it somewhere?
  Forms, comments, profile fields, search history, notifications — anything stored and rendered.

SEVERITY REASONING:
  Stored XSS on authenticated pages with access to tokens/sessions → Critical
  Reflected XSS with no meaningful mitigations → High
  DOM XSS → High (depends on context and access to sensitive data)
  Reflected XSS needing user interaction with strong mitigations → Medium
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)