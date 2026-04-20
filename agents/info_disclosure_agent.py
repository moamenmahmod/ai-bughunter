from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class InfoDisclosureAgent(ReasoningAgent):
    VULN_TYPE = "InfoDisclosure"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR INFORMATION DISCLOSURE ━━━

WHAT THE RESPONSE HEADERS TELL YOU:
  Server: Apache/2.4.41 → exact version → check CVEs for that version
  X-Powered-By: PHP/7.4.3 → exact PHP version → known vulnerabilities
  X-AspNet-Version → .NET version
  X-Backend-Server → internal hostname leaked
  Via: → proxy chain exposed
  X-Debug-Token → Symfony debug mode active
  X-CF-Ray → Cloudflare, reveals CDN presence
  Permissions-Policy, Content-Security-Policy → tells you what the app trusts

WHAT ERROR MESSAGES TELL YOU:
  Stack traces → framework, file paths, function names, database structure
  SQL errors → table names, column names, database backend
  Exception class names → language, framework, libraries used
  File paths in errors → internal server directory structure
  "Debug mode" messages → application in development configuration

WHAT DELIBERATE ERROR TRIGGERING REVEALS:
  Send a string where a number is expected → type error → framework revealed
  Send a very large value → overflow or truncation error
  Send a null byte (%00) → file path handling error
  Send unexpected JSON structure → parser error with stack trace
  Send a missing required field → validation error message
  Each of these may produce a different error with different information

WHAT COMMON SENSITIVE FILES LOOK LIKE WHEN ACCESSIBLE:
  /.env → DATABASE_URL, SECRET_KEY, API keys — Critical if found
  /.git/config → remote repository URL (may reveal internal infrastructure)
  /.git/HEAD → confirms .git is accessible → run git-dumper to get source
  /config.php, /config.json, /settings.py → credentials, connection strings
  /web.config → .NET application configuration, sometimes credentials
  /phpinfo.php → full PHP configuration, server info, environment variables
  /server-status → Apache status page, shows current requests, internal IPs

WHAT ACTUATOR ENDPOINTS TELL YOU (Spring Boot Java apps):
  /actuator → lists available actuator endpoints
  /actuator/env → ALL environment variables including secrets
  /actuator/mappings → all URL routes in the application
  /actuator/beans → all Spring beans, reveals architecture
  /actuator/heapdump → full heap dump → contains everything in memory → Critical
  /actuator/trace or /actuator/httptrace → recent HTTP requests including auth headers
  /actuator/logfile → application logs
  Any of these accessible without auth → High/Critical

WHAT SWAGGER/OPENAPI DISCLOSURE TELLS YOU:
  /api-docs, /swagger.json, /openapi.json, /swagger-ui.html, /v2/api-docs
  These list ALL endpoints including ones not shown in the UI
  Look for: admin endpoints, internal-only endpoints, endpoints accepting file uploads
  Look for: example request bodies that contain real data or test credentials
  Look for: deprecated endpoints that may have weaker security

WHAT JAVASCRIPT FILES TELL YOU:
  API keys embedded in client-side JS → Critical (cloud provider keys especially)
  Internal API endpoint paths → expand attack surface
  Authentication logic → may reveal bypass opportunities
  Commented-out code → may reveal old endpoints, debug features, credentials
  Source maps (.js.map) → exposes original unminified source code

WHAT BACKUP AND EDITOR FILES MEAN:
  file.php~ → vim backup → contains source code
  file.php.bak, file.php.old, file.php.orig → backup copies
  .file.php.swp → vim swap file → partial source
  These expose source code of the current file → check for credentials, logic flaws

WHAT CLOUD STORAGE EXPOSURE LOOKS LIKE:
  S3 bucket names often appear in JS files, HTML, API responses
  Test: https://BUCKETNAME.s3.amazonaws.com/ → does it list files?
  GCS: https://storage.googleapis.com/BUCKETNAME/
  If bucket lists → check what is in it → may contain backups, user data, credentials

SEVERITY REASONING:
  API keys, passwords, private keys, database credentials → Critical
  Source code exposure, heap dump → Critical
  Stack traces with paths and framework info → Medium
  Version numbers in headers only → Low
  robots.txt listing paths → Informational
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)