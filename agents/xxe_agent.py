from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class XXEAgent(ReasoningAgent):
    VULN_TYPE = "XXE"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR XXE ━━━

WHAT TELLS YOU XML IS BEING PARSED:
  Content-Type: application/xml, text/xml, application/soap+xml
  Endpoints: /ws, /soap, /service, /wsdl, /api (try switching to XML)
  File uploads: SVG, DOCX, XLSX, PPTX, ODT are all XML-based formats
  Responses that reflect XML structure back to you
  Error messages mentioning XML, SAX, DOM, parser

WHAT TELLS YOU ENTITIES ARE PROCESSED:
  Inject <!DOCTYPE foo [<!ENTITY test "CANARY123">]> and reference &test;
  If CANARY123 appears in the response → external entities likely also processed

WHAT TELLS YOU THE PARSER IS VULNERABLE:
  Internal entity reflected → try external entity with file:// or http://
  Error message references the entity value → parser is processing DOCTYPE

WHAT DIFFERENT PARSERS SUPPORT:
  libxml2 (PHP, Python):    Supports external entities by default (older versions)
  Java SAX/DOM:             Depends on configuration — many still vulnerable
  .NET XmlReader:           Often vulnerable unless explicitly hardened
  Expat:                    Does not support external entities by default

WHAT FILE PATHS TO TARGET:
  Linux: /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ,
         /proc/self/cmdline, application config files, .env files
  Windows: c:/windows/win.ini, c:/inetpub/wwwroot/web.config

WHAT TELLS YOU IT IS BLIND (no output reflected):
  Entity is processed but value does not appear in response
  Try out-of-band: point SYSTEM to http://your-callback-server/
  DNS hit or HTTP hit on your server confirms blind XXE

WHAT YOU KNOW ABOUT PHP WRAPPERS (if PHP backend suspected):
  php://filter/convert.base64-encode/resource=/etc/passwd
  Returns base64 of file content — decode to get the file

WHAT TELLS YOU IT IS AN SVG UPLOAD:
  Image upload that accepts SVG → inject XXE into the SVG XML
  The server may parse it server-side to render or process it

WHAT TELLS YOU IT IS A DOCX/XLSX:
  Create a minimal DOCX (zip of XML files), inject XXE into word/document.xml
  Upload the file and check if the server processes the XML inside

WHAT MAKES XXE ESCALATE BEYOND FILE READ:
  SSRF via XXE: SYSTEM "http://169.254.169.254/latest/meta-data/"
  Internal service scanning: SYSTEM "http://127.0.0.1:8080/"

SEVERITY REASONING:
  /etc/passwd, source code, credentials read → Critical
  SSRF to internal/metadata → Critical
  Blind XXE (OOB confirmed only) → Medium
  Internal file read from a low-sensitivity file → High
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)