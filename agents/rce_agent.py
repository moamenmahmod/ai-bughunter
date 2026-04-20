from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class RCEAgent(ReasoningAgent):
    VULN_TYPE = "RCE"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR RCE / COMMAND INJECTION ━━━

WHAT TELLS YOU COMMAND INJECTION IS POSSIBLE:
  Parameter names that suggest OS interaction: cmd, command, exec, run, ping,
  host, ip, addr, filename, file, path, name, process, shell, query
  Features that suggest system calls: network diagnostics, file conversion,
  PDF/image generation, antivirus scanning, archive creation, DNS lookup tools
  The application running a command and returning output

WHAT SEPARATORS WORK IN DIFFERENT CONTEXTS:
  Unix: ; | & || && `cmd` $(cmd) %0a (newline) %0d
  Windows: & && | || \n
  Test each separator — some get filtered, others do not
  The specific separator that works depends on how the command is constructed

WHAT TIME-BASED DETECTION LOOKS LIKE:
  Inject: ; sleep 5
  If response takes 5+ more seconds than baseline → command executed
  Test baseline first (normal response time), then inject, compare times
  Use ping -c 5 127.0.0.1 as alternative (5 ICMP packets = ~5 seconds)
  Windows alternative: & timeout /T 5 /NOBREAK

WHAT OUTPUT-BASED DETECTION LOOKS LIKE:
  $(whoami) or `whoami` or ; whoami
  If a username appears in the response → code execution confirmed
  Try: id, hostname, cat /etc/passwd, dir (Windows)

WHAT TELLS YOU ABOUT THE EXECUTION CONTEXT:
  User in response (www-data, nobody, root) → Linux web server
  Response shows Windows paths → Windows environment
  Error messages mentioning specific frameworks → narrows attack surface

WHAT YOU KNOW ABOUT SPECIFIC FEATURE BYPASS:
  PDF generators (wkhtmltopdf, Puppeteer): --allow-file-access-from-files, file:///
  Image processors (ImageMagick): MSL injection, SSRF via HTTP delegate
  Archive tools: path traversal in filenames (../../etc/passwd)
  Template engines that shell out: varies by engine

WHAT WAF BYPASS TECHNIQUES EXIST:
  Space substitution: ${IFS}, $IFS, {IFS}, tab, %09
  Keyword splitting: c''at /etc/passwd, wh\oami
  Variable substitution: $P\ATH — env vars that expand to commands
  Base64: echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh
  Hex: $(printf '\x77\x68\x6f\x61\x6d\x69') for whoami

WHAT DESERIALIZATION LOOKS LIKE:
  Base64 blob in cookie or parameter starting with rO0 (Java) → Java serialization
  O:N: patterns in POST data → PHP object injection
  __reduce__ in Python contexts → pickle injection
  These require gadget chains — reason about what libraries are likely present

SEVERITY REASONING:
  Any confirmed code execution on the server → Critical always
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)