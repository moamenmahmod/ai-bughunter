# How To Edit The AI Bug Hunter System

---

## Adding a New Tool (e.g. amass, naabu, nuclei)

1. Open `tools/recon.py`
2. Add an async function following the same pattern:
```python
async def run_amass(domain: str) -> List[str]:
    cmd = ["amass", "enum", "-d", domain, "-silent"]
    out = await asyncio.wait_for(_run(cmd), timeout=300)
    return [l.strip() for l in out.splitlines() if l.strip()]
```
3. Open `agents/recon_agent.py`
4. Import your function at the top
5. Call it inside `recon_node()` and merge results into `all_urls` or `subdomains`

---

## Adding a New Vulnerability Agent

1. Create `agents/my_vuln_agent.py`:
```python
from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient

class MyVulnAgent(ReasoningAgent):
    VULN_TYPE = "MyVuln"
    VULN_PROMPT = """
VULNERABILITY: My Custom Vulnerability

YOUR METHODOLOGY:
Phase 1 — Detection: ...
Phase 2 — Exploitation: ...
Phase 3 — Impact: ...

SEVERITY: ...
"""
    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)
```

2. Open `orchestrator.py`
3. Import: `from agents.my_vuln_agent import MyVulnAgent`
4. Add to `AGENT_MAP`: `"MyVuln": MyVulnAgent`
5. Add to `VULN_RELEVANCE`: `"MyVuln": lambda ep: True`  (or your condition)

That's it. The reasoning loop, parallelism, verification, and reporting all work automatically.

---

## Editing an Existing Vuln Agent's Behaviour

Open the agent file (e.g. `agents/xss_agent.py`) and edit `VULN_PROMPT`.

The prompt is the agent's instruction manual. You can:
- Add new techniques: "Also try mXSS (mutation XSS) in innerHTML sinks"
- Restrict focus: "Only test GET parameters, skip POST bodies"
- Change severity rules: "Treat self-XSS as Medium not Low"
- Add WAF-specific bypasses you've discovered

No code changes needed — just edit the text.

---

## Changing Which Endpoints Get Tested for What

Open `orchestrator.py` and edit `VULN_RELEVANCE`.

Each entry is: `"VulnType": lambda endpoint -> bool`

```python
# Current: test XSS only on endpoints with params
"XSS": lambda ep: _has_params(ep),

# Change to: also test endpoints with no params (blind XSS in headers etc.)
"XSS": lambda ep: True,

# Change to: only test if specific keywords in URL
"SQLi": lambda ep: any(k in ep["url"] for k in ["id=", "user=", "item="]),
```

---

## Tuning Agent Behaviour Globally

Open `config.py` and change:

```python
MAX_VULN_ITERATIONS   = 20    # More = deeper reasoning but slower + more API cost
PARALLEL_ENDPOINT_CAP = 8     # More = faster but risks rate limits and detection
GROQ_CONCURRENCY      = 4     # Match to your Groq plan's rate limit
REQUEST_TIMEOUT       = 15    # Increase for slow targets
REQUEST_DELAY         = 0.3   # Increase to be stealthier
MAX_ENDPOINTS_TEST    = 200   # Reduce for quick scans
```

---

## Swapping an LLM Model

Open `config.py`:

```python
# To use DeepSeek R1 for vuln agents instead of Qwen3:
MODEL_VULN = "deepseek-reasoner"

# To use Gemini for orchestration:
MODEL_ORCHESTRATOR = "gemini-2.5-pro-preview-05-06"
# Then update core/llm.py orchestrator_think() to use the gemini client
```

---

## Adding a Custom HTTP Header to All Requests

Open `core/http_client.py` and edit `DEFAULT_HEADERS`:

```python
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 ...",
    "X-Custom-Header": "my-value",   # add your header here
    "Cookie": "session=abc123",       # add auth cookies here
}
```

For per-target auth, add to the initial state and pass it through.

---

## Adding Authentication (Login First, Then Test)

1. Open `core/http_client.py`
2. Add a `login()` method that performs the login and stores cookies
3. Call it in `recon_agent.py` before crawling
4. The session will carry cookies automatically through `aiohttp.ClientSession`

---

## Changing the Discord Report Format

Open `reporter.py` and edit `_build_embed()`. 
Each `field` in the embed is a Discord field object with `name`, `value`, `inline`.
Add, remove, or reorder fields freely.

---

## Running Only Specific Vuln Types

```bash
# Test only XSS and SQLi
python main.py --target example.com --vulns xss sqli

# Available: xss sqli xxe rce ssti cors csrf openredirect ssrf oauth infodisclosure
```

---

## Saving Results to a Different Directory

```bash
python main.py --target example.com --output-dir /path/to/reports
```

---

## Understanding the Output Files

```
output/
├── 2025-01-15_10-30_example.com_report.md    ← Full human-readable report
├── 2025-01-15_10-30_example.com_findings.json ← Machine-readable findings
└── run_20250115_103000.log                    ← Full debug log
```
