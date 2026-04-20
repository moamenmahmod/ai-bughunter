import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ───────────────────────────────────────────────────────
DEEPSEEK_API_KEY   = os.getenv("DEEPSEEK_API_KEY", "")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
DISCORD_WEBHOOK    = os.getenv("DISCORD_WEBHOOK", "")

# ── Model Names ────────────────────────────────────────────────────
# Change these if you want to swap models
MODEL_ORCHESTRATOR  = "deepseek-chat"             # DeepSeek V3.1
MODEL_VULN          = "qwen/qwen3-235b-a22b"      # Qwen3 235B on Groq (thinking)
MODEL_FAST          = "llama-3.3-70b-versatile"   # Groq Llama — fast tasks
MODEL_GEMINI        = "gemini-2.5-pro-preview-05-06"

# ── Recon Tool API Keys ────────────────────────────────────────────
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
CENSYS_API_ID      = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET  = os.getenv("CENSYS_API_SECRET", "")
GITHUB_TOKEN       = os.getenv("GITHUB_TOKEN", "")
CHAOS_KEY          = os.getenv("CHAOS_KEY", "")

# ── Paths ──────────────────────────────────────────────────────────
WORDLIST_PATH      = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")
OUTPUT_DIR         = "output"

# ── Agent Behaviour ────────────────────────────────────────────────
# HOW TO EDIT: Change these values to tune agent behaviour globally

MAX_VULN_ITERATIONS   = 20    # Max reasoning loop iterations per vuln/endpoint
MAX_RECON_SUBDOMAINS  = 500   # Cap subdomains to prevent huge runs
MAX_ENDPOINTS_TEST    = 200   # Cap endpoints sent to vuln testing
PARALLEL_ENDPOINT_CAP = 8     # Max endpoints tested in parallel
GROQ_CONCURRENCY      = 4     # Max parallel Qwen3 calls (Groq rate limit)
REQUEST_TIMEOUT       = 15    # HTTP request timeout in seconds
REQUEST_DELAY         = 0.3   # Delay between requests (be polite)
FFUF_THREADS          = 40    # ffuf thread count

# ── Severity Colours for Discord ──────────────────────────────────
SEVERITY_COLORS = {
    "Critical": 0xCC0000,
    "High":     0xFF4400,
    "Medium":   0xFF8800,
    "Low":      0xFFCC00,
    "Info":     0x0088FF,
}

def validate_config():
    """Call on startup to warn about missing keys."""
    missing = []
    if not DEEPSEEK_API_KEY:  missing.append("DEEPSEEK_API_KEY")
    if not GROQ_API_KEY:      missing.append("GROQ_API_KEY")
    if not GEMINI_API_KEY:    missing.append("GEMINI_API_KEY")
    if missing:
        print(f"⚠  Missing API keys in .env: {', '.join(missing)}")
        print("   Some agents will fall back to available models.")
