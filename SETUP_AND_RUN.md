# AI Bug Hunter — Complete Setup & Run Guide

---

## Prerequisites

You need:
- **Python 3.11+**
- **Go 1.21+** (for recon tools)
- **3 free API keys** (setup takes ~5 minutes)

---

## Step 1 — Get Your Free API Keys

### DeepSeek API (Orchestrator brain)
1. Go to https://platform.deepseek.com
2. Register → Dashboard → API Keys → Create key
3. Copy the `sk-...` key

### Groq API (Vuln agent brain — Qwen3-235B)
1. Go to https://console.groq.com
2. Sign up → API Keys → Create API Key
3. Copy the `gsk_...` key

### Google AI Studio (Gemini — JS/HTTP analysis)
1. Go to https://aistudio.google.com
2. Sign in with Google → Get API Key → Create API key
3. Copy the `AIza...` key

### Discord Webhook (optional but recommended)
1. Open your Discord server
2. Server Settings → Integrations → Webhooks → New Webhook
3. Copy the webhook URL

---

## Step 2 — Install Go (if not installed)

### macOS
```bash
brew install go
```

### Ubuntu/Debian
```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Windows
Download installer from https://golang.org/dl/

---

## Step 3 — Clone and Setup

```bash
# Clone or create the project directory
cd ai-bughunter

# Make setup script executable and run it
chmod +x setup.sh
./setup.sh
```

This automatically:
- Installs all Python packages
- Installs subfinder, httpx, katana, gau, waybackurls, ffuf
- Creates the .env file
- Downloads the directory wordlist

---

## Step 4 — Configure API Keys

```bash
# Open the .env file
nano .env   # or: code .env / vim .env
```

Fill in your keys:
```
DEEPSEEK_API_KEY=sk-your-key-here
GROQ_API_KEY=gsk_your-key-here
GEMINI_API_KEY=AIza-your-key-here
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

Save and close.

---

## Step 5 — Verify Tools Are Installed

```bash
subfinder -version
httpx -version
katana -version
gau --version
ffuf -V
```

If any command is not found:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
# Add this line to your ~/.bashrc or ~/.zshrc to make it permanent
```

---

## Step 6 — Run Your First Scan

```bash
# Basic scan
python main.py --target example.com

# With explicit scope
python main.py --target example.com --scope "*.example.com" "api.example.com"

# Only specific vuln types (faster)
python main.py --target example.com --vulns xss sqli cors ssrf

# Skip verification (faster, more false positives)
python main.py --target example.com --no-verify

# Limit endpoints (for quick test)
python main.py --target example.com --max-endpoints 20
```

---

## What Happens When You Run It

```
Phase 1 — Recon (10-20 min depending on target size)
  • subfinder finds subdomains
  • httpx checks which are live
  • katana + gau + waybackurls collect all URLs
  • ffuf fuzzes directories on top hosts
  • JS files are fetched and analyzed by Gemini
  • All endpoints are parsed and scope-filtered

Phase 2 — Vulnerability Testing (main phase, can take 1-3 hours)
  • All endpoints tested in parallel
  • Each endpoint: all relevant vuln agents run simultaneously
  • Each agent runs its reasoning loop (up to 20 iterations)
  • Agent thinks → sends request → analyzes response → adapts → repeats

Phase 3 — Verification (5-10 min)
  • Qwen3-235B reviews each finding
  • Filters out false positives
  • Assigns accurate severity and CVSS scores

Phase 4 — Reporting (1 min)
  • Markdown report saved to output/
  • JSON findings saved to output/
  • Each finding sent to Discord as rich embed
```

---

## Output Files

After a run you'll find:
```
output/
├── 2025-01-15_10-30_example.com_report.md    ← Full report with PoCs
├── 2025-01-15_10-30_example.com_findings.json ← JSON for further use
└── run_20250115_103000.log                    ← Debug log (full trace)
```

---

## Test It Works (Safe Target)

Test on intentionally vulnerable apps before running on real targets:

```bash
# DVWA (run locally with Docker)
docker run -d -p 80:80 vulnerables/web-dvwa
python main.py --target localhost --scope "localhost"

# Juice Shop (OWASP)
docker run -d -p 3000:3000 bkimminich/juice-shop
python main.py --target localhost:3000 --scope "localhost:3000"

# HackTheBox / TryHackMe machines (use your VPN)
python main.py --target 10.10.10.X --scope "10.10.10.X"
```

---

## Troubleshooting

### "API key not set" warning
→ Check your .env file. Make sure there are no spaces around the = sign.
→ `DEEPSEEK_API_KEY=sk-abc123` ✅  vs  `DEEPSEEK_API_KEY = sk-abc123` ❌

### "subfinder not found"
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Groq rate limit errors
→ Reduce `GROQ_CONCURRENCY` in `config.py` to 2 or 3
→ Increase `REQUEST_DELAY` to 0.5

### Too many endpoints, scan taking forever
```bash
python main.py --target example.com --max-endpoints 50 --vulns xss sqli ssrf
```

### No findings but you know there are bugs
→ Increase `MAX_VULN_ITERATIONS` in `config.py` from 20 to 30
→ The agent may need more iterations to reason through complex bypasses

---

## Important: Only Test What You're Authorized To Test

Only run this against:
- Systems you own
- Systems with explicit written permission (bug bounty programs)
- Intentionally vulnerable practice targets

Bug bounty programs: HackerOne, Bugcrowd, Intigriti, YesWeHack
