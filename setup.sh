#!/bin/bash
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   AI Bug Hunter — Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Python deps ────────────────────────────────
# ── Python deps ────────────────────────────────
echo "[1/4] Setting up Python virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  ✓  Virtual environment created"
fi

source venv/bin/activate

pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "  ✓  Python dependencies installed"

# ── Go tools ───────────────────────────────────
echo "[2/4] Installing Go recon tools..."

if ! command -v go &> /dev/null; then
    echo "  ⚠  Go not found. Install from https://golang.org/dl/"
    echo "     Then re-run setup.sh"
    exit 1
fi

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Make sure Go bin is in PATH
GO_BIN=$(go env GOPATH)/bin

if [[ ":$PATH:" != *":$GO_BIN:"* ]]; then
    echo "export PATH=\$PATH:$GO_BIN" >> ~/.zshrc
    export PATH=$PATH:$GO_BIN
    echo "  ✓  Go PATH added to ~/.zshrc"
fi


# ── .env file ──────────────────────────────────
echo "[3/4] Setting up .env..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "  ✓  .env created — EDIT IT NOW with your API keys"
else
    echo "  ✓  .env already exists"
fi

# ── Wordlist ───────────────────────────────────
echo "[4/4] Downloading wordlist for directory fuzzing..."
mkdir -p wordlists
if [ ! -f wordlists/common.txt ]; then
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -o wordlists/common.txt
    echo "  ✓  wordlists/common.txt downloaded"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   Setup complete!"
echo ""
echo "   Next steps:"
echo "   1. Edit .env and add your API keys"
echo "   2. Run: python main.py --target example.com"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
