#!/usr/bin/env bash
# Installs the Yemanode CLI on Linux.
set -e

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing Yemanode v2 from $SRC_DIR ..."

if command -v pipx >/dev/null 2>&1; then
    echo "[*] pipx found — installing with pipx (recommended, isolated environment)"
    pipx install "$SRC_DIR" --force
elif command -v pip3 >/dev/null 2>&1; then
    echo "[*] Installing with pip3 --user"
    pip3 install --user "$SRC_DIR"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        SHELL_RC="$HOME/.bashrc"
        [[ "$SHELL" == *zsh* ]] && SHELL_RC="$HOME/.zshrc"
        if ! grep -q '\.local/bin' "$SHELL_RC" 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            echo "[*] Added ~/.local/bin to PATH in $SHELL_RC — restart your terminal or run: source $SHELL_RC"
        fi
    fi
else
    echo "Error: neither pipx nor pip3 found. Install Python 3 + pip first." >&2
    exit 1
fi

echo ""
echo "[+] Installed! Run it with:  yemanode"
echo ""
echo "    Interactive menu:          yemanode"
echo "    Hacker Pentest Engine:     yemanode hacker-test . -H 10 -f all"
echo "    Source folder:             yemanode scan-repo /path/to/project -f all"
echo "    API URL / OpenAPI Spec:    yemanode scan-api https://.... -f all"
echo "    JWT Token:                 yemanode scan-jwt 'eyJhbGciOi...'"
echo "    Android APK:               yemanode scan-apk ./app.apk -f all"
echo "    Desktop binary:            yemanode scan-binary /path/to/binary -f all"
echo "    Load & Rate Limit Test:    yemanode load-test https://api.example.com -n 100 -c 10"
