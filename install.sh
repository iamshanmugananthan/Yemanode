#!/usr/bin/env bash
# Installs the Yemanode CLI on Linux.
set -e

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Cleaning up any legacy CodeSentinel installations..."
if command -v pipx >/dev/null 2>&1; then
    pipx uninstall codesentinel >/dev/null 2>&1 || true
fi
if command -v pip3 >/dev/null 2>&1; then
    pip3 uninstall -y codesentinel >/dev/null 2>&1 || true
fi
rm -f "$HOME/.local/bin/codesentinel" "$HOME/.local/bin/codeessential"

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
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        echo "[*] Added ~/.local/bin to PATH in $SHELL_RC — restart your terminal or run: source $SHELL_RC"
    fi
else
    echo "Error: neither pipx nor pip3 found. Install Python 3 + pip first." >&2
    exit 1
fi

echo ""
echo "[+] Installed! Run it with:  yemanode"
echo ""
echo "    Interactive menu:          yemanode"
echo "    Source folder:             yemanode scan-repo /path/to/project"
echo "    API URL:                   yemanode scan-api https://...."
echo "    Android APK:               yemanode scan-apk ./app.apk"
echo "    Desktop binary:            yemanode scan-binary /path/to/binary"
