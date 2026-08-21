#!/usr/bin/env bash
# Uninstalls the Yemanode CLI on Linux.

echo "[*] Uninstalling Yemanode v2..."

UNINSTALLED=0

if command -v pipx >/dev/null 2>&1; then
    if pipx list | grep -i yemanode >/dev/null 2>&1; then
        echo "[*] Removing Yemanode via pipx..."
        pipx uninstall yemanode
        UNINSTALLED=1
    fi
fi

if command -v pip3 >/dev/null 2>&1; then
    echo "[*] Attempting pip3 uninstall..."
    pip3 uninstall -y yemanode >/dev/null 2>&1 && UNINSTALLED=1 || true
elif command -v pip >/dev/null 2>&1; then
    echo "[*] Attempting pip uninstall..."
    pip uninstall -y yemanode >/dev/null 2>&1 && UNINSTALLED=1 || true
fi

echo ""
echo "[+] Yemanode CLI successfully uninstalled."
