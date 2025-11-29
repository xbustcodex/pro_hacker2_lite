#!/data/data/com.termux/files/usr/bin/bash
# Simple installer for Pro_Hacker2 LITE + (optional) encrypted Pro core

set -e

TARGET_BIN="$PREFIX/bin/pro_hacker2"
SCRIPT_NAME="pro_hacker2_lite.sh"

echo "[*] Installing Pro_Hacker2 LITE..."

if [[ ! -f "$SCRIPT_NAME" ]]; then
  echo "[!] $SCRIPT_NAME not found in current directory."
  echo "    Run this installer from the folder containing $SCRIPT_NAME."
  exit 1
fi

cp "$SCRIPT_NAME" "$TARGET_BIN"
chmod +x "$TARGET_BIN"

echo "[+] Installed LITE to: $TARGET_BIN"

# Optional: install encrypted Pro core if present
if [[ -f "$HOME/.pro_hacker2_pro_core.enc" ]]; then
  echo "[+] Found existing encrypted Pro core at ~/.pro_hacker2_pro_core.enc"
else
  echo "[*] No encrypted Pro core detected yet."
  echo "    You can place it later at: ~/.pro_hacker2_pro_core.enc"
fi

echo
echo "Run with: pro_hacker2"
echo "LITE menu is public; owner-only Pro core is hidden behind"
echo "license + PIN + encrypted module."
echo
