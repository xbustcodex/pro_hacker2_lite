#!/data/data/com.termux/files/usr/bin/bash
# Simple installer for Pro_Hacker2 LITE

INSTALL_DIR="$HOME/.pro_hacker2_lite"
SCRIPT_NAME="pro_hacker2_lite.sh"

# CHANGE THIS to the RAW URL of your script:
DOWNLOAD_URL="https://raw.githubusercontent.com/YOURUSER/Pro_Hacker2_LITE/main/pro_hacker2_lite.sh"

set -e

echo "[+] Installing Pro_Hacker2 LITE..."

if [[ "$DOWNLOAD_URL" == *"YOURUSER"* ]]; then
  echo "[!] You must edit this installer and set a real DOWNLOAD_URL."
  exit 1
fi

mkdir -p "$INSTALL_DIR"

curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

# Add alias to bashrc / zshrc if present
ALIAS_CMD="alias prohacker2-lite='$INSTALL_DIR/$SCRIPT_NAME'"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [[ -f "$rc" ]]; then
    if ! grep -q "prohacker2-lite" "$rc"; then
      echo "$ALIAS_CMD" >> "$rc"
      echo "[+] Added alias to $rc"
    fi
  fi
done

echo
echo "[+] Install complete."
echo "   Run: source ~/.bashrc   or   source ~/.zshrc"
echo "   Then start with: prohacker2-lite"
