#!/data/data/com.termux/files/usr/bin/bash
# Pro_Hacker2 LITE v1.0
# Educational / legal utilities only.
# Lite edition to demo features of the full Pro_Hacker2 toolkit.

VERSION="1.0.0"

UPDATE_URL="https://raw.githubusercontent.com/xbustcodex/Pro_Hacker2_LITE/main/pro_hacker2_lite.sh"
KOFI_LINK="https://ko-fi.com/kali188"

# ---------- COLORS ----------
c_reset="\e[0m"
c_red="\e[31m"
c_green="\e[32m"
c_yellow="\e[33m"
c_blue="\e[34m"
c_magenta="\e[35m"
c_cyan="\e[36m"
c_gray="\e[90m"

# ==========================================================
#  OWNER / LICENSE CONTROL (hidden owner mode)
# ==========================================================

LITE_NAME="pro_hacker2_lite"
LICENSE_FILE="$HOME/.${LITE_NAME}.license"
OWNER_LICENSE="XBUSTCODEX-ULTRA-9999"

SCRIPT_MODE="lite"

# PIN security / forensics
PIN_FAIL_FILE="$HOME/.pro_hacker2_pin_fails"
MAX_PIN_FAILS=3

# Fail counter (per-system; simple)
init_pin_fail_counter() {
  [[ -f "$PIN_FAIL_FILE" ]] || echo 0 > "$PIN_FAIL_FILE"
}

get_pin_fail_count() {
  init_pin_fail_counter
  awk 'NR==1{print $1}' "$PIN_FAIL_FILE" 2>/dev/null || echo 0
}

set_pin_fail_count() {
  echo "$1" > "$PIN_FAIL_FILE"
  chmod 600 "$PIN_FAIL_FILE" 2>/dev/null
}

record_pin_fail() {
  local count
  count="$(get_pin_fail_count)"
  count=$((count + 1))
  set_pin_fail_count "$count"
}

reset_pin_fail() {
  set_pin_fail_count 0
}

if [[ -f "$LICENSE_FILE" ]]; then
  USER_LICENSE="$(tr -d '\r\n' < "$LICENSE_FILE" 2>/dev/null)"
  if [[ "$USER_LICENSE" == "$OWNER_LICENSE" ]]; then
    SCRIPT_MODE="owner"
  fi
fi

is_owner() {
  [[ "$SCRIPT_MODE" == "owner" ]]
}

# Extra anti-tamper: require tight perms on license
anti_tamper_guard() {
  [[ -f "$LICENSE_FILE" ]] || return 1

  local perms
  perms="$(stat -c '%a' "$LICENSE_FILE" 2>/dev/null || echo '000')"
  if [[ "$perms" != "600" && "$perms" != "400" ]]; then
    echo -e "${c_yellow}[!] License file permissions are too open; Pro core disabled.${c_reset}"
    return 1
  fi

  return 0
}

# Forensic log (owner-only, but created here)
FORENSIC_LOG="$HOME/.pro_hacker2_forensic.log"

log_event() {
  # Only log on owner systems (no point for public users)
  is_owner || return 0
  local msg="$1"
  {
    date +"[%Y-%m-%d %H:%M:%S] PID $$ USER $USER PWD $(pwd)"
    echo "  EVENT: $msg"
    echo
  } >> "$FORENSIC_LOG" 2>/dev/null
  chmod 600 "$FORENSIC_LOG" 2>/dev/null
}

# Hidden owner PIN + Pro core loader
require_owner_and_pin() {
  if ! is_owner; then
    # silently fail – no hint that owner mode exists
    return 1
  fi

  anti_tamper_guard || return 1

  local fails
  fails="$(get_pin_fail_count)"
  if (( fails >= MAX_PIN_FAILS )); then
    echo -e "${c_red}[!] Too many failed PIN attempts. Pro core locked for this session.${c_reset}"
    log_event "PIN LOCKOUT: $fails failed attempts"
    return 1
  fi

  echo
  read -rsp "Owner PIN: " _PH2_PIN
  echo

  if [[ -z "$_PH2_PIN" ]]; then
    echo -e "${c_red}[!] Empty PIN. Aborting.${c_reset}"
    return 1
  fi

  # Build passphrase from license + PIN (not stored on disk)
  PH2_PASSPHRASE="${OWNER_LICENSE}:${_PH2_PIN}"

  return 0
}

owner_notice() {
  : # hidden – no owner banner
}

# ---------- ANDROID / CYBER BANNER ----------
banner() {
  clear
  echo -e "${c_green}"
  echo "   ___            _   _             _                "
  echo "  / _ \ _ __  ___| |_(_) ___ _ __  | |__   ___ _ __  "
  echo " | | | | '_ \/ __| __| |/ _ \ '_ \ | '_ \ / _ \ '_ \ "
  echo " | |_| | | | \__ \ |_| |  __/ | | || | | |  __/ | | |"
  echo "  \___/|_| |_|___/\__|_|\___|_| |_||_| |_|\___|_| |_|"
  echo -e "${c_reset}"
  echo -e "${c_green}         Pro_Hacker2 LITE v${VERSION}${c_reset}"
  echo -e "${c_gray}   Android / Termux utilities – Free Edition${c_reset}"
  echo
  owner_notice
}

pause() {
  echo
  read -rp "Press Enter to continue..." _
}

progress_bar() {
  local msg="$1"
  echo -ne "${c_cyan}${msg} ${c_reset}"
  for _ in {1..15}; do
    echo -ne "."
    sleep 0.05
  done
  echo
}

# ---------- VERSION CHECK / AUTO UPDATE ----------
get_remote_version() {
  if [[ "$UPDATE_URL" == *"YOURUSER"* ]]; then
    echo "unknown"
    return
  fi
  curl -fsSL "$UPDATE_URL" 2>/dev/null \
    | grep -m1 '^VERSION="' \
    | sed -e 's/^[^"]*"\([^"]*\)".*/\1/'
}

check_for_updates() {
  banner
  echo -e "${c_blue}[+] Checking for updates...${c_reset}"
  local remote
  remote="$(get_remote_version)"

  if [[ -z "$remote" || "$remote" == "unknown" ]]; then
    echo -e "${c_yellow}[!] Could not check remote version. Make sure UPDATE_URL is set correctly.${c_reset}"
    pause
    return
  fi

  echo -e "Local version : ${c_green}${VERSION}${c_reset}"
  echo -e "Remote version: ${c_green}${remote}${c_reset}"
  echo

  if [[ "$remote" == "$VERSION" ]]; then
    echo -e "${c_green}You already have the latest version.${c_reset}"
    pause
    return
  fi

  read -rp "Update to v${remote}? [y/N] " ans
  case "$ans" in
    y|Y) auto_update "$remote" ;;
    *)   echo "Update cancelled."; pause ;;
  esac
}

auto_update() {
  local new_ver="$1"
  if [[ "$UPDATE_URL" == *"YOURUSER"* ]]; then
    echo -e "${c_red}[!] UPDATE_URL is still a placeholder. Edit the script and set a real URL.${c_reset}"
    pause
    return
  fi

  progress_bar "Downloading v${new_ver}"
  tmp_file="$(mktemp)"
  if ! curl -fsSL "$UPDATE_URL" -o "$tmp_file"; then
    echo -e "${c_red}[!] Download failed – update aborted.${c_reset}"
    rm -f "$tmp_file"
    pause
    return
  fi

  chmod +x "$tmp_file"
  mv "$tmp_file" "$0"
  echo -e "${c_green}[+] Updated successfully to v${new_ver}.${c_reset}"
  echo "Restarting..."
  sleep 1
  exec "$0"
}

# ==========================================================
#  HIDDEN PRO CORE LOADER (encrypted external file)
# ==========================================================

PH2_PRO_ENC="$HOME/.pro_hacker2_pro_core.enc"

run_hidden_pro_core() {
  require_owner_and_pin || {
    echo "Invalid option."
    return 1
  }

  if ! command -v openssl >/dev/null 2>&1; then
    echo -e "${c_yellow}[!] openssl not installed. Run: pkg install openssl-tool${c_reset}"
    return 1
  fi

  if [[ ! -f "$PH2_PRO_ENC" ]]; then
    echo -e "${c_yellow}[!] Encrypted Pro core not found (${PH2_PRO_ENC}).${c_reset}"
    return 1
  fi

  tmp_script="$(mktemp)"

  if ! printf '%s\n' "$PH2_PASSPHRASE" \
      | openssl enc -aes-256-cbc -pbkdf2 -salt -d \
        -in "$PH2_PRO_ENC" -out "$tmp_script" -pass stdin 2>/dev/null; then
    echo -e "${c_red}[!] Auth failed or corrupted Pro core.${c_reset}"
    rm -f "$tmp_script"
    record_pin_fail
    log_event "PIN FAIL: decrypt error"
    return 1
  fi

  # PIN ok; reset fail counter
  reset_pin_fail
  log_event "PIN OK: Pro core loaded"

  chmod +x "$tmp_script"
  "$tmp_script" "$@"
  rm -f "$tmp_script"
}

# ---------- LITE MODULES ----------
device_info() {
  banner
  echo -e "${c_cyan}[ Device Info Scanner – Lite ]${c_reset}"
  echo
  echo -e "${c_green}Device:${c_reset} $(getprop ro.product.model 2>/dev/null || echo "Unknown")"
  echo -e "${c_green}Brand :${c_reset} $(getprop ro.product.brand 2>/dev/null || echo "Unknown")"
  echo -e "${c_green}Android:${c_reset} $(getprop ro.build.version.release 2>/dev/null || echo "Unknown")"
  echo -e "${c_green}Arch   :${c_reset} $(uname -m)"
  echo -e "${c_green}Kernel :${c_reset} $(uname -r)"
  echo
  echo -e "${c_green}Battery:${c_reset} $(dumpsys battery 2>/dev/null | grep -E 'level' | awk '{print $2"%"}' || echo "N/A")"
  echo -e "${c_green}IP addr:${c_reset} $(ip addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | head -n1 || echo "N/A")"
  echo
  if command -v su >/dev/null 2>&1; then
    echo -e "${c_yellow}Root binary detected (su present).${c_reset}"
  else
    echo -e "${c_gray}su binary not found – likely non-rooted.${c_reset}"
  fi
  pause
}

osint_lite() {
  while true; do
    banner
    echo -e "${c_cyan}[ OSINT Lite – Safe Utilities ]${c_reset}"
    echo
    echo " 1) WHOIS domain lookup"
    echo " 2) DNS A record lookup"
    echo " 3) IP Geolocation (ip-api.com)"
    echo " 0) Back to main menu"
    echo
    read -rp "Select an option: " opt
    case "$opt" in
      1)
        read -rp "Enter domain (example.com): " domain
        [[ -z "$domain" ]] && continue
        progress_bar "Running whois"
        if command -v whois >/dev/null 2>&1; then
          whois "$domain" | head -n 40
        else
          echo -e "${c_yellow}[!] whois not installed. Run: pkg install whois${c_reset}"
        fi
        pause ;;
      2)
        read -rp "Enter domain: " domain
        [[ -z "$domain" ]] && continue
        progress_bar "Resolving domain"
        if command -v nslookup >/dev/null 2>&1; then
          nslookup "$domain" | head -n 20
        elif command -v host >/dev/null 2>&1; then
          host "$domain"
        else
          echo -e "${c_yellow}[!] nslookup/host not installed. Try: pkg install dnsutils${c_reset}"
        fi
        pause ;;
      3)
        read -rp "Enter IP address: " ip
        [[ -z "$ip" ]] && continue
        progress_bar "Querying ip-api.com"
        curl -fsSL "http://ip-api.com/line/$ip" 2>/dev/null || \
          echo -e "${c_yellow}[!] Failed to query IP info.${c_reset}"
        pause ;;
      0) break ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

port_scan_lite() {
  banner
  echo -e "${c_cyan}[ Port Scanner LITE – Top 20 Ports ]${c_reset}"
  echo
  read -rp "Target IP / hostname: " target
  [[ -z "$target" ]] && return

  local ports=(21 22 23 25 53 80 110 111 135 139 143 443 445 587 993 995 3306 3389 5900 8080)
  echo
  echo -e "${c_green}Scanning ${#ports[@]} common ports on ${target}...${c_reset}"
  echo

  for p in "${ports[@]}"; do
    timeout 1 bash -c ">/dev/tcp/$target/$p" 2>/dev/null \
      && echo -e "[${c_green}OPEN${c_reset}] Port $p" \
      || echo -e "[${c_gray}CLOSED${c_reset}] Port $p"
  done

  echo
  echo -e "${c_gray}Lite version: for full Nmap profiles, stealth scans & reports, upgrade to Pro_Hacker2 FULL.${c_reset}"
  pause
}

crypto_tools() {
  while true; do
    banner
    echo -e "${c_cyan}[ Crypto / Encoding Tools – Lite ]${c_reset}"
    echo
    echo " 1) Base64 encode"
    echo " 2) Base64 decode"
    echo " 3) MD5 hash"
    echo " 4) SHA1 hash"
    echo " 5) ROT13"
    echo " 0) Back to main menu"
    echo
    read -rp "Select an option: " opt
    case "$opt" in
      1) read -rp "Text to encode: " txt; echo "$txt" | base64; pause ;;
      2) read -rp "Base64 string: " txt; echo "$txt" | base64 -d 2>/dev/null || echo "Invalid Base64."; pause ;;
      3) read -rp "Text to hash (MD5): " txt; echo -n "$txt" | md5sum | awk '{print $1}'; pause ;;
      4) read -rp "Text to hash (SHA1): " txt; echo -n "$txt" | sha1sum | awk '{print $1}'; pause ;;
      5) read -rp "Text for ROT13: " txt; echo "$txt" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; pause ;;
      0) break ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

about_screen() {
  banner
  echo -e "${c_cyan}[ About – Pro_Hacker2 LITE ]${c_reset}"
  echo
  echo "This is the FREE Lite edition of Pro_Hacker2."
  echo "- Safe, legal utilities only"
  echo "- Built for Android + Termux"
  echo "- Designed to demo the full toolkit's UX and workflow"
  echo
  echo -e "Support development & unlock the full version:"
  echo -e "${c_green}${KOFI_LINK}${c_reset}"
  echo
  pause
}

# ---------- MAIN MENU ----------
main_menu() {
  while true; do
    banner
    echo -e "${c_cyan}Main Menu${c_reset}"
    echo
    echo " 1) Device Info Scanner (Lite)"
    echo " 2) OSINT Tools (Lite)"
    echo " 3) Port Scanner (Top 20 ports)"
    echo " 4) Crypto / Encoding Tools"
    echo " 5) Check for Updates"
    echo " 6) About / Support (Ko-fi)"
    echo
    echo " 0) Exit"
    echo
    read -rp "Select an option: " opt

    # HIDDEN PRO TRIGGER: 99
    if [[ "$opt" == "99" ]]; then
      run_hidden_pro_core
      sleep 1
      continue
    fi

    case "$opt" in
      1) device_info ;;
      2) osint_lite ;;
      3) port_scan_lite ;;
      4) crypto_tools ;;
      5) check_for_updates ;;
      6) about_screen ;;
      0)
        echo "Bye."
        exit 0 ;;
      *)
        echo "Invalid option."
        sleep 1 ;;
    esac
  done
}

main_menu