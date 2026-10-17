#!/usr/bin/env bash
# Enterprise Uninstaller for AgentEdict on Linux (systemd) and macOS (launchd)
set -euo pipefail

PURGE_DATA=false
if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE_DATA=true
fi

if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root (use sudo)." >&2
  exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

# Ask the installed binary which files it manages before removing it, so this
# list never drifts from the targets the daemon locks.
MANAGED=()
if [[ -x /usr/local/bin/edict ]]; then
  while IFS= read -r line; do MANAGED+=("$line"); done < <(/usr/local/bin/edict targets)
else
  echo "[!] /usr/local/bin/edict not found; managed policy files cannot be listed or unlocked." >&2
fi

echo "[+] Stopping and removing AgentEdict daemon..."

if [[ "${OS}" == "linux" ]]; then
  if systemctl list-unit-files | grep -q "agent-edict.service"; then
    systemctl stop agent-edict.service 2>/dev/null || true
    systemctl disable agent-edict.service 2>/dev/null || true
    rm -f /etc/systemd/system/agent-edict.service
    rm -f /etc/default/agent-edict
    systemctl daemon-reload
    echo "[+] Removed systemd service."
  fi
elif [[ "${OS}" == "darwin" ]]; then
  PLIST_PATH="/Library/LaunchDaemons/io.github.ryandunton.agent-edict.plist"
  if [[ -f "${PLIST_PATH}" ]]; then
    launchctl unload -w "${PLIST_PATH}" 2>/dev/null || true
    rm -f "${PLIST_PATH}"
    echo "[+] Removed launchd plist."
  fi
fi

# Unlock every managed file. Hook registrations run the edict binary, which is
# removed below, so they are always deleted; a fail-closed client would
# otherwise deny every tool call. Policy files are kept unless purging.
for entry in "${MANAGED[@]}"; do
  purpose="${entry%%$'\t'*}"
  f="${entry#*$'\t'}"
  [[ -f "$f" && ! -L "$f" ]] || continue
  if [[ "${OS}" == "linux" ]]; then
    chattr -i "$f" 2>/dev/null || true
  else
    chflags noschg "$f" 2>/dev/null || true
    chflags nouchg "$f" 2>/dev/null || true
  fi
  if [[ "${PURGE_DATA}" == "true" || "$purpose" == "hook-registration" ]]; then
    rm -f -- "$f"
  fi
done

rm -f /usr/local/bin/edict
echo "[+] Removed /usr/local/bin/edict."

if [[ "${PURGE_DATA}" == "true" ]]; then
  echo "[+] Purging cache and vault directories..."
  rm -rf /etc/agent-edict /var/lib/agent-edict
fi

echo "[✓] AgentEdict successfully uninstalled."
