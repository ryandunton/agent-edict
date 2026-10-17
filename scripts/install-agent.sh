#!/usr/bin/env bash
# Enterprise Installer for AgentEdict on Linux (systemd) and macOS (launchd)
set +x
set -euo pipefail
umask 077

# Every installed service executable component must be controlled by root.
# Do not change ownership of a user-managed Homebrew prefix to make this pass.
assert_trusted_executable_path() {
  local current="$1" metadata owner mode acl_listing
  [[ "$current" == /* && "$current" != *'/../'* && "$current" != *'/./'* ]] || {
    echo 'Service executable path must be absolute and normalized.' >&2; return 1;
  }
  while :; do
    if [[ -L "$current" ]]; then
      echo "Unsafe service executable path (symlink): $current" >&2; return 1
    fi
    if [[ -e "$current" ]]; then
      if [[ "$OS" == darwin ]]; then
        metadata=$(stat -f '%u %Lp' "$current") || return 1
        # macOS ACL grants can bypass mode bits. Reject ACL-bearing components
        # conservatively instead of attempting to interpret localized ACE text.
        acl_listing=$(LC_ALL=C ls -lde "$current") || return 1
        if [[ "$acl_listing" == *$'\n'* ]]; then
          echo "Unsafe service executable path (ACL requires administrator review): $current" >&2; return 1
        fi
      else
        metadata=$(stat -c '%u %a' "$current") || return 1
      fi
      read -r owner mode <<< "$metadata"
      if [[ ! "$owner" =~ ^[0-9]+$ || ! "$mode" =~ ^[0-7]{3,4}$ ]] ||
         [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
        echo "Unsafe service executable path: $current must be root-owned and not writable by group or other users." >&2
        echo 'Provision a trusted system installation path before retrying; do not change ownership of a user-managed Homebrew tree.' >&2
        return 1
      fi
    fi
    [[ "$current" != / ]] || break
    current="${current%/*}"
    [[ -n "$current" ]] || current=/
  done
}

# Reads <bundle-url> [--deploy-token-file PATH] [--sync-interval-minutes N].
# The interval range matches the Windows installer's -SyncIntervalMinutes.
parse_install_args() {
  BUNDLE_URL="${1:-}"
  TOKEN_SOURCE=""
  SYNC_INTERVAL_MINUTES=15
  [[ $# -gt 0 ]] && shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --deploy-token-file)
        [[ -n "${2:-}" ]] || { echo 'Missing token-file path.' >&2; return 1; }
        TOKEN_SOURCE="$2"
        shift 2 ;;
      --sync-interval-minutes)
        [[ "${2:-}" =~ ^[1-9][0-9]{0,3}$ && "${2:-}" -le 1440 ]] || {
          echo 'Sync interval must be a whole number of minutes from 1 to 1440.' >&2; return 1; }
        SYNC_INTERVAL_MINUTES="$2"
        shift 2 ;;
      --*)
        echo 'Unknown option. Usage: <HTTPS_BUNDLE_URL> [--deploy-token-file PATH] [--sync-interval-minutes N]' >&2
        return 1 ;;
      *)
        echo 'Raw deploy-token arguments are not supported; use --deploy-token-file PATH.' >&2
        return 1 ;;
    esac
  done
}

main() {
parse_install_args "$@" || return 1
DEPLOY_TOKEN=""

if [[ -z "$BUNDLE_URL" || "$BUNDLE_URL" != https://* || "$BUNDLE_URL" == *[[:space:]]* || "$BUNDLE_URL" == *'"'* || "$BUNDLE_URL" == *'\'* ]]; then
  echo "Usage: sudo $0 <HTTPS_BUNDLE_URL> [--deploy-token-file PATH] [--sync-interval-minutes N]" >&2
  exit 1
fi
URL_AUTHORITY="${BUNDLE_URL#https://}"
URL_AUTHORITY="${URL_AUTHORITY%%/*}"
[[ "$URL_AUTHORITY" != *@* ]] || { echo 'Embedded URL credentials are not permitted.' >&2; exit 1; }
if [[ -n "$TOKEN_SOURCE" ]]; then
  [[ -f "$TOKEN_SOURCE" && ! -L "$TOKEN_SOURCE" ]] || { echo 'Token source must be a regular file, not a symlink.' >&2; exit 1; }
  DEPLOY_TOKEN=$(cat -- "$TOKEN_SOURCE")
  [[ -n "$DEPLOY_TOKEN" ]] || { echo 'Token file is empty.' >&2; exit 1; }
fi
[[ "$DEPLOY_TOKEN" != *[[:space:]]* ]] || { echo 'Invalid token format.' >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root (use sudo)." >&2
  exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "$OS" == linux || "$OS" == darwin ]] || { echo "Unsupported operating system: $OS" >&2; exit 1; }

# Validate the executable and its complete ancestry before any installation writes.
assert_trusted_executable_path /usr/local/bin/edict

# Store only a credential-file path in service arguments and the readable plist.
# Refuse preexisting links before creating the root-owned private directory.
for path in /etc/agent-edict /etc/agent-edict/credentials; do
  [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] || { echo "Unsafe credential directory: $path" >&2; exit 1; }
  mkdir -p "$path"
  chown root "$path"
  chmod 700 "$path"
done
TOKEN_FILE=""
if [[ -n "$DEPLOY_TOKEN" ]]; then
  TOKEN_FILE=/etc/agent-edict/credentials/deploy-token
  TOKEN_TEMP=$(mktemp /etc/agent-edict/credentials/.deploy-token.XXXXXX)
  trap 'rm -f -- "${TOKEN_TEMP:-}"' EXIT
  printf '%s\n' "$DEPLOY_TOKEN" > "$TOKEN_TEMP"
  chown root "$TOKEN_TEMP"
  chmod 600 "$TOKEN_TEMP"
  mv -f "$TOKEN_TEMP" "$TOKEN_FILE"
fi
unset DEPLOY_TOKEN

# Resolve appropriate binary candidate
CANDIDATES=()
if [[ "${OS}" == "darwin" ]]; then
  if [[ "${ARCH}" == "arm64" ]]; then
    CANDIDATES=("${SCRIPT_DIR}/../bin/edict-darwin-arm64" "${SCRIPT_DIR}/edict-darwin-arm64" "${SCRIPT_DIR}/../bin/edict" "${SCRIPT_DIR}/edict")
  else
    CANDIDATES=("${SCRIPT_DIR}/../bin/edict-darwin-amd64" "${SCRIPT_DIR}/edict-darwin-amd64" "${SCRIPT_DIR}/../bin/edict" "${SCRIPT_DIR}/edict")
  fi
elif [[ "${OS}" == "linux" ]]; then
  CANDIDATES=("${SCRIPT_DIR}/../bin/edict-linux" "${SCRIPT_DIR}/edict-linux" "${SCRIPT_DIR}/../bin/edict" "${SCRIPT_DIR}/edict")
fi

BIN_SOURCE=""
for candidate in "${CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    BIN_SOURCE="${candidate}"
    break
  fi
done

if [[ -z "${BIN_SOURCE}" ]]; then
  echo "[-] Could not find edict binary for ${OS}/${ARCH} in ../bin/ or current directory." >&2
  echo "    Please run 'make build' or place the edict binary here." >&2
  exit 1
fi

echo "[+] Using binary source: ${BIN_SOURCE}"

if [[ "${OS}" == "darwin" ]]; then
  # Strip Apple quarantine attribute from source binary if present
  xattr -c "${BIN_SOURCE}" 2>/dev/null || true
  xattr -d com.apple.quarantine "${BIN_SOURCE}" 2>/dev/null || true
fi

echo "[+] Installing binary to /usr/local/bin/edict..."
assert_trusted_executable_path /usr/local/bin/edict
install -o root -m 0755 "${BIN_SOURCE}" /usr/local/bin/edict
assert_trusted_executable_path /usr/local/bin/edict

if [[ "${OS}" == "darwin" ]]; then
  # Clear quarantine on installed destination and sign ad-hoc for macOS Gatekeeper
  xattr -c /usr/local/bin/edict 2>/dev/null || true
  xattr -d com.apple.quarantine /usr/local/bin/edict 2>/dev/null || true
  codesign --force --deep -s - /usr/local/bin/edict 2>/dev/null || true
fi

# Seed initial policies immediately
echo "[+] Running initial policy sync..."
SYNC_CMD=("/usr/local/bin/edict" "sync-once" "-bundle-url" "${BUNDLE_URL}")
if [[ -n "${TOKEN_FILE}" ]]; then
  SYNC_CMD+=("-deploy-token-file" "${TOKEN_FILE}")
fi
"${SYNC_CMD[@]}"

if [[ "${OS}" == "linux" ]]; then
  echo "[+] Ensuring target directories exist for systemd sandbox..."
  mkdir -p /etc/codex /etc/claude-code /etc/gemini-cli /etc/opencode /etc/cursor /etc/github-copilot /etc/kiro /etc/devin /etc/windsurf /etc/agent-edict /var/lib/agent-edict

  # Claude profiles with claude.sandbox: required need these packages. This
  # installer never installs packages; AgentEdict skips such files until both exist.
  if ! command -v bwrap >/dev/null 2>&1 || ! command -v socat >/dev/null 2>&1; then
    echo "[!] Claude Code's sandbox needs the bubblewrap and socat packages. Claude files that require the sandbox are not installed until both are present." >&2
  fi

  echo "[+] Configuring Linux systemd service..."
  mkdir -p /etc/default
  cat <<EOF > /etc/default/agent-edict
EDICT_BUNDLE_URL="${BUNDLE_URL}"
EDICT_DEPLOY_TOKEN_FILE="${TOKEN_FILE}"
EDICT_SYNC_INTERVAL="${SYNC_INTERVAL_MINUTES}m"
EOF
  chmod 600 /etc/default/agent-edict

  mkdir -p /etc/systemd/system
  cp "${SCRIPT_DIR}/../deploy/systemd/agent-edict.service" /etc/systemd/system/agent-edict.service
  systemctl daemon-reload
  systemctl enable --now agent-edict.service
  echo "[✓] AgentEdict service installed and running via systemd."

elif [[ "${OS}" == "darwin" ]]; then
  echo "[+] Configuring macOS launchd daemon..."
  PLIST_PATH="/Library/LaunchDaemons/io.github.ryandunton.agent-edict.plist"

  TOKEN_ARGS=""
  if [[ -n "${TOKEN_FILE}" ]]; then
    TOKEN_ARGS="        <string>-deploy-token-file</string>
        <string>${TOKEN_FILE}</string>"
  fi

  XML_BUNDLE_URL=$(printf '%s' "$BUNDLE_URL" | sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
  cat <<EOF > "${PLIST_PATH}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.github.ryandunton.agent-edict</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/edict</string>
        <string>daemon</string>
        <string>-bundle-url</string>
        <string>${XML_BUNDLE_URL}</string>
        <string>-interval</string>
        <string>${SYNC_INTERVAL_MINUTES}m</string>
${TOKEN_ARGS}
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/agent-edict.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/agent-edict.err</string>
</dict>
</plist>
EOF

  chmod 644 "${PLIST_PATH}"
  chown root:wheel "${PLIST_PATH}"

  launchctl unload -w "${PLIST_PATH}" 2>/dev/null || true
  launchctl bootout system "${PLIST_PATH}" 2>/dev/null || true
  launchctl bootstrap system "${PLIST_PATH}" 2>/dev/null || launchctl load -w "${PLIST_PATH}"
  echo "[✓] AgentEdict daemon installed and running via launchd."
else
  echo "[-] Unsupported operating system: ${OS}" >&2
  exit 1
fi

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
