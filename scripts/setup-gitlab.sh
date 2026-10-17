#!/usr/bin/env bash
# Usage: GITLAB_TOKEN=<management token> ./scripts/setup-gitlab.sh [TOKEN] [NAMESPACE]
# Prefer the environment or an interactive hidden prompt over a token argument.
set +x
set -euo pipefail

fail() { printf '[-] %s\n' "$*" >&2; return 1; }

# Response bodies can contain credentials. Keep them in the private temporary
# directory and never include them in diagnostics, arguments, or tracing.
gitlab_request() {
  local method="$1" path="$2" payload="${3:-}" status
  local args=(--disable --silent --show-error --connect-timeout 15 --max-time 60
    --request "$method" --header "@${AUTH_HEADERS}" --output "${API_RESPONSE}"
    --write-out '%{http_code}')
  if [[ -n "$payload" ]]; then args+=(--data-binary "@${payload}"); fi
  status=$(curl "${args[@]}" "https://gitlab.com/api/v4/${path}") || {
    fail "GitLab request failed (${method}); no response credentials were logged."; return 1;
  }
  [[ "$status" =~ ^[0-9]{3}$ ]] || { fail 'Invalid GitLab HTTP status.'; return 1; }
  API_STATUS="$status"
}

expect_status() {
  [[ "$API_STATUS" == "$1" ]] || { fail "GitLab request failed (HTTP ${API_STATUS}; expected $1)."; return 1; }
}

json_field() {
  python3 - "$API_RESPONSE" "$1" <<'PY'
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
    value = obj[sys.argv[2]]
    if sys.argv[2] == 'id':
        if type(value) is not int or value <= 0: raise ValueError()
    elif not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError()
    print(value)
except (KeyError, TypeError, ValueError, OSError):
    sys.exit('Invalid GitLab JSON response field: ' + sys.argv[2])
PY
}

save_deploy_token() {
  python3 - "$API_RESPONSE" "$1" <<'PY'
import json, os, sys
try:
    data = json.load(open(sys.argv[1]))
    token = data['token']
    if (not isinstance(token, str) or not token.strip() or
        any(c.isspace() for c in token) or
        data.get('scopes') != ['read_package_registry'] or
        data.get('revoked', False) or data.get('expired', False)):
        raise ValueError()
    # Refuse to overwrite an existing credential or follow a symlink.
    fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output: output.write(token + '\n')
except (KeyError, TypeError, ValueError, OSError):
    sys.exit('Deploy-token creation failed validation; no management-token fallback is permitted.')
PY
}

embed_public_key() {
  python3 - "$1" "$2" <<'PY'
import pathlib, re, sys
source = pathlib.Path(sys.argv[1])
public = pathlib.Path(sys.argv[2]).read_text().strip()
if '`' in public or not public.startswith('-----BEGIN PUBLIC KEY-----') or not public.endswith('-----END PUBLIC KEY-----'):
    sys.exit('Invalid public key PEM.')
content, count = re.subn(r'const defaultPublicKeyPEM = `[^`]*`', lambda _: 'const defaultPublicKeyPEM = `' + public + '`', source.read_text())
if count != 1: sys.exit('Expected exactly one defaultPublicKeyPEM declaration; source unchanged.')
source.write_text(content)
PY
}

main() {
  # Prevent inherited shell tracing from printing credentials.
  set +x
  umask 077
  local token="${1:-${GITLAB_TOKEN:-}}" namespace="${2:-${GITLAB_NAMESPACE:-}}"
  local project_name='agent-edict' root_dir project_id actual_user encoded_path namespace_id
  if [[ -z "$token" && -t 0 ]]; then read -r -s -p 'GitLab management token: ' token; printf '\n'; fi
  [[ -n "$token" ]] || { fail 'Set GITLAB_TOKEN or supply a token interactively.'; return 1; }
  [[ "$token" != *$'\n'* && "$token" != *$'\r'* ]] || { fail 'Invalid token format.'; return 1; }
  unset GITLAB_TOKEN
  root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cd "$root_dir"
  PRIVATE_TEMP=$(mktemp -d)
  trap 'rm -rf -- "$PRIVATE_TEMP"' EXIT
  AUTH_HEADERS="${PRIVATE_TEMP}/headers"
  API_RESPONSE="${PRIVATE_TEMP}/response.json"
  printf 'PRIVATE-TOKEN: %s\nContent-Type: application/json\n' "$token" > "$AUTH_HEADERS"
  printf '%s' "$token" > "${PRIVATE_TEMP}/management-token"
  unset token

  printf '[1/7] Verifying GitLab credentials...\n'
  gitlab_request GET user; expect_status 200
  actual_user=$(json_field username)
  [[ -n "$namespace" ]] || namespace="$actual_user"
  printf '[+] Authenticated; target namespace: %s\n' "$namespace"

  printf '[2/7] Preparing Ed25519 signing keys...\n'
  mkdir -p keys
  [[ ! -L keys && -d keys ]] || { fail 'keys must be a real directory.'; return 1; }
  chmod 700 keys
  local private_key='keys/agent-edict-signing-key.pem' public_key='keys/agent-edict-public-key.pem'
  if [[ ! -f "$private_key" ]]; then openssl genpkey -algorithm ED25519 -out "$private_key"; fi
  openssl pkey -in "$private_key" -pubout -out "$public_key"
  chmod 600 "$private_key"
  chmod 644 "$public_key"

  printf '[3/7] Embedding public verification key...\n'
  embed_public_key cmd/edict/main.go "$public_key"

  printf '[4/7] Ensuring the GitLab project exists...\n'
  encoded_path=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$namespace/$project_name")
  gitlab_request GET "projects/${encoded_path}"
  if [[ "$API_STATUS" == 404 ]]; then
    # Resolve the requested namespace explicitly; never silently create in the caller's namespace.
    encoded_path=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$namespace")
    gitlab_request GET "namespaces/${encoded_path}"; expect_status 200
    namespace_id=$(json_field id)
    python3 - "$namespace_id" "$project_name" > "${PRIVATE_TEMP}/project.json" <<'PY'
import json, sys
json.dump(dict(name=sys.argv[2], path=sys.argv[2], namespace_id=int(sys.argv[1]), visibility='private', initialize_with_readme=False), sys.stdout)
PY
    gitlab_request POST projects "${PRIVATE_TEMP}/project.json"; expect_status 201
  else
    expect_status 200
  fi
  project_id=$(json_field id)

  printf '[5/7] Committing and pushing the codebase...\n'
  git init -b main
  git config user.name >/dev/null 2>&1 || git config user.name "$actual_user"
  git config user.email >/dev/null 2>&1 || git config user.email "${actual_user}@users.noreply.gitlab.com"
  git add -A
  git commit -m 'Initialize AgentEdict Universal Policy Engine' --allow-empty
  local remote="https://gitlab.com/${namespace}/${project_name}.git"
  if git remote get-url origin >/dev/null 2>&1; then git remote set-url origin "$remote"; else git remote add origin "$remote"; fi
  # Git receives a helper path, never a credential in its URL or command line.
  cat > "${PRIVATE_TEMP}/askpass" <<'ASKPASS'
#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' oauth2 ;;
  *Password*) cat "$EDICT_SETUP_TOKEN_FILE" ;;
  *) exit 1 ;;
esac
ASKPASS
  chmod 700 "${PRIVATE_TEMP}/askpass"
  GIT_ASKPASS="${PRIVATE_TEMP}/askpass" GIT_TERMINAL_PROMPT=0 EDICT_SETUP_TOKEN_FILE="${PRIVATE_TEMP}/management-token" \
    git -c credential.helper= push -u origin HEAD:main

  printf '[6/7] Configuring the protected CI signing variable...\n'
  python3 - "$private_key" > "${PRIVATE_TEMP}/variable.json" <<'PY'
import base64, json, pathlib, sys
json.dump(dict(key='EDICT_SIGNING_PRIVATE_KEY', value=base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode(), protected=True, masked=False, raw=True), sys.stdout)
PY
  gitlab_request GET "projects/${project_id}/variables/EDICT_SIGNING_PRIVATE_KEY"
  if [[ "$API_STATUS" == 404 ]]; then
    gitlab_request POST "projects/${project_id}/variables" "${PRIVATE_TEMP}/variable.json"; expect_status 201
  else
    expect_status 200
    gitlab_request PUT "projects/${project_id}/variables/EDICT_SIGNING_PRIVATE_KEY" "${PRIVATE_TEMP}/variable.json"; expect_status 200
  fi

  printf '[7/7] Creating a scoped endpoint credential...\n'
  local endpoint_file="${root_dir}/keys/agent-edict-deploy-token-$(date +%Y%m%d%H%M%S)"
  printf '%s' '{"name":"agent-edict-endpoint-token","scopes":["read_package_registry"]}' > "${PRIVATE_TEMP}/deploy.json"
  gitlab_request POST "projects/${project_id}/deploy_tokens" "${PRIVATE_TEMP}/deploy.json"; expect_status 201
  save_deploy_token "$endpoint_file"
  gitlab_request POST "projects/${project_id}/pipeline?ref=main"; expect_status 201
  local bundle_url="https://gitlab.com/api/v4/projects/${project_id}/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz"
  printf '\nSetup complete. Endpoint token saved to protected file: %s\n' "$endpoint_file"
  printf 'Review policy-map.yaml before deployment: the pipeline signs whatever it contains.\n'
  printf 'Securely copy the endpoint token file to each workstation; do not paste its contents into commands.\n'
  printf 'Windows: .\\scripts\\install-agent.ps1 -BundleUrl "%s" -DeployTokenFile "C:\\secure\\agent-edict-token"\n' "$bundle_url"
  printf 'Linux/macOS: sudo ./scripts/install-agent.sh "%s" --deploy-token-file /secure/agent-edict-token\n' "$bundle_url"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
