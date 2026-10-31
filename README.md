# AgentEdict (`edict`)

AgentEdict compiles policy profiles, verifies signed bundles, and installs managed configuration files for AI coding agents. **One explicitly assigned machine policy applies to every user of that machine.**

File installation and filesystem locks do not prove that an installed agent version consumed or enforced those settings. Verify native agent behavior before deployment. Gemini CLI, Cursor, Antigravity, GitHub Copilot, Kiro, Windsurf / Devin Desktop, and Cline have explicit native integrations that do not require enterprise administration credentials. Their control coverage differs; hooks do not provide mandatory OS containment.

## Supported configuration targets

| Agent | Windows | Linux / WSL | macOS |
| :--- | :--- | :--- | :--- |
| OpenAI Codex | `C:\ProgramData\OpenAI\Codex\requirements.toml` | `/etc/codex/requirements.toml` | `/etc/codex/requirements.toml` |
| Claude Code | `C:\Program Files\ClaudeCode\managed-settings.json` | `/etc/claude-code/managed-settings.json` | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| OpenCode | `C:\ProgramData\opencode\opencode.json` | `/etc/opencode/opencode.json` | `/Library/Application Support/opencode/opencode.json` |

OpenCode also requires `managed-instructions.md` beside `opencode.json`. The compiler emits this sidecar even when empty, so switching profiles clears previous instructions. Cursor uses its actual system hooks interface described below; the former invented `policy.json` format is not used.

The compiler corrects the managed-control nesting for [Claude](https://code.claude.com/docs/en/managed-settings) and emits OpenCode's `instructions` as managed file references. The three supported file targets do not implement equivalent support for every unified policy constraint.

## Native product integrations

`compile-native` accepts explicit product controls independently of the unified sandbox policy. No enterprise license or cloud administrator credential is needed by these adapters.

| Product | Local mechanism | Scope and limits |
| --- | --- | --- |
| [Gemini CLI](docs/integrations/gemini.md) | Protected standard admin TOML tool rules and system JSON defaults | Admin tool decisions override user rules in the reviewed v0.64.0 source. Sandbox defaults are overridable; MCP startup is not blocked by a tool denial. |
| [Cursor](docs/integrations/cursor.md) | System `hooks.json` and a protected AgentEdict evaluator | Default-deny native tool gate plus exact shell commands and MCP identities/tools. Local hook loading has no entitlement check in inspected 3.24.18. Startup/discovery and user-controlled shell behavior limit enforcement. |
| [Antigravity App](docs/integrations/antigravity.md) | Global user `PreToolUse` registration with protected machine rules | Exact terminal commands/directories, file roots and HTTPS origins; unknown/MCP tools deny. Each user must enroll; users can disable hooks. |
| [GitHub Copilot](docs/integrations/copilot.md) | Root-owned file-based `managed-settings.json` | Copilot's own allow/ask/deny rules, bypass-mode lock, MCP allow/deny lists and sandbox settings. A non-interactive bypass of the bypass-mode lock is reported upstream. |
| [Kiro](docs/integrations/kiro.md) | Admin rules in `managed-settings.json` | Deny/ask rules per capability (shell, files, web, MCP, sign-in methods); admin rules cannot grant. |
| [Windsurf / Devin Desktop](docs/integrations/windsurf.md) | System Cascade `hooks.json` and a protected AgentEdict evaluator | Exact terminal commands and MCP server/tool labels; blocks only on exit code 2, so hook failures fail open. |
| [Cline](docs/integrations/cline.md) | Per-user `PreToolUse` hook with protected machine rules | Allowed tools and exact commands; Cline fails open on hook errors, and users can disable hooks. Cline has no machine-wide configuration. |

These integrations implement local tool guardrails. They do not make every execution path, alternate client, child process, file access or network connection subject to a mandatory boundary. Use the product documents for exact covered controls, source versions and acceptance checks.

### Build a native bundle

The [native example](examples/native/local-guardrails.yaml) starts with tool access denied, except a few read-only and question tools. Add only the native permissions you intend to grant. The companion map selects one machine profile for all seven products.

```sh
./bin/edict compile-native -profile examples/native/local-guardrails.yaml \
  -target-os all -output-dir dist/native/profiles
cp examples/native/policy-map.yaml dist/native/policy-map.yaml
./bin/edict validate-bundle -dir dist/native -target-os all
```

`make native-example` performs the same compile/validation in `dist/native-example`. See the [configuration builder](https://agent-edict.com/builder/) and the product-specific examples. `-agent gemini`, `cursor`, `antigravity`, `copilot`, `kiro`, `windsurf` or `cline` selects one declared section; use a matching `managed_agents` list. Keep `<profile>.native.yaml` with the generated files: bundle validation recompiles it and requires exact matching artifacts. `<profile>.native-capabilities.json` is a human-readable report, not an enforcement attestation. Generate native bundles with the same AgentEdict release deployed on endpoints; output-contract changes require coordinated recompilation and binary rollout. To combine native and unified outputs, use the same profile name and output directory, then explicitly list every intended product in the signed map.

Install the current trusted `edict` binary at `/usr/local/bin/edict` or `C:\Program Files\AgentEdict\edict.exe` before syncing a hook-based policy. The endpoint rejects hook installation if that executable or its ancestry is untrusted. Machine policy files and hook rule sidecars are protected; Cursor and Windsurf hook rules are installed before their registrations.

After signed machine-policy installation, each Antigravity or Cline user runs this **without sudo or an elevated administrator terminal**:

```sh
edict install-hook antigravity
edict install-hook cline
```

For Antigravity it merges the `agent-edict` entry into `~/.gemini/config/hooks.json`, preserves other hooks, and backs up an existing file before changing it. For Cline it writes a `PreToolUse` hook into `<Documents>/Cline/Hooks` and `~/.cline/hooks`, refusing to replace a different existing hook. Restart the client and test a denied tool call. Installing the machine policy does not enroll all users, and `status` reports that registration has not been verified.

## Machine policy and deployment scope

Every signed bundle must contain a `policy-map.yaml` with an explicit `machine_profile` and a nonempty `managed_agents` list. For an intentional Codex-only deployment:

```yaml
version: 1
machine_profile: contractor-readonly
managed_agents: [codex]
sync_wsl: false
```

With a version 1 map, all sessions on the endpoint receive this profile. Logging in, logging out, switching the console user, or changing group membership does not select a different policy. To choose policies from users' groups instead, use a [version 2 map](#role-based-policies-version-2-maps).

Legacy `rules`, group memberships, priorities, and `default_profile` are retained for diagnostics; they do not select the enforced profile. A missing required file for the declared scope rejects the bundle instead of silently retaining a different profile for that agent.

The repository's `policy-map.yaml` is a [version 2](#role-based-policies-version-2-maps) sample that CI compiles, validates and signs with `profiles/` (`POLICY_BUILD_MODE: bundle`). It manages Codex and Claude:
- Contractors get read-only Codex and a restricted Claude policy.
- Group rules are ordered strictest first.
- Everyone else gets the knowledge-worker policy.

The tracked [knowledge-worker Codex gateway configuration](docs/codex-gateway.md) is a public example using `company-coding-model`. Keep real gateway hosts and aliases in a private policy source, never in this repository. The profile contains only the credential variable name; each Codex client must receive its own secret outside AgentEdict. Claude retains its existing route.

Replace its example groups before deploying. Gemini and OpenCode aren't in it: Gemini needs a native declaration, and OpenCode can't enforce the `filesystem.deny_read` every profile uses. Agents omitted from `managed_agents` are outside the declared scope and are not reported as verified. To build a version 1 bundle instead, set `POLICY_BUILD_MODE` to `unified` or `native`. Removing files from a bundle is never a valid way to narrow its scope.

### Role-based policies (version 2 maps)

A version 2 map carries a standard policy for everyone plus group policies. Each machine then picks each managed agent's policy from the groups of the users logged in, and the lowest priority number wins. Only a complete listing of logged-in users changes a machine's files. Otherwise the last known users are kept, and a first start applies the standard. AgentEdict only manages files; it never blocks logins or restarts agents.

```bash
edict compile-bundle -map examples/role-policy/policy-map.yaml \
  -profiles-dir examples/role-policy/profiles -target-os all -output-dir dist
edict validate-bundle -dir dist -target-os all
```

Profiles that cover Claude and block reads or command networking must set `claude.sandbox` (`required` or `tools-only`, per OS). `required` turns on Claude Code's OS sandbox on macOS and Linux (Linux needs `bubblewrap` and `socat`). Claude deny rules for absolute paths now use Claude's `//` form, so `/etc/shadow` is actually protected. See [docs/role-policy.md](docs/role-policy.md) for group syntax on Windows (SIDs, Entra IDs, local groups), timing, takeover and release behavior, status, and limits.

### Optional WSL provisioning

`sync_wsl` defaults to `false`. On Windows, an explicit `true` requests provisioning of the active console owner's distributions under that user's identity. It does not enumerate every user's distributions. If no suitable interactive identity is available, native file installation can complete while WSL provisioning is explicitly reported as deferred and retried on later enforcement passes. Other WSL provisioning failures fail the enforcement pass. Include the selected profile's Linux outputs in the signed bundle when enabling this option.

Copy-only `sync_wsl` is rejected when Cursor, Antigravity, Windsurf or Cline is selected because it does not provision the trusted Linux hook executable. Install and manage AgentEdict within each intended distribution separately.

A distribution owner can obtain root and change its files or immutable flags. Copying policies into WSL is provisioning, not containment of the distribution owner. Use separately administered runtimes when that boundary is required.

## Deploy

Step-by-step guides take you from this repository to a signed bundle on every machine:

- [Deploying AgentEdict](docs/deployment/README.md): policies, the signing key, building the agent, installing it and checking a machine.
- [Deploy from GitLab](docs/deployment/gitlab.md): `.gitlab-ci.yml` publishes to the project's package registry, and machines read it with a deploy token.
- [Deploy from GitHub](docs/deployment/github.md): `.github/workflows/agentedict.yml` publishes to a private bundle repository, and machines read it with a fine-grained token.

## Bundle lifecycle

1. Download the bundle and detached signature over HTTPS. URLs with embedded credentials and redirects to other origins are rejected.
2. Verify the Ed25519 signature before extraction.
3. Extract into a new private staging snapshot, enforcing archive path, file-type, size, and required-profile checks.
4. Activate the complete snapshot by atomically replacing a pointer. Retain at most two snapshots: the current snapshot and its predecessor.
5. Install every configuration file required by `managed_agents`, applying platform ownership, permissions, and available filesystem locks.

A rejected download or invalid candidate leaves the previous verified snapshot available. If that snapshot can be installed, `sync-once` reports the update failure and use of cached policy. An absent usable snapshot or failed installation returns a nonzero exit status. Snapshot activation is atomic; installation across several different agent configuration directories is not one filesystem transaction.

The daemon watches target directories and polls for updates. Repair is best effort and depends on the daemon running, operating-system support, and access checks; there is no guaranteed repair latency. Administrators and root remain outside the local tamper-resistance boundary.

## Configuration builder

The [configuration builder](https://agent-edict.com/builder/) is a static page for building profiles, native profiles and policy maps without learning every agent's settings. Drag settings into a file, or paste an existing one. A pasted Codex `requirements.toml` becomes a profile, with a note for anything AgentEdict doesn't keep. Each setting says what it writes for each agent on macOS, Linux and Windows, how far it is enforced, and where the facts come from. Settings AgentEdict can't write yet, ones only a vendor console can set, and ones users control are listed too, for information. **Check** and **Preview** run AgentEdict's own validation and compiler in the browser (Go compiled to WebAssembly), so the page reports the same errors CI does. Copy or download the YAML into your policy repository.

Run it locally with `make builder`, then serve `public/` with any static web server, for example `python3 -m http.server --directory public 8000`, and open `http://localhost:8000/builder/`. Opening `index.html` straight from disk doesn't work: browsers block its scripts on `file://` pages, and the page says so. The settings catalog is `public/builder/catalog.json`; `go test ./internal/builder` fails when AgentEdict gains or loses a field the catalog doesn't describe, and [docs/builder-catalog-sources.md](docs/builder-catalog-sources.md) lists the vendor pages it cites.

## Compile policies

Build the CLI with a Go toolchain compatible with `go.mod`:

```bash
mkdir -p bin
go build -o bin/edict ./cmd/edict
go test ./...
```

### Contractor read-only profile

The [contractor profile](profiles/contractor-readonly.yaml) compiles for Codex only. Its restricted filesystem profile requires Codex 0.138.0 or later. It sets approval to `never`, disables web search and MCP servers, and restricts filesystem and command-network access. Verify these controls in the Codex version you deploy.

```bash
./bin/edict compile \
  -profile profiles/contractor-readonly.yaml \
  -agent codex \
  -target-os all \
  -output-dir dist/codex/profiles
```

The command writes `contractor-readonly.codex.toml` for Windows, Linux, and macOS, plus a separate optional telemetry configuration. The daemon installs the requirements file; the optional `*.codex.config.toml` telemetry file needs separate deployment. Replace the example telemetry endpoint in private configuration. The [public requirements example](examples/contractor-readonly.requirements.toml) illustrates the native settings.

The engineering profile can also be compiled explicitly for Codex:

```bash
./bin/edict compile \
  -profile profiles/engineering.yaml \
  -agent codex \
  -target-os all \
  -output-dir dist/codex/profiles
```

For a reviewed policy that fits the supported adapter capabilities, `-agent all` produces Codex, Claude, and OpenCode outputs. Cross-agent compilation rejects strict read-only policies, `filesystem.deny_read`, custom filesystem boundaries, and disabled command networking when the other adapters cannot preserve them. `filesystem.deny_write` is unsupported and rejected by both compilation modes; use an explicit Codex permission profile. Gemini, Cursor, Antigravity, Copilot, Kiro, Windsurf and Cline use `compile-native`; the unified compiler does not silently translate sandbox restrictions into weaker hooks. Do not remove required restrictions just to make compilation pass.

A deployable bundle contains `policy-map.yaml` and `profiles/<os>/<machine_profile>.<format>` for every declared target. Validate the prepared directory before signing:

```bash
./bin/edict validate-bundle -dir dist -target-os all
```

`-target-os` accepts `windows`, `linux`, `darwin`, or `all`. Validation checks the signed map's machine assignment and managed-agent scope, required files, and supported file formats. Use the actual bundle directory: the compilation examples above write under `dist/codex/profiles`, so their matching map belongs at `dist/codex/policy-map.yaml` and their validation command is `./bin/edict validate-bundle -dir dist/codex -target-os all`. An explicitly scoped Codex map is required for those examples.

Sign the validated archive with the private Ed25519 key and distribute its detached `.sig` alongside it. The endpoint must trust the matching public key. Validation does not execute native agent consumers, and compilation alone does not create or deploy a signed release.

CI uses the official `golang:1.27.2` image, verifies the committed module checksums without rewriting `go.mod` or `go.sum`, and runs unit tests, race checks, vet, and cross-build/test-compilation checks. The signing job repeats bundle validation and uses a private temporary key file with cleanup. The deliberate cross-agent capability rejection remains a publication gate for the historical unified profiles. For an explicitly selected native release, set CI variables `POLICY_BUILD_MODE=native`, `POLICY_SOURCE=examples/native/local-guardrails.yaml` (or your reviewed native file), and `POLICY_MAP_FILE=examples/native/policy-map.yaml` (or its matching map). Both validation and signing use the same selection.

## Credentials

Anonymous HTTPS downloads are supported: omit `-deploy-token-file` for a publicly readable bundle and signature. Ed25519 verification is still required. Private registries need a credential.

Use a GitLab deploy token restricted to `read_package_registry`, or a GitHub fine-grained token with read-only access to the bundle repository's contents. Transfer it through your secret-management process to a restricted file. The CLI accepts `-deploy-token-file`; it does not accept a literal token argument. Only the credential-file path belongs in service arguments and readable service definitions.

Unix credential files must be owned by the service account and inaccessible to other users. The installers copy credentials into a protected directory. Windows installation applies protected ownership and ACLs that grant access to SYSTEM and Administrators.

Setup scripts require an explicitly supplied management credential, fail when deploy-token creation fails, and do not substitute that management credential into endpoint installation commands. Previously committed credentials require separate revocation or rotation; deleting a literal from the working tree does not revoke it or erase repository history.

## Run or inspect an endpoint

Run privileged commands only on the endpoint you intend to manage. Use the public key matching the release signer; `sync-once` and `daemon` accept `-pubkey` to select a PEM file explicitly.

```bash
sudo ./bin/edict sync-once \
  -bundle-url "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" \
  -deploy-token-file /etc/agent-edict/credentials/deploy-token \
  -pubkey /etc/agent-edict/signing-public.pem

sudo ./bin/edict daemon \
  -bundle-url "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" \
  -deploy-token-file /etc/agent-edict/credentials/deploy-token \
  -pubkey /etc/agent-edict/signing-public.pem \
  -interval 15m

sudo ./bin/edict status
```

`status` reports **FILES VERIFIED** when the declared files match the active snapshot and their inspected protection checks pass, or **INCOMPLETE** when required checks fail. Both states explicitly say **consumer enforcement unverified**. They are not an attestation of agent runtime behavior. The static page under `public/` is documentation, not live endpoint telemetry.

### Windows installation

Supply a binary built with the intended trusted public key. Run from an elevated PowerShell prompt:

```powershell
.\scripts\install-agent.ps1 `
  -BundleUrl "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" `
  -DeployTokenFile "C:\secure\agent-edict-token" `
  -BinarySource ".\bin\edict.exe" `
  -SyncIntervalMinutes 15
```

The installer resolves the system Program Files directory and installs beneath its `AgentEdict` directory. It validates privileges and every service-executable ancestor, rejects reparse points or untrusted writable paths, secures the binary and credential paths, registers the service, checks initial synchronization, and starts the service. It does not Authenticode-sign the Windows binary. To register an already installed binary directly:

```powershell
& (Join-Path $env:ProgramFiles "AgentEdict\edict.exe") service install `
  -bundle-url "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" `
  -deploy-token-file (Join-Path $env:ProgramFiles "AgentEdict\credentials\deploy-token")
& (Join-Path $env:ProgramFiles "AgentEdict\edict.exe") service start
```

### Linux and macOS installation

Build the appropriate release binary with `make build` and the intended trusted public key. The same installer accepts a token file on either platform:

```bash
sudo ./scripts/install-agent.sh \
  "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" \
  --deploy-token-file /secure/agent-edict-token \
  --sync-interval-minutes 15
```

`--sync-interval-minutes` sets how often the service checks for a new bundle, from 1 to 1440 minutes, matching the Windows installer's `-SyncIntervalMinutes`. It defaults to 15.

It validates `/usr/local/bin/edict` and its ancestors, rejecting symlinks, unsafe ownership, writable ancestors, and unsupported ACL conditions. It then installs the binary, performs initial synchronization, and configures systemd on Linux or launchd on macOS. A user-owned `/usr/local` or other unsafe installation ancestor requires administrator remediation before installation; the installer does not silently take over unrelated directories. The daemon uses `/etc/agent-edict/credentials/deploy-token`; raw tokens are not placed in the service command line or launchd plist.

To remove the service and its managed data deliberately:

```powershell
.\scripts\uninstall-agent.ps1 -PurgeData
```

```bash
sudo ./scripts/uninstall-agent.sh --purge-data
```

The uninstallers ask the installed binary for its managed files (`edict targets`) before removing it, then unlock them. Hook registrations that run `edict` (Cursor and Windsurf system hooks) are always removed, because a client would otherwise keep calling a deleted evaluator; other policy files are removed only with the purge option. Per-user Antigravity and Cline registrations are not removed and must be cleaned up by each user.

## Project structure

| Path | Purpose |
| :--- | :--- |
| `profiles/` | Unified policy examples, including engineering, knowledge-worker, and contractor profiles |
| `policy-map.yaml` | Sample version 2 map that CI signs: standard policy, group rules and managed-agent scope |
| `internal/compiler/` | Policy validation and supported adapter output |
| `internal/agent/` | Signature verification, staged snapshots, scope validation, and installation |
| `internal/cursorhook/`, `internal/antigravityhook/`, `internal/windsurfhook/`, `internal/clinehook/` | Hook evaluators for each client's native protocol |
| `internal/platform/` | Native ownership, permissions, locks, credentials, and optional WSL provisioning |
| `cmd/edict/` | Compile, daemon, sync-once, service, and status commands |
| `scripts/`, `deploy/` | Bootstrap scripts, installers, and service definitions |
| `docs/` | Deployment guides, the role policy guide, and per-client integration notes |
| `.github/workflows/` | This project's CI and website, and the policy pipeline for deploying from GitHub |
| `.gitlab-ci.yml` | The policy pipeline for deploying from GitLab |
| `public/` | The website and configuration builder, published with GitHub Pages |

## Verification boundaries

Unit tests and cross-compilation check implementation behavior and build compatibility. They do not establish native Windows ACL/WSL behavior or prove that installed consumer versions enforce every emitted setting. Test those integrations on representative endpoints before rollout. No repository change rotates a GitLab credential or deploys an endpoint by itself.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
