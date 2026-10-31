# Local application controls

AgentEdict's native integrations target endpoint applications without a cloud administration credential or enterprise license dependency. Use `compile-native` and an explicit signed machine assignment. The unified compiler continues to reject restrictions that its adapters cannot preserve.

For model API routing across these and the unified clients, see [gateway support by client](../gateway-support.md). Native tool controls and model gateway settings have separate client contracts.

| Application | Mechanism | Verified here | Remaining boundary |
| --- | --- | --- | --- |
| [Gemini CLI](gemini.md) | Protected admin TOML policy plus system settings | v0.64.0 source and generated TOML/JSON tests | Tool decisions do not prevent MCP startup or mandate an OS sandbox. |
| [Cursor](cursor.md) | System hooks invoking protected `edict` | Official 3.24.18 package source, evaluator and PowerShell transport tests | Hook startup/discovery and user-controlled shell environment can bypass invocation. Other tools and remote machines need separate coverage. |
| [Antigravity App](antigravity.md) | Per-user named PreToolUse hook invoking protected machine rules | Official 2.23.1 package contract, evaluator and registration tests | Users can disable the hook. Timeout/failure behavior and complete coverage need client tests. |
| [GitHub Copilot](copilot.md) | Root-owned file-based `managed-settings.json` | GitHub's managed-settings reference; generated JSON and bundle round-trip tests | Client-enforced; a reported non-interactive bypass of `disableBypassPermissionsMode` is open. Key support varies by client. |
| [Kiro](kiro.md) | Admin deny/ask rules in `managed-settings.json` | Kiro's permission-policy documentation; generated schema tests | Client-enforced; admins cannot grant. Kiro CLI handling not independently verified. |
| [Windsurf / Devin Desktop](windsurf.md) | Cascade system hooks invoking protected `edict` | Devin Desktop hooks documentation, evaluator and PowerShell exit-code transport tests | Hook failures fail open; reads and writes are not gated; MCP labels are user-chosen. |
| [Cline](cline.md) | Per-user PreToolUse hook invoking protected machine rules | Cline source for both payload shapes, evaluator, hook script and enrollment tests | Cline fails open on hook errors; users can disable hooks; no machine-wide or local remote configuration exists. |

All seven integrations are implemented. None of the application consumers was launched in a logged-in native acceptance test. File installation status must not be interpreted as proof of mandatory machine lockdown.

## Build and distribute

See the [root README](../../README.md#build-a-native-bundle) and [native example](../../examples/native/local-guardrails.yaml). Each native product emits one or two required artifacts (Windsurf's hook registration is installed at two locations). The signed bundle also retains `<profile>.native.yaml`; the endpoint recompiles that declaration and compares exact artifact bytes before activation. Arbitrary destinations in capability reports are never used for privileged writes.

Hook-based scope requires the trusted, application-readable `edict` executable at its fixed system path. This prerequisite is checked before promoting a downloaded snapshot, so a missing runtime does not evict the previous usable policy. Rule sidecars are installed before their hook registration files. Installation across multiple files is not transactional.

Antigravity's global registration and Cline's per-user hook are applied separately by `edict install-hook antigravity` and `edict install-hook cline`, run as each ordinary application user. The command verifies the protected template, preserves unrelated hooks, and saves a backup before changes. It refuses elevated execution and linked config paths. The central rule file remains common to all enrolled users; per-user enrollment is not per-user role selection.

Private registries may use a read-only download credential; public HTTPS bundles can be downloaded anonymously. Ed25519 signature verification applies in both cases. Hook execution itself needs no credential.

## Validation

Automated tests cover strict native declarations, exact generated artifacts, signed snapshot activation and rollback, scope completeness, hook runtime prerequisites, native deny/ask/allow protocols, malformed and oversized JSON, duplicate keys, path escapes, per-user registration preservation, and all three target OS file layouts. CI also builds the hook packages for the target platforms.

Before production use, run the version-specific acceptance checks in each product document. Windows ACL/WSL behavior and native application execution still need testing on their actual endpoints. Local hooks can reduce agent mistakes and block covered tool calls, but preventing a determined local user from bypassing every path needs an additional OS or isolated-runtime boundary.

### Implementation checks (2026-10-16)

- Added Copilot, Kiro, Windsurf and Cline adapters. `go test -race ./... -count=1` and `go vet` passed for darwin, linux and windows on amd64 and arm64.
- Hook transport tests executed the generated Windows Windsurf command through PowerShell (exit 2 propagates only with `exit $LASTEXITCODE`, confirmed by removing it) and the generated Cline hooks through `sh` and PowerShell.
- Native CLI smoke test: the example now generates 11 native artifacts per OS and the complete bundle validates on all three OSes.

### Implementation checks (2026-10-15)

- `go test -race ./... -count=1`: passed for all six packages on macOS/arm64, including a real disposable-file macOS ACL check and harmless PowerShell argument transport test.
- `go vet ./...`: passed.
- CLI builds: Windows, Linux and macOS, each amd64 and arm64. All package test binaries also compiled for those platforms on amd64; changed compiler/hook tests additionally compiled on arm64. Cross-compilation does not execute platform tests.
- Native CLI smoke test: generated six product artifacts plus declaration/report for every OS; the complete example bundle validated on all three OSes. Changed artifact bytes were rejected. Cursor and Antigravity emitted their expected native decisions; missing policies returned denial JSON and exit code 2.
- Bootstrap regressions: seven Python tests and both mocked PowerShell suites passed. Bash, CI YAML/embedded shell, JSON schema syntax, HTML nesting, and whitespace checks passed.

No service installation, live application session, commit, push, or publication was performed.
