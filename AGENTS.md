# Working in AgentEdict

This file is guidance for contributors and coding agents working in this **public** repository. Read it before changing policy, compiler output, bundle validation, installation, or deployment code. The repository's source and tests remain the authority for behavior; this file does not grant permission to publish a bundle or change a machine.

## What the project does

AgentEdict (`edict`) compiles YAML policy into client-specific managed files, validates a complete policy bundle, verifies a signed bundle on an endpoint, and installs the selected files. A version 2 policy map can select a policy per managed agent from the groups of logged-in users; each selected file is still machine-wide. Version 1 maps select one machine profile. See [README.md](README.md), [role policy](docs/role-policy.md), and the [deployment guide](docs/deployment/README.md) before changing these contracts.

There are two source formats:

- `profiles/<name>.yaml`: unified policy for Codex, Claude Code, and OpenCode. The compiler must reject a profile/agent pairing it cannot faithfully represent.
- `profiles/<name>.native.yaml`: explicit product controls for Gemini CLI, Cursor, Antigravity, GitHub Copilot, Kiro, Windsurf / Devin Desktop, and Cline. These integrations have different coverage and prerequisites; consult [their individual guides](docs/integrations/README.md).

`policy-map.yaml` is a **sample** version 2 map. It declares the managed agents and every profile/agent pair that a bundle must contain, including currently unmatched group rules. The tracked profiles and map are examples, not an organization deployment. A compiled bundle is an output artifact, not a new policy source.

## Non-negotiable boundaries

### Keep the public repository generic

Do not add real gateway hostnames, model aliases, tenant or organization IDs, group names, internal topology, private URLs, credentials, or customer data to tracked source, tests, fixtures, documentation, builder catalogs, or generated artifacts. Use clearly fictional examples such as `https://aigateway.internal.company.com/v1`, `company-coding-model`, and `AI_GATEWAY_API_KEY`. Keep examples consistent across the profile, guide, and tests. Inspect the **staged diff as well as the working tree** before a commit: a file may already be staged. CI is not a substitute for checking content before it leaves the workstation.

For actual deployment, keep the real map and profiles in a separate private policy source. A private repository is still not a place for API keys. Signing keys, deploy tokens, and gateway credentials belong in an appropriate secret store or protected local credential file. Never put a literal secret in YAML, Git, CI variables displayed in logs, bundles, managed client files, command arguments, test output, or examples. An `env_key` field names a variable; it does not carry its value. Deliver the credential to the **client process** through a client-side secret manager or managed launcher. The AgentEdict service does not distribute it. A shell variable may not reach a separately launched desktop client. See [Codex gateway guidance](docs/codex-gateway.md).

If a suspected secret or real deployment value is found, stop propagating it into outputs or logs and report the affected path privately. Do not paste the value into an issue, commit message, or response.

### Preserve policy meaning and reject unsupported states

- Fail closed on unknown YAML fields, invalid values, unsupported client fields, incomplete map scope, missing files, and altered managed artifacts. Fix the source or add complete validated support; do not silently drop a requested restriction to make compilation pass.
- Keep `managed_agents` explicit. An omitted agent is outside AgentEdict's declared scope; it is not verified or blocked. Do not narrow scope by deleting files from a bundle. For a deliberately Codex-only policy, declare `managed_agents: [codex]` and compile the supported Codex path.
- Do not translate unified sandbox, filesystem, command, MCP, or network restrictions into a weaker native hook without an explicit, documented capability boundary. Preserve the restricted contractor Codex policy and Claude's required versus tools-only sandbox distinction.
- Version 2 chooses the lowest numeric priority for each managed agent across logged-in users. Do not change arbitration, first-start defaults, retained assignments on incomplete session evidence, or file release/takeover behavior without tests for the affected platforms and a documentation update.
- Validate all profile/agent/OS combinations a map can select, including dormant rules. A bundle must be compiled and validated as a unit before signing. Keep the original bundle available when an update is rejected.
- Treat generated capabilities and `status` as limited evidence. Compilation shows what this version emits; bundle validation checks required files and supported artifact rules. Neither proves a specific client version consumed the file or that hooks provide OS containment. Endpoint installation/locks do not close user, administrator/root, alternate-client, or uncovered tool paths. State those limits in claims and reviews.
- Native bundle validation recompiles retained native declarations and requires matching artifacts. Compile with the AgentEdict release intended for endpoints; coordinate output-contract and binary changes.

## Repository map

| Area | Responsibility |
| --- | --- |
| `cmd/edict/` | CLI: compile, `compile-native`, `compile-bundle`, `validate-bundle`, status, sync, and service commands. |
| `internal/compiler/schema.go`, `compiler.go`, `agent.go` | Unified YAML schema, validation, Codex/Claude/OpenCode output and agent selection. |
| `internal/compiler/*_native.go`, `native.go`, `native_types.go` | Explicit native product schemas and artifacts. |
| `internal/agent/` | Policy maps, bundle verification/validation, role selection, snapshots, installation, and release. |
| `internal/platform/` | OS-specific paths, protected file operations, credentials, sessions, and runtime prerequisites. |
| `internal/{cursorhook,antigravityhook,windsurfhook,clinehook,hookjson}/` | Local hook evaluators and shared hook data handling. |
| `internal/builder/`, `cmd/edict-wasm/`, `public/builder/` | Browser builder validation/import, WebAssembly compiler, UI, and settings catalog. |
| `profiles/`, `policy-map.yaml`, `examples/` | Public example inputs; examples also exercise separate role and native flows. |
| `docs/`, `public/` | Technical/deployment guidance and the static site. |
| `.github/workflows/`, `.gitlab-ci.yml`, `scripts/` | Verification, signing/publication workflows, installers, and setup helpers. |

The usual path is **YAML source → schema validation → per-client compiler → `profiles/<os>/` managed artifact → bundle validation → signature verification on endpoint → selected file installation**. Trace a change through that path. The browser builder is another input path to the same compiler and must expose supported fields accurately.

## How to make a change

1. Inspect `git status --short` and both staged and unstaged diffs. Preserve unrelated work; never reset, clean, or overwrite it to make a task easier. Identify the exact source, callers, generated output, tests, examples, builder metadata, and docs affected by the change.
2. Confirm the current client contract from official vendor documentation when changing a client setting or making an enforcement claim. Record the supported product version and any client-specific limitation in the relevant integration guide. A valid TOML or JSON file alone is insufficient evidence of client behavior.
3. Add or change schema validation at the input boundary and validate the compiled artifact where the bundle is accepted. Prefer a clear error that names the field and target. Keep policy fields distinct from runtime secrets.
4. Update each affected compiler and target OS output. If only one client supports a feature, leave other clients' behavior explicit and tested; do not invent equivalence. Keep generated files deterministic, including ordering and empty-state behavior.
5. Update the builder importer and `public/builder/catalog.json` when the supported schema changes. Update public examples and docs together. If output shown on the site changes, follow [public/README.md](public/README.md) to refresh its real compiler output.
6. Add focused positive and rejection tests at the relevant boundaries. Test malformed or unsupported settings, profile/agent selection, bundle revalidation, and a representative generated file. Use temporary directories; never write test artifacts to live managed paths.
7. Review the final diff for leaked values, weakened policy, accidental publication steps, and documentation that promises more than the code proves.

For gateway work in particular, keep `profiles/knowledge-worker.yaml`, [docs/codex-gateway.md](docs/codex-gateway.md), compiler tests, builder catalog, and bundle tests in agreement. The public example uses a generic Codex Responses endpoint and a variable **name**. It does not configure Claude with a Codex model alias. A future Claude gateway needs its own supported Messages endpoint, model alias, credential flow, and validation.

## Local verification

Use a Go toolchain compatible with `go.mod` and the version pinned in CI. The checks in [GitHub CI](.github/workflows/ci.yml) and [GitLab CI](.gitlab-ci.yml) are the release baseline. Run focused tests first, then expand based on the code touched:

```sh
go test ./internal/compiler ./internal/agent ./internal/builder ./cmd/edict
go test ./...
go vet ./...
make builder
node --test scripts/tests/builder/*.test.mjs
git diff --check
git diff --cached --check
```

`make builder` creates the WebAssembly files the Node tests load. The Node tests matter when builder JavaScript or catalog behavior changes. CI also runs race tests and cross-compiles supported OS/architecture targets. A cross-build checks compilation, not Windows or macOS runtime behavior.

For a complete sample bundle, build the local CLI in a temporary directory. `compile-bundle` refuses an output directory with an existing `policy-map.yaml` or `profiles/` to avoid stale signed files:

```sh
guide_tmp=$(mktemp -d)
go build -o "$guide_tmp/edict" ./cmd/edict
"$guide_tmp/edict" compile-bundle -map policy-map.yaml -profiles-dir profiles -target-os all -output-dir "$guide_tmp/bundle"
"$guide_tmp/edict" validate-bundle -dir "$guide_tmp/bundle" -target-os all
```

For a Codex gateway edit, also run `go test ./cmd/edict -run TestKnowledgeWorkerGatewayBundle` and inspect the generated `knowledge-worker.codex.toml` on Windows, Linux, and macOS. Run `make native-example` or the relevant native tests for native adapter changes. Report exactly what ran and what remained unverified.

## Deployment and review discipline

Signing, publishing, merging to a deployment branch, running installers, `sync-once`, `daemon`, and changing endpoint files can affect real machines. Do not perform those steps as part of routine implementation or verification unless the user explicitly requests them. GitLab's default-branch pipeline can sign and publish; GitHub's publishing job can do so when its repository variable and protected environment are configured. Treat a default-branch merge as a potential deployment action.

When reporting a change, distinguish: source review, local tests, compiled artifact inspection, bundle validation, endpoint installation, and live client acceptance. Give the exact files and commands behind each claim. Call out client-specific coverage and missing prerequisites. Follow the deployment guide for any separately authorized rollout; do not infer fleet safety from passing unit tests.
