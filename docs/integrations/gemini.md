# Gemini CLI local management

AgentEdict supports Gemini CLI's **local system settings and administrator TOML tool policies**. These mechanisms do not require an enterprise subscription. The adapter is based on the tagged **Gemini CLI v0.64.0** source; older versions have not been qualified. The policy-loading path is unconditional in the [CLI configuration code](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/cli/src/config/config.ts) and [policy configuration code](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/policy/config.ts).

This is an explicit native policy contract. Existing unified profiles are not silently translated into weaker Gemini controls.

## What is supported

| Control | Delivery | Scope |
|---|---|---|
| Allow, deny, or ask for tool calls | Standard administrator TOML file | Admin rules take precedence over user policies, remembered approvals, and CLI tool allowances in the compatible client. |
| Shell command prefixes | Native `commandPrefix` rule | Gemini applies its shell parsing and command-composition semantics. A prefix is a literal prefix, not AgentEdict's unified command glob syntax. |
| MCP tool calls | Native `mcpName` and `toolName` rule | Controls calls to discovered tools. Does not prevent server startup or network connections. |
| Disable YOLO and Always Allow | System `security` settings | Configuration; a user can redirect the settings file with an environment variable. |
| Sandbox default | System `tools.sandbox` setting | Configuration; CLI flags and environment variables can override it. |

The administrator policy file is a client-level tool control, not an OS filesystem or network sandbox. A user who can execute a modified client or a separate program can act outside this client. Managing execution of approved application versions requires endpoint application controls. MCP process lifecycle restrictions are not implemented by this local adapter.

## Native profile

```yaml
version: 1
name: gemini-local-review
gemini:
  default_decision: deny
  settings:
    disable_yolo_mode: true
    disable_always_allow: true
    sandbox_default: auto
  rules:
    - tool_name: read_file
      decision: allow
      priority: 100
    - tool_name: run_shell_command
      command_prefix: git status
      decision: ask_user
      priority: 200
    - tool_name: '*'
      mcp_name: '*'
      decision: deny
      priority: 999
      deny_message: MCP tool calls are disabled by this machine policy.
```

The required `default_decision` is `deny` or `ask_user`. It becomes an administrator catchall at priority zero, active in every approval mode. Rule decisions are `allow`, `deny`, or `ask_user`. Rule priorities are 1–999, excluding 950. Larger numbers win. Avoid equal priorities for overlapping rules, since ordering then matters. The compiler reserves priority 950 because v0.64.0's Always Allow detection can skip that priority even in administrator rules when `disableAlwaysAllow` is enabled. [Native policy engine](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/policy/policy-engine.ts)

Optional `modes` values are `default`, `autoEdit`, `plan`, and `yolo`; omitted or empty means every mode. Optional `command_prefix` is valid only with the built-in `run_shell_command`, without `mcp_name`. Optional `mcp_name` is a server name or `*`; optional `deny_message` is a user-facing explanation. Field names are translated to the native TOML schema, and strings are serialized with a TOML encoder. Arbitrary regexes or extra vendor settings are not accepted. [Native TOML schema](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/policy/toml-loader.ts)

`ask_user` retains Gemini's native semantics. In particular, bare shell rules can be refined by known-safe-command heuristics; this value does not guarantee that every matching shell invocation prompts. Use `deny` where execution must be blocked. For noninteractive execution Gemini ordinarily converts a remaining `ask_user` decision to `deny`. [Native decision implementation](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/policy/policy-engine.ts)

The two security settings default to `true` when omitted; explicit `false` is preserved. `sandbox_default` is optional. Its values are:

| Value | Target |
|---|---|
| `auto`, `disabled`, `docker`, `podman` | All supported operating systems; a suitable runtime must exist when enabling a sandbox |
| `sandbox-exec` | macOS |
| `runsc`, `lxc` | Linux |
| `windows-native` | Windows |

`auto` emits `tools.sandbox: true`; `disabled` emits `false`; named runtimes emit that runtime name. Missing runtimes are Gemini startup errors, not automatic AgentEdict installation errors. The adapter does not install a sandbox runtime. [Sandbox selection](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/cli/src/config/sandboxConfig.ts)

## Files and signed deployment

The compiler emits `<profile>.gemini.json` and `<profile>.gemini.policy.toml`. Both files are required when the signed bundle declares `managed_agents: [gemini]`.

| Platform | System settings | Administrator policy |
|---|---|---|
| Linux | `/etc/gemini-cli/settings.json` | `/etc/gemini-cli/policies/agentedict.toml` |
| macOS | `/Library/Application Support/GeminiCli/settings.json` | `/Library/Application Support/GeminiCli/policies/agentedict.toml` |
| Windows | `C:\ProgramData\gemini-cli\settings.json` | `C:\ProgramData\gemini-cli\policies\agentedict.toml` |

These are Gemini's fixed standard locations. The settings override variable does not relocate the standard administrator policy directory. [Native paths](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/config/storage.ts)

The policy directory must pass Gemini's security checks: root ownership without group/other write permission on Unix, and a secure Windows ACL. AgentEdict's privileged delivery applies its file/directory protection. Restart Gemini after installation; already-running processes can retain their previous policy. Other administrator TOML files in the same directory also participate in policy evaluation and must be reviewed when deploying this file. [Directory checks](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/utils/security.ts)

## Bypass boundaries

| Ordinary user input | Effect in v0.64.0 |
|---|---|
| User policy or `--policy` | Lower tier than the standard administrator TOML file. |
| `--allowed-tools`, trusted MCP tools, remembered approvals | Lower tier than administrator rules. |
| `--admin-policy` or `adminPolicyPaths` | Ignored when the standard administrator directory contains any `.toml` file. |
| `GEMINI_CLI_SYSTEM_SETTINGS_PATH` | Can bypass JSON settings; does not change the fixed administrator directory. |
| `--sandbox=false`, `GEMINI_SANDBOX=false`, or `SANDBOX` | Can bypass a configured sandbox default. |
| User-added MCP server or `--allowed-mcp-server-names` | May start a server; administrator tool denial does not prevent startup. |

The tier ordering and supplemental-policy guard are implemented in [policy configuration](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/policy/config.ts). The settings path is handled separately in [storage](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/config/storage.ts). The compiler deliberately does not emit file-based `admin.mcp` controls: Gemini obtains that namespace from its remote administration service, and local files are ignored. Likewise, an empty local MCP allowlist is not a reliable deny-all mechanism. [Settings merge](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/cli/src/config/settings.ts), [MCP client filtering](https://github.com/google-gemini/gemini-cli/blob/v0.64.0/packages/core/src/tools/mcp-client-manager.ts)

## Verification boundary

Compiler tests parse the emitted JSON/TOML, verify all three operating-system paths, preserve the native rule fields, reject invalid rules and reserved priorities, and check that capability metadata distinguishes tool enforcement from configuration. These are generation tests, not a live consumer certification.

Before rollout, test the installed Gemini version as a standard user in a disposable workspace: confirm the admin directory is accepted, confirm a denied built-in and an MCP tool remain denied with user allow rules and CLI tool allowances, try a supplemental administrator policy, and repeat with the settings override variable. Separately verify that your endpoint application controls prevent running alternate clients if that is a requirement. No enterprise account is needed to load local administrator TOML policies; Gemini's normal model authentication is separate.
