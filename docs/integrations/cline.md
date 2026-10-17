# Cline local hooks

Cline has **no machine-wide managed configuration**. Its [remote configuration](https://docs.cline.bot/enterprise-solutions/configuration/remote-configuration/overview) is delivered only through Cline's hosted service, and Cline documents "Allow YOLO mode" as unsupported in every client; [cline/cline#14765](https://github.com/cline/cline/issues/14765) (open) reports that nothing reads `yoloModeAllowed`. AgentEdict therefore emits no remote configuration.

The local control point is Cline's **PreToolUse file hook**. AgentEdict installs a protected machine policy, and each user enrolls a hook that runs the `edict` evaluator. The contract follows Cline's source, reviewed October 2026: [hook examples and payloads](https://github.com/cline/cline/blob/main/sdk/examples/hooks/README.md), the [SDK hook runner](https://github.com/cline/cline/blob/main/sdk/packages/core/src/hooks/hook-file-hooks.ts), the [VS Code hooks adapter](https://github.com/cline/cline/blob/main/apps/vscode/src/sdk/hooks-adapter.ts), and its [hook process launcher](https://github.com/cline/cline/blob/main/apps/vscode/src/core/hooks/HookProcess.ts).

## What is supported

| Tool call | Decision |
|---|---|
| `run_commands` (SDK clients) and `execute_command` (older extension releases) | Run only when **every** requested command exactly matches `commands`. |
| Any other tool | Run only when `tools` sets it to `allow`. |
| Anything else | Cancel. |

The evaluator accepts both payload shapes: the CLI/SDK sends `tool_call.{name, input}`, and the VS Code extension sends `preToolUse.{toolName, parameters}` with non-string parameters JSON-encoded. It normalizes every `run_commands` input form (`commands`, `command`, `cmd`, bare strings and arrays, and `{command, args}` argv entries); argv entries with whitespace or quotes have no exact single-line form and are cancelled. Unrecognized shapes are cancelled, never treated as "no commands".

In the VS Code extension a cancel stops the whole run, not only the one tool call. Hooks do not see MCP server identity.

## Native profile

```yaml
version: 1
name: cline-guardrails
cline:
  hooks:
    version: 1
    tools:
      read_files: allow
      search_codebase: allow
      editor: allow
    commands: ["git status", "npm test"]
```

## Files and enrollment

The compiler emits `<profile>.cline.policy.json`, installed at `/etc/agent-edict/cline-policy.json` (macOS, Linux) or `C:\ProgramData\AgentEdict\cline-policy.json` (Windows).

Each user then runs `edict install-hook cline` without elevation. It verifies the protected policy and evaluator and writes the hook into both directories Cline reads:

| Client | Hook file |
|---|---|
| VS Code extension | `<Documents>/Cline/Hooks/PreToolUse` (Windows: `PreToolUse.ps1`) |
| CLI | `~/.cline/hooks/PreToolUse` (Windows: `PreToolUse.ps1`) |

`<Documents>` matches Cline's own lookup: the Windows Documents known folder (including OneDrive redirection), `xdg-user-dir DOCUMENTS` on Linux, or `~/Documents`. The command refuses symlinked hook directories and never replaces a different existing `PreToolUse` hook.

## Bypass boundaries

- **Cline fails open.** Hook timeouts, crashes, non-zero exits, and invalid output let the tool run. The evaluator therefore answers every request, including malformed ones, with valid `{"cancel": true}` JSON and exit code 0, but a missing or unlaunchable evaluator still fails open.
- **Enrollment is per user and optional.** The user can delete the hook. The extension runs hooks only when the user's "Enable Hooks" setting is on, and Cline disables hooks in `--yolo` mode.
- The extension launches Windows hooks with `-ExecutionPolicy Bypass`; the CLI does not, so a restrictive execution policy can stop the CLI hook from running.

## Verification boundary

Tests cover both payload shapes, every command input form, malformed and duplicate-key payloads, the exit-0 JSON protocol, the generated Unix and Windows hook scripts (run through `sh` and PowerShell), and idempotent, non-clobbering enrollment. No Cline client was launched. Before rollout, confirm in each client version that a denied tool is cancelled and the user sees the explanation.
