# Windsurf / Devin Desktop local hooks

AgentEdict installs **Cascade system-level hooks** that run the protected `edict` evaluator before terminal commands and MCP tool calls. Windsurf is now Devin Desktop; the hook contract follows the [Cascade hooks documentation](https://docs.devin.ai/desktop/cascade/hooks), reviewed October 2026.

## What is supported

| Hook | Decision | Scope |
|---|---|---|
| `pre_run_command` | Proceed only when `tool_info.command_line` exactly matches a listed command | Compound commands, prefixes and variations are blocked. |
| `pre_mcp_tool_use` | Proceed only when the MCP server label and tool name are listed | Labels are user-chosen, not authenticated identities. Does not prevent server startup or connections. |

Cascade blocks an action only when a pre-hook **exits with code 2**, and shows the hook's stderr to the agent. Empty lists block every command or MCP tool call. There is no "ask" decision: an allowed action still goes through Cascade's own approval settings. `pre_read_code` and `pre_write_code` are not registered, so file reads and writes are not path-restricted.

## Native profile

```yaml
version: 1
name: windsurf-guardrails
windsurf:
  hooks:
    version: 1
    commands: ["git status", "npm test"]
    mcp:
      - server: github
        tools: [create_issue]
```

## Files

The compiler emits `<profile>.windsurf.policy.json` and `<profile>.windsurf.hooks.json`. The hook registration is installed at both the Devin Desktop location and the legacy Windsurf location, which Devin Desktop reads only when its own file is absent and older Windsurf releases read directly.

| Platform | Evaluator policy | System hooks |
|---|---|---|
| Linux | `/etc/agent-edict/windsurf-policy.json` | `/etc/devin/hooks.json`, `/etc/windsurf/hooks.json` |
| macOS | `/etc/agent-edict/windsurf-policy.json` | `/Library/Application Support/Devin/hooks.json`, `/Library/Application Support/Windsurf/hooks.json` |
| Windows | `C:\ProgramData\AgentEdict\windsurf-policy.json` | `C:\ProgramData\Devin\hooks.json`, `C:\ProgramData\Windsurf\hooks.json` |

On macOS and Linux, Cascade runs the hook's `command` via `bash -c`. On Windows it runs the `powershell` value via `powershell -Command`, which converts a native exit code of 2 into 1 unless the command ends with `exit $LASTEXITCODE` ([PowerShell exit codes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)). The generated command forwards the UTF-8 payload without console APIs and ends with `exit $LASTEXITCODE`; a test runs it through PowerShell and confirms exit 2 reaches the caller.

## Bypass boundaries

- **Hook failures fail open.** Any exit code other than 2, a missing or unlaunchable evaluator, or Restricted Mode (where hooks do not run) lets the action proceed. The evaluator itself exits 2 for every malformed request.
- System hooks merge with cloud, user and workspace hooks and cannot be disabled by end users without administrator rights.
- Hooks are preflight checks; they do not sandbox the command or its child processes.

## Verification boundary

Tests cover the exact hook schema, paths, the evaluator's allow/block decisions for malformed, ambiguous and duplicate-key payloads, and the Windows PowerShell transport. No Devin Desktop or Windsurf client was launched. Before rollout, confirm in each version that an unlisted command is blocked, the agent sees the explanation, and the legacy path behaves as expected when both files exist.
