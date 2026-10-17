# Cursor local hooks

AgentEdict compiles and delivers local Cursor hooks without a cloud administration
credential. The adapter covers `preToolUse`, `beforeShellExecution`, and
`beforeMCPExecution`.
It does not require a Cursor enterprise administration API or deploy an MDM
profile. The official Cursor 3.24.18 client source loads local machine hooks
without a team membership or enterprise entitlement check. Acceptance by an
installed standalone client remains a deployment verification step.

## Input

Use this section in a native AgentEdict policy:

```yaml
cursor:
  hooks:
    version: 1
    tools_allow: [Read, List, Grep, Shell, "MCP:search", "MCP:lookup"]
    shell:
      allow:
        - git status
      ask:
        - git push
      deny:
        - rm -rf /
    mcp:
      - name: documentation
        url: https://mcp.example.com/docs
        tools: [search, lookup]
        decision: allow
      - name: local-docs
        command: /usr/local/bin/docs-mcp --read-only
        tools: [search]
        decision: allow
```

The `preToolUse` gate is always registered. Every reported tool name absent from
`tools_allow` is denied, including new or unknown names. An omitted or empty
`tools_allow` denies all reported tool invocations. The example permits read/list/
search categories and selected shell/MCP invocations; it blocks `Write`, `Delete`,
`Fetch`, `ComputerUse`, and `WriteShellStdin` because they are absent. Add a name
only when that whole tool category is intended. In particular, permitting
`WriteShellStdin` can feed input to an existing shell without the shell command
hook inspecting that input.

Allowed `Shell` and `MCP:<tool_name>` categories must also pass their specific
hooks. Every unlisted command or MCP invocation is denied. Empty lists deny all
calls in that category. Shell matching compares the complete command string, including
spaces. It performs no prefix, substring, or wildcard matching. For example,
allowing `git status` does not allow `git status; curl example.com`.

MCP matching requires all of the following: the configured server name, the exact
HTTPS URL or full rendered launch command reported by Cursor, and an explicit tool
name. A server name alone never grants access. Shell `ask` delegates the decision
to Cursor's user confirmation. MCP rules accept only `allow`; every unmatched
call is denied. The shipped Cursor 3.24.18 MCP executor checks `deny` and otherwise
proceeds, so `ask` would not enforce a confirmation. AgentEdict rejects it even
though the public hook response schema includes that value. The adapter also does
not emit `ask` for `preToolUse`, where Cursor does not enforce it.

## Local artifacts

| OS | Hook configuration | AgentEdict rules |
| --- | --- | --- |
| Linux | `/etc/cursor/hooks.json` | `/etc/cursor/agentedict-policy.json` |
| macOS | `/Library/Application Support/Cursor/hooks.json` | `/Library/Application Support/Cursor/agentedict-policy.json` |
| Windows | `C:\ProgramData\Cursor\hooks.json` | `C:\ProgramData\Cursor\agentedict-policy.json` |

Each hook uses an absolute installed `edict` executable path, a bounded timeout,
and `failClosed: true`. The rules sidecar is installed before the hook
configuration. The evaluator reads JSON over stdin and emits a permission result.
Malformed JSON, duplicate keys, invalid policy, inconsistent event or transport
identity, and excessive input size return `deny`. Hook inputs and policy contents
are never logged by the evaluator. The JSON protocol limit is 1 MiB per request.

The signed bundle contains both files. Endpoint installation protects their
ownership and permissions. This is the machine's hook configuration: deployment
replaces an existing file at the same path, so migrate existing machine hooks
before enrolling Cursor.

## Enforcement scope

These are application hook guardrails. They apply when the installed Cursor
client calls the documented local permission hooks. They do not restrict a user's
ordinary terminal, a modified client, another application, or a remote host that
has not been enrolled. Administrators can change the deployment.

An exact shell command rule does not constrain the command's child processes,
network, files, working directory, shell initialization, executable resolution,
aliases, or executable contents. A permitted executable can perform additional
operations. Use the client or OS sandbox separately where process containment is
required.

The MCP hook controls tool invocations. It does not prevent a configured local
MCP server process from starting, or a remote connection from being opened before
the hook. A permitted tool can have arbitrary effects in its own implementation.
Transport command comparison uses Cursor's rendered command field; it does not
attest the executable or its arguments independently.

The adapter does not claim filesystem read/write isolation, network isolation,
model restrictions, login restrictions, or equivalent coverage of Tab, actions
that do not emit a tool hook, cloud agents, and remote workspaces. Denying `Read`,
`Write`, or `Delete` prevents those reported tool calls; allowing `Shell` or
another capable tool can still permit equivalent file operations through that
tool. No enterprise policies are silently inferred
from the unified Codex schema.

## Endpoint acceptance checks

After installing the signed bundle and the protected `edict` executable, check
Cursor's Hooks view and Hooks output channel for all three system hooks. Exercise one
allowed, one prompted, and one unlisted shell invocation. Exercise an allowed MCP
tool, an unlisted tool on the same server, and a server with the same name but a
different endpoint. Confirm a lower-level user/project hook returning `allow`
does not override a machine `deny`. Exercise a permitted `Read` and blocked
`Write`, `Delete`, `Fetch`, and `WriteShellStdin` invocation. Confirm missing/unreadable evaluator or rules
causes a block. Repeat checks after client updates, and separately for any remote
workspace deployment.

These are deployment acceptance checks; AgentEdict's file status does not certify
that Cursor has consumed the files or that a specific client build invokes every
hook. Unit tests cover compiler output and evaluator decisions, not a live Cursor
session.

## Client source verification

Inspected the official Linux package `cursor_3.24.18_amd64.deb`, downloaded from
Cursor's download page on 2026-10-15. Package product metadata identifies commit
`be4c9e5350d77747b42cd467cbd3370a753d4640`, built 2026-10-13. No application code
was executed or installed during this inspection.

In `out/vs/workbench/workbench.desktop.main.js`, `initialize`,
`resolveEnterpriseConfigDirectoryAndPath`, `reloadHooks`, and
`executeHookForStep` load and select local system hooks independently of team
authentication. The `thirdPartyExtensibilityEnabled` toggle affects imported
Claude/plugin hooks, not native machine hooks. Empty workspaces only disable the
project configuration paths; system paths are still loaded. Remote workspaces
resolve the system configuration on the remote host.

`_executeCommandHookScript` implements failure blocking for timeouts, nonzero exit
codes, missing output, malformed responses, and execution errors. The shipped
agent executor handles shell `ask` but only handles `deny` for MCP invocations;
this is why MCP `ask` is rejected in AgentEdict.

The same executor's generic wrapper calls `preToolUse` and returns a rejected
result on `deny` before invoking the wrapped operation. Verified tool names are
`Read`, `Write`, `Delete`, `List`, `Grep`, `Shell`, `WriteShellStdin`, `Fetch`,
`ReadLints`, `ListMcpResources`, `FetchMcpResource`, `ComputerUse`, and `RecordScreen`.
Its MCP wrapper emits `MCP:<tool_name>`. This adapter emits only `allow`/`deny`
for the generic gate; it does not assume that every future tool is hooked.

Source inspection also found a startup limitation: ordinary clients use a
bounded hook-readiness wait (default two seconds), whereas an unbounded wait is
controlled by an enterprise administration setting. Native hook configuration
parse/read failures can result in no hook being loaded. `failClosed` protects
failures of a configured hook, not failure to discover the configuration itself.
The adapter therefore reports application guardrails, not guaranteed containment.

There is also a user-environment limitation in
`out/vs/workbench/api/node/extensionHostProcess.js`: the direct hook executor
selects the shell from `SHELL` on Unix. On Windows it resolves PowerShell from
`PATH` before trying the system fallback. A user who can launch Cursor with a
replacement shell can influence hook execution despite the absolute evaluator
path. Protecting the policy files therefore does not provide a mandatory boundary
against a user deliberately bypassing the client.

On Windows, the generated command quotes the executable path containing spaces.
Cursor 3.24.18's direct hook transport adds PowerShell's call operator to commands
that begin with a quoted path, then pipes the JSON payload to the invocation.
The compiler test exercises that transport with a harmless PowerShell argument
capture script and verifies the event, policy path, and input. A separate `.cmd`
wrapper is not needed for this client version. This test runs when `pwsh` is
available and does not launch Cursor or change machine policies.

Evidence hashes (SHA-256):

- `workbench.desktop.main.js`:
  `ed6922a7a86c8c448a46aa39af0c931580da162770fe406a0d41737290e637d9`
- `extensions/cursor-agent-exec/dist/main.js`:
  `fa2c81cdcb4457eff4e9c3c42ca7ee89ac4438881279c3b6f58a252d6885e159`
- `out/vs/workbench/api/node/extensionHostProcess.js`:
  `473047ad3a1d711e955da5d407e9393b1ea78189c86abfd70be4b18335077507`

## Vendor references

- [Cursor hooks](https://cursor.com/docs/hooks): local paths, hook event schemas,
  failure handling, response merging, and cloud distribution.
- [Cursor deployment patterns](https://cursor.com/docs/enterprise/deployment-patterns):
  device policies use separate OS-specific delivery mechanisms; those settings
  are not fabricated in this adapter's hook files.
