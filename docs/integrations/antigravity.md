# Antigravity App local hooks

AgentEdict supports the **Antigravity desktop application** through its documented `PreToolUse` hook. The adapter uses local files and the local `edict` executable. It does not require a cloud administration credential or an enterprise policy service.

This is a tool guardrail for an enrolled user. It is **not mandatory machine lockdown**: the App lets users disable named hooks, and an administrator-protected rules file cannot force an application to invoke its hook. AgentEdict reports this distinction in the compiled capability report.

## Configure and compile

Create a native profile, substituting real absolute paths for the endpoint:

```yaml
version: 1
name: workstation
antigravity:
  hooks:
    version: 1
    read_roots:
      - /srv/work/project
    write_roots:
      - /srv/work/project
    https_origins:
      - https://docs.example.test
    commands:
      - command: git status
        directory: /srv/work/project
        decision: allow
      - command: git diff
        directory: /srv/work/project
        decision: ask
    tools:
      view_file: allow
      list_dir: allow
      find_by_name: allow
      grep_search: allow
      write_to_file: ask
      replace_file_content: ask
      multi_replace_file_content: ask
      read_url_content: ask
      ask_question: allow
      list_permissions: allow
```

```sh
edict compile-native -profile workstation.native.yaml -agent antigravity -target-os linux
```

Use `darwin` for macOS or `windows` for Windows. Paths in `read_roots`, `write_roots`, and command directories must be absolute and valid for the selected operating system. A profile with Unix paths cannot be compiled unchanged for Windows. Empty rules produce a deny-by-default tool policy.

Decisions are `allow`, `ask`, and `deny`. `ask` emits the App's `force_ask` response so a cached approval does not suppress the prompt. `allow` emits the native `allow` decision; it should be used only for a call the operator is willing to permit without a new prompt. Current web documentation describes `allow` as delegating to subsequent hooks or the native policy, while the guide embedded in App 2.23.1 describes automatic allowance. AgentEdict does not emit `auto_approve`, argument overwrites, or temporary permission overrides.

## Install the rules and enroll each user

Compilation produces two application artifacts plus the common native declaration and capability report:

| Artifact | Delivery |
| --- | --- |
| `<profile>.antigravity.policy.json` | Protected machine rules: `/etc/agent-edict/antigravity-policy.json` on Linux and macOS; `C:\ProgramData\AgentEdict\antigravity-policy.json` on Windows. |
| `<profile>.antigravity.hooks.json` | Named hook registration template. The endpoint stores it in its protected management directory; it must then be registered in each user's global hooks file. |

After the endpoint has installed the native artifacts and the protected executable, run this command **as the user who runs Antigravity**:

```sh
edict install-hook antigravity
```

This merges the `agent-edict` entry into the current user's `~/.gemini/config/hooks.json`, preserving unrelated named hooks. Check the App's **Settings → Customizations → Hooks** view for the enabled entry. Installation of machine rules alone does not enroll existing or future users.

The registration uses the documented App schema:

```json
{
  "agent-edict": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "'/usr/local/bin/edict' hook antigravity -policy '/etc/agent-edict/antigravity-policy.json'",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The Windows template uses `C:\Program Files\AgentEdict\edict.exe`. The hook's stdout is exclusively the App's decision JSON; diagnostics go to stderr. Policy/input parse failures emit a native `deny` response and return an error.

## Decisions covered

- **Terminal:** exact, complete `CommandLine` plus the canonical `Cwd`. Prefixes, globs, additional arguments, compound suffixes, unknown argument fields, and control characters do not match. `RequestedTerminalID` and persistent command mode are denied because an existing interactive shell or long-lived task is outside the rule's assumptions.
- **Files:** explicitly enabled `view_file`, `list_dir`, `find_by_name`, and `grep_search` use `read_roots`; `write_to_file`, `replace_file_content`, and `multi_replace_file_content` use `write_roots`. Existing symlinks and existing parent directories are resolved before testing containment. Claimed `workspacePaths` in the payload never grant access.
- **URLs:** `read_url_content` requires an exact configured HTTPS origin, including an explicit port if present. Credentials, non-HTTPS URLs, and fragments are rejected. Paths and queries on an allowed origin are permitted.
- **Other built-ins:** `ask_question` and `list_permissions` can be explicitly enabled. `search_web` can be enabled, but doing so permits its search request without a destination allowlist; `https_origins` does not constrain that tool.
- **MCP and unrecognized tools:** denied. The documented payload does not provide a verified MCP server endpoint or launch identity, so this adapter does not claim to authorize a specific MCP server by a tool-name prefix. MCP initialization and connections can happen before tool calls and remain outside this control.

## Limits and endpoint verification

1. Users can disable the registration, edit their user configuration, use another configuration root, or run another client. Workspace hook precedence, hooks that rewrite arguments, and whether every execution path invokes `PreToolUse` must be checked in the installed client. Protecting the rules file does not resolve these application behaviors.
2. A hook decision is a preflight check. It does not hold a filesystem handle across the App's operation, so concurrent symlink changes can race the check. Directory enumeration or search behavior is implemented by the App. Exact terminal text does not bind the executable, `PATH`, aliases, project scripts, environment, child processes, or network behavior. An allowed URL may redirect. OS containment is required for those boundaries.
3. The vendor documents a timeout but does not establish fail-closed behavior for command startup errors, timeouts, or invalid hook output. AgentEdict's evaluator denies parse errors when it runs; this does not prove the App denies when the executable cannot run. Do not infer that a successful file installation proves effective enforcement.
4. Automated tests cover native artifact structure, supported OS paths, documented input/output, exact command decisions, prompting, canonical roots, symlink escapes, URL origins, unknown tools, and malformed JSON. Static inspection of the official App 2.23.1 Linux archive corroborated the named-hook schema and hook input contract. No logged-in App session was exercised as part of these tests.

Before rollout and after upgrades, check actual allow/prompt/deny behavior, unknown and MCP calls, malformed input, an unavailable hook executable, timeout handling, competing workspace hooks, and Windows command invocation where applicable. Record the App version and whether the registration is enabled. A free local hook should be presented as a guardrail until mandatory registration and bypass prevention are established separately.

## Vendor contracts

- [Antigravity hooks: paths, named hook registration, tool schemas, and PreToolUse decisions](https://antigravity.google/docs/hooks)
- [Antigravity settings](https://antigravity.google/docs/settings)
- [Antigravity permissions](https://antigravity.google/docs/permissions)
- [Antigravity MCP configuration](https://antigravity.google/docs/mcp)
- [Official application downloads](https://antigravity.google/download)
