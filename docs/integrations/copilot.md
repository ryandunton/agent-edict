# GitHub Copilot local management

AgentEdict writes GitHub Copilot's **file-based enterprise managed settings**: a root-owned `managed-settings.json` that Copilot clients load at startup. The schema follows GitHub's [enterprise managed settings reference](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings) and [deployment guide](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings), reviewed October 2026.

## What is supported

| Control | Managed key | Scope |
|---|---|---|
| Allow, ask, deny tool rules | `permissions.allow`, `ask`, `deny` | Composed `deny > ask > allow` across every managed source. A managed `ask` cannot be satisfied by bypass mode, auto-approval, hooks, or stored grants. |
| Bypass mode | `permissions.disableBypassPermissionsMode: "disable"` | Blocks `--yolo`, `--allow-all`, `/yolo` and `/allow-all`. **Open issue [github/copilot-cli#4528](https://github.com/github/copilot-cli/issues/4528) reports that non-interactive `-p` sessions still bypass it.** |
| MCP servers | `allowedMcpServers`, `deniedMcpServers` | Match an exact `serverName`, a `serverUrl` pattern, or an exact `serverCommand`. Deny wins; an empty allowlist blocks every non-built-in server. First-party servers such as the GitHub MCP server cannot be blocked. Server names are user-chosen labels. |
| Copilot sandbox | `sandbox.enabled`, `failIfUnavailable`, `allowBypass` | Copilot enforces its own sandbox; AgentEdict only manages the setting. Requires Copilot CLI 1.0.93, VS Code 1.141.0, or the GitHub Copilot app 1.1.26; older clients are blocked from connecting once `sandbox` is set. |
| Computer use | `features.computerUse: false` | Stops users from enabling computer use. |

Bypass mode is disabled by default. Rule strings must use Copilot's selectors: `Shell(...)` (with `Bash(...)` and `PowerShell(...)` aliases), `Read(...)`, `Edit(...)` / `Write(...)`, or `Domain(...)`. A rule cannot appear in two lists.

## Native profile

```yaml
version: 1
name: copilot-guardrails
copilot:
  permissions:
    allow: ["Shell(npm test *)"]
    ask: ["Shell(git push *)"]
    deny: ["Shell(rm -rf *)", "Read(~/.ssh/**)"]
  mcp:
    allowed:                                   # omit for no allowlist; [] blocks all
      - url: "https://api.githubcopilot.com/*"
      - command: ["npx", "@playwright/mcp@latest"]
    denied:
      - name: filesystem
  sandbox:
    enabled: true
    fail_if_unavailable: true
    allow_bypass: false
  computer_use: false
```

## Files

The compiler emits `<profile>.copilot.json`, installed at GitHub's file-based location:

| Platform | Path |
|---|---|
| Linux | `/etc/github-copilot/managed-settings.json` |
| macOS | `/Library/Application Support/GitHubCopilot/managed-settings.json` |
| Windows | `C:\Program Files\GitHubCopilot\managed-settings.json` |

Copilot CLI rejects the file on macOS and Linux unless it is a regular, root-owned file that is not group- or world-writable and not a symlink; AgentEdict installs it root-owned, mode 0644, and immutable. Restart clients after an update.

## Bypass boundaries

- MDM-managed and server-managed settings take precedence over this file for most keys; `permissions` and `sandbox` compose in the most restrictive direction across all sources.
- Key support varies by client (CLI, VS Code, JetBrains, Copilot app). Check GitHub's supported-keys table for each client you rely on.
- Local administrators can change or remove the file.

## Verification boundary

Compiler tests check the exact JSON keys, all three paths, selector and matcher validation, the documented defaults, and that an empty MCP allowlist survives the signed bundle round trip. No Copilot client was launched. Before rollout, confirm in each client version that a denied shell rule blocks, a managed `ask` prompts under `--allow-all`, and an unlisted MCP server does not start.
