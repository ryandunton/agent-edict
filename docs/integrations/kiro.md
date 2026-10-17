# Kiro local management

AgentEdict writes Kiro's **enterprise permission policies**: admin `rules` in a protected `managed-settings.json` that both Kiro IDE and Kiro CLI read. The schema follows Kiro's [permission policies](https://kiro.dev/docs/enterprise/governance/permissions/), [permissions](https://kiro.dev/docs/permissions/), and [sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/) documentation, reviewed October 2026.

## What is supported

Admin rules can only **deny** or **ask**; they can restrict access but never grant it. When admin and user rules target the same capability, the stricter effect wins (`deny > ask > allow`), an admin `ask` always prompts, and a policy preset `allow` never overrides an admin rule. Compound shell commands (`;`, `&&`, `||`, `|`) are split and each sub-command is evaluated.

| Field | Values |
|---|---|
| `capability` | `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`, `skill`, `power`, `context`, `diagnostics`, `sandbox_network`, the meta-capabilities `all`, `builtin`, `filesystem`, and `signin_method` |
| `match`, `exclude` | Optional globs. Shell globs support only `*`, so the compiler rejects `**`, `?` and character classes there. Excluded resources fall through to the user's own permissions. |
| `effect` | `deny` or `ask` (`signin_method`: `deny` only) |

`signin_method` rules name methods (`idc`, `external_idp`, `builder_id`, `google`, `github`, `social`), at most 16 per rule, and apply to Kiro IDE 1.2 and Kiro CLI 2.25.0 or later. `signin_help_url` adds a help link.

## Native profile

```yaml
version: 1
name: kiro-guardrails
kiro:
  rules:
    - capability: shell
      match: ["rm *", "sudo *"]
      effect: deny
    - capability: fs_write
      match: ["~/**"]
      exclude: ["~/.kiro/**"]
      effect: ask
    - capability: web_fetch
      effect: deny
    - capability: signin_method
      match: [github]
      effect: deny
  signin_help_url: "https://it.example.com/help"
```

## Files

The compiler emits `<profile>.kiro.json`:

| Platform | Path |
|---|---|
| Linux | `/etc/kiro/managed-settings.json` |
| macOS | `/Library/Application Support/Kiro/managed-settings.json` |
| Windows | `C:\ProgramData\Kiro\managed-settings.json` |

Kiro rejects the entire file when a rule has an unknown field, so the compiler emits only the documented fields and always includes `rules`. A malformed file is reported to make Kiro deny all tool calls. Restart Kiro after an update.

## Verification boundary

Policies are enforced by the Kiro client and can be circumvented by users with administrative access. Compiler tests check the emitted schema, paths, and rejection of rules Kiro cannot honor. No Kiro client was launched; Kiro CLI's handling of this file in particular has not been independently verified. Before rollout, confirm in each version that a denied shell pattern blocks with a user `allow` rule present and that an admin `ask` still prompts.
