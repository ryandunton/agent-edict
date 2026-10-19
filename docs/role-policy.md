# Role-based policies (version 2 maps)

A version 2 policy map lets one signed bundle carry a **standard** policy for everyone plus **group policies** where some users need a different setup. Each machine works out, from who is logged in, which policy each managed agent gets, then installs and locks those files.

Version 1 maps (`machine_profile`) keep working exactly as before. A machine follows whichever version its signed bundle carries.

To build a map, or the profiles it names, without writing YAML by hand, use the [configuration builder](https://agent-edict.com/builder/). Its **Policy map** tab checks the map with the same code as `edict compile-bundle` and explains each Windows group entry as you type it.

## The map

```yaml
version: 2
managed_agents: [codex, claude, cursor]
sync_wsl: false
standard:
  profile: standard
  priority: 100
rules:
  - priority: 10
    profile: contractor-readonly
    agents: [codex]
    match_groups:
      windows: ['S-1-5-21-1111111111-2222222222-3333333333-1104', 'entra:3f2a8c1e-5b7d-4e2a-9c1f-0a1b2c3d4e5f', '.\Contractors']
      linux: [contractors]
      darwin: [contractors]
  - priority: 11
    profile: contractor-claude
    agents: [claude]
    match_groups:
      windows: ['S-1-5-21-1111111111-2222222222-3333333333-1104', '.\Contractors']
      linux: [contractors]
      darwin: [contractors]
  - priority: 20
    profile: engineering
    agents: [all]
    match_groups:
      windows: ['CORP\SG-Engineers']
      linux: [engineers]
      darwin: [engineers]
```

The full working example is in [`examples/role-policy/`](../examples/role-policy/).

- **`managed_agents`** lists the agents AgentEdict manages. Agents not listed are never touched.
- **`standard`** applies to every managed agent whenever no matching rule covers that agent. It competes at its own priority.
- **Each rule** names a profile, the agents it covers (`[all]` means every managed agent), and the groups it matches on each OS.
- **Priorities are unique** whole numbers from 1 up, and the lowest number wins. A missing `priority:` is an error. AgentEdict does not judge which policy is stricter: you decide by ordering them.
- `sync_wsl: true` is rejected in version 2.

### Group names

| OS | Write a group as | Notes |
| --- | --- | --- |
| Linux, macOS | `contractors` or a numeric GID | Matched exactly. |
| Windows | `S-1-5-21-…` | Recommended for domain groups. It comes from the login token, so no network is needed. |
| Windows | `entra:<object-id>` | An Entra ID group; converted to its `S-1-12-1-…` SID. |
| Windows | `.\Contractors` | A local group on the machine itself, on any machine. Built-in groups are `BUILTIN\Name`. |
| Windows | `CORP\SG-Engineers` | A domain group by name. Names need a domain controller to translate; see [When files change](#when-files-change). |

Windows matching ignores case.

## Which policy each agent gets

AgentEdict decides each agent separately:

1. For each logged-in user, it takes the matching rule with the lowest priority among the rules that cover this agent. If none matches, that user's candidate is the standard.
2. The agent gets the lowest-priority candidate across all logged-in users.

With the map above, an engineer and a contractor logged in together give:

- **Codex**: contractor-readonly (10 beats engineering's 20).
- **Claude**: contractor-claude (11 beats 20).
- **Cursor**: engineering (the contractor rules don't cover Cursor, so the contractor's candidate is the standard at 100, and engineering's 20 wins).

Without the priority-11 rule, the contractor's Claude candidate would be the standard (100), and Claude would get engineering. **Policy files are machine-wide**, so whichever policy wins applies to everyone on the machine. Rank the standard above engineering if a standard user sharing a machine must never get engineering.

A rule that names an agent its profile can't enforce fails at publish time, and nothing is signed. The error names the setting and the agent. AgentEdict never installs a weaker or partial file in its place.

## When files change

AgentEdict only writes, locks, copies and removes files. It never blocks logins, delays agents, or stops or restarts them.

- **Proof.** Only a complete, successful listing of at least one logged-in user, with everyone's groups resolved, can change which policy an agent gets.
- **No proof means no change.** Nobody logged in, the login screen showing, a failed listing, or one user's failed group lookup all keep what's installed, and AgentEdict retries.
- **First start.** With nothing saved yet, every managed agent gets the standard.
- **Who counts.**
  - **Windows** counts every session with a user, including disconnected ones.
  - **Linux** counts user sessions from `logind`, desktop or SSH. Root, login screens and background sessions are excluded. A machine without `logind` never has proof, so it keeps the standard.
  - **macOS** uses the console user; Macs are assumed to be single-user. The login window and system accounts, such as Setup Assistant's, don't count.
- **Windows group names.** If a rule uses a `DOMAIN\Name` group and Windows can't translate one of the user's Active Directory groups, for example offline, that look is not proof. SID and `entra:` rules have no such dependency, and Entra groups never need translating.
- **A new bundle while nobody is logged in** is applied to the last users AgentEdict saw. Your rule and profile changes still land without anyone signing in.
- **Timing.**
  - Every 30 seconds (`-session-interval`), AgentEdict checks who is logged in. That check makes no network calls.
  - Group lookups run only when the set of logged-in users changes, on every bundle check (15 minutes by default, `-interval`), and on Windows session events. A group membership change is therefore picked up within the bundle interval.
- **Running agents** keep the settings they loaded at startup. A switch takes effect the next time the agent starts.

The vault keeps the last proven users, each agent's assignment, and the installed file hashes in `role-state.json`. These survive reboots.

## Taking over and releasing files

- **First takeover.** If a file AgentEdict didn't write is already at a target, AgentEdict copies it into the vault (`originals/`) before replacing it. Status lists the copy. Files installed by version 1 count as AgentEdict's and are not copied.
- **Dropping an agent from `managed_agents`.**
  - Hook registrations go first: Cursor's `hooks.json` and both Windsurf `hooks.json` files.
  - Antigravity and Cline get a fixed "released" policy that allows every action. Their per-user hooks, registered in users' home folders, would otherwise block every action.
  - The agent's other files are unlocked and deleted, and empty folders AgentEdict created for it are removed.
  - Nothing is restored automatically. Saved originals stay in the vault for manual recovery.
- **Moving from version 1 to version 2.** Agents that the version 1 bundle managed and the new map leaves out are released in the same way.
- **Role switches never drop an agent.** They only replace file contents.
- **Uninstall** is unchanged: hook registrations are always removed, and policy files only with `--purge-data`.

## Claude's sandbox

Claude's file tools follow `Read(...)` deny rules, but shell commands don't. Blocking `cat ~/.ssh/id_rsa` needs Claude Code's own OS sandbox, which runs on macOS and Linux. Native Windows has none.

A profile that covers Claude and uses `filesystem.deny_read`, or turns command networking off, must choose:

```yaml
claude:
  sandbox:
    unix: required      # macOS and Linux
    windows: tools-only # native Windows has no Claude sandbox
```

| Choice | Machine | Result |
| --- | --- | --- |
| `required` | macOS | Installed and fully enforced; the sandbox is built in. |
| `required` | Linux with `bubblewrap` and `socat` | Installed and fully enforced. |
| `required` | Linux missing either | Claude's file is not installed; the previous one stays, Claude starts as before, and status names the missing packages. It installs within 30 seconds of both appearing. AgentEdict never installs packages. |
| `required` | Windows | Publishing fails. |
| `tools-only` | Any | Installed. Claude's tools can't read the paths, but shell commands can. Publishing and status list each such setting. |

`required` also confines Claude's shell commands:

- Writes are limited to the project and temp folders.
- Shell network traffic goes through Claude's proxy:
  - With networking on, each new host prompts, and tools that ignore proxy settings, such as plain `ssh`, can't connect.
  - With networking off, the allowed-host list is empty and locked.
- If `bubblewrap` or `socat` is removed after install, Claude itself refuses to start (`failIfUnavailable`).

Absolute deny paths are written in Claude's absolute form: `/etc/shadow` becomes `Read(//etc/shadow/**)`. A single leading slash would be relative to the settings file.

## Publish

```bash
edict compile-bundle -map examples/role-policy/policy-map.yaml \
  -profiles-dir examples/role-policy/profiles -target-os all -output-dir dist
edict validate-bundle -dir dist -target-os all
tar -czf policy-bundle.tar.gz -C dist policy-map.yaml profiles
```

- **What gets compiled.** `compile-bundle` compiles every profile-agent pair the map can select, for every OS, including rules nobody currently matches.
- **Where sources come from.** Unified agents (Codex, Claude, OpenCode) read `<profile>.yaml`. Native agents read `<profile>.native.yaml` from the same directory.
- **All or nothing.** Nothing is written unless everything compiles, and the output directory must be new or empty so an earlier bundle's files can't be signed with this one.
- **Validation.** `validate-bundle` checks every pair's files and exact native bytes before signing, and endpoints check them again before activating.
- **CI.** The pipeline signs the repository's `policy-map.yaml` with `profiles/` this way (`POLICY_BUILD_MODE: bundle`). Point `POLICY_MAP_FILE` and `POLICY_SOURCE` at your own map and profiles to sign those instead.

## Status

`edict status` on a version 2 machine shows:

- each agent's profile, rule priority and state;
- the last proof time;
- released agents and saved originals;
- settings Claude enforces only in its own tools.

Usernames appear only when status runs as root or Administrator.

`edict status` exits 1 unless every required file is verified, so compliance tools can detect incomplete machines. When some agents are skipped (for example, `bubblewrap` is missing), the service keeps running and retries them, and `sync-once` prints a warning but exits 0, so the installers still finish. `consumer_verification` stays `not_performed`: installed files are not proof that a running agent enforces them.

## Limits

- One policy per agent per machine, applied to everyone logged in.
- Accounts that run programs without logging in aren't counted: scheduled tasks, cron jobs, background services, and probably Windows SSH logons and `runas`.
- Detection takes up to 30 seconds (faster on Windows), and running agents keep their loaded settings.
- Switches across several product folders are not atomic. A failure shows as incomplete and is retried.
- macOS counts the console user only.
- With `tools-only`, Claude's shell commands are not covered.
- Replaying an older signed bundle is not prevented.
- On Linux the installer still pre-creates every product folder, because the systemd sandbox keeps `/etc` read-only for the service.

Before rolling out widely, run the [pilot checklist](plans/2026-10-16-session-role-policy-pilot-checklist.md) on real machines.
