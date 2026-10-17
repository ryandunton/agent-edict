# Deploying AgentEdict

A deployment has two halves:

- **A pipeline** in your Git host turns your policy files into one bundle, checks it, signs it with your private key, and publishes it.
- **An agent** on every machine downloads the bundle, checks the signature against your public key, and installs each AI tool's files. It checks again on a schedule and repairs any file someone edited or deleted.

```
policy repository ──▶ pipeline: compile, validate, sign ──▶ bundle host
                                                                 │
every machine: edict service ◀── HTTPS + read-only token ───────┘
```

This page covers the steps that are the same everywhere. The host-specific guides cover the pipeline and the machines' download token:

- [Deploy from GitLab](gitlab.md)
- [Deploy from GitHub](github.md)

## Choose a host

| | GitLab | GitHub |
| --- | --- | --- |
| Pipeline | `.gitlab-ci.yml` in this repository | `.github/workflows/agentedict.yml` in this repository |
| Where the bundle lives | The project's package registry, under the `latest` version | The default branch of a second, private repository |
| Machine token | A deploy token with only `read_package_registry` | A fine-grained token with read-only access to that repository's contents |
| Setup | `scripts/setup-gitlab.sh` does most of it on gitlab.com | About ten manual steps |
| Fleet size | No practical limit | About 625 machines per token-owning account at the default 15-minute sync; see [rate limits](github.md#rate-limits) |

Any other HTTPS server works too. The agent downloads `<bundle-url>` and `<bundle-url>.sig`, with no token, a GitLab token or a GitHub token. The URL can't contain a query string, and the agent refuses redirects to a different host.

## 1. Write your policies

Policies live in this repository:

- `profiles/` holds one file per profile: `<name>.yaml` for Codex, Claude Code and OpenCode, and `<name>.native.yaml` for the other seven tools.
- `policy-map.yaml` says which profile each managed agent gets, a standard for everyone plus group rules. See the [role policy guide](../role-policy.md).

The [configuration builder](https://ryandunton.github.io/agent-edict/builder/) builds and checks these files in the browser. To check them locally the same way the pipeline does:

```bash
go build -o bin/edict ./cmd/edict
./bin/edict compile-bundle -map policy-map.yaml -profiles-dir profiles -target-os all -output-dir dist
./bin/edict validate-bundle -dir dist -target-os all
```

## 2. Create the signing key

The pipeline signs every bundle with an Ed25519 private key, and machines install only bundles signed by it. Create it outside this repository, and outside any folder that syncs to a cloud drive such as OneDrive, Dropbox or iCloud:

```bash
umask 077
mkdir -p ~/agentedict-keys
openssl genpkey -algorithm ED25519 -out ~/agentedict-keys/signing-key.pem
openssl pkey -in ~/agentedict-keys/signing-key.pem -pubout -out ~/agentedict-keys/public-key.pem
```

The `openssl` that ships with macOS is LibreSSL, which can't create Ed25519 keys. Use OpenSSL 3 instead: `brew install openssl@3`, then run the commands with `"$(brew --prefix openssl@3)/bin/openssl"`. Or run them on a Linux machine. `scripts/gen-keys.sh` has the same requirement.

The pipeline needs the private key as a single line of Base64:

```bash
base64 < ~/agentedict-keys/signing-key.pem | tr -d '\n'
```

Paste that into your host's CI secret (each guide says where). Keep one copy of the private key in your password manager or secret store, then delete the local file. Never commit it; `keys/` is in `.gitignore`, but a synced folder still copies it off the machine.

If you used `scripts/setup-gitlab.sh` or `scripts/gen-keys.sh`, they wrote the key to `keys/agent-edict-signing-key.pem` inside this repository. Move it to your secret store and delete it from the folder.

## 3. Build the agent with your public key

The agent trusts the public key compiled into it. Out of the box that's a placeholder, and an agent built with it refuses to sync until you set a real key. Open `cmd/edict/main.go`, find `defaultPublicKeyPEM`, and replace the placeholder between the backticks with the contents of `public-key.pem`, including the `BEGIN` and `END` lines. Then build:

```bash
make build
```

That gives you:

| File | For |
| --- | --- |
| `bin/edict.exe` | Windows, x64 |
| `bin/edict-linux` | Linux, x64 |
| `bin/edict-darwin-arm64` | macOS on Apple silicon |
| `bin/edict-darwin-amd64` | macOS on Intel |

There's no Linux ARM build yet. `setup-gitlab.sh` edits `defaultPublicKeyPEM` for you. Commit the change, since the key is public; it means every binary built from this repository trusts your key.

## 4. Install on every machine

Each machine needs three things: the binary for its platform, the bundle URL, and a file containing the read-only token. Copy the token file through your secret-management process or MDM; never pass the token itself on a command line. The option is called `deploy-token-file` for every host.

**Windows**, from an elevated PowerShell prompt:

```powershell
.\scripts\install-agent.ps1 `
  -BundleUrl "<bundle-url>" `
  -DeployTokenFile "C:\secure\agentedict-token" `
  -BinarySource ".\bin\edict.exe" `
  -SyncIntervalMinutes 15
```

**Linux and macOS**, as root. The installer picks the binary for the machine from `bin/` (the files `make build` made), so copy `scripts/` and `bin/` to the machine together. It installs the binary as `/usr/local/bin/edict` after checking that every folder above it is owned by root:

```bash
sudo ./scripts/install-agent.sh "<bundle-url>" \
  --deploy-token-file /secure/agentedict-token \
  --sync-interval-minutes 15
```

The sync interval is 15 minutes unless you set it, and can be anything from 1 to 1440 minutes. The installers copy the token into a protected folder, run a first sync, and register a service: a Windows service, systemd on Linux, or launchd on macOS.

To roll out with Intune, Jamf, Kandji or similar, package the binary, the token file and the installer, and run the installer as an administrator or root with the same arguments.

## 5. Check a machine

```bash
sudo edict status
```

On Windows, run `& "$env:ProgramFiles\AgentEdict\edict.exe" status` from an elevated prompt.

It shows each agent's policy and the rule that chose it, and each file and its protection. It ends with **FILES VERIFIED** or **INCOMPLETE**, and exits with a non-zero code unless everything is verified, so a compliance tool can alert on it.

## Changing policy

Edit the files, open a merge or pull request, and merge it to `main` once the checks pass. The pipeline signs and publishes the new bundle, and machines pick it up at their next sync. If a download or signature check fails, a machine keeps its last verified policy and tries again at the next interval.

## Replacing credentials

- **The machine token:** create a new token, copy its file to every machine, and run the installer again with the new file. Revoke the old token afterwards.
- **The signing key:** the agent trusts one key, compiled into it, and can't yet move to a new key by itself. Build new binaries with the new public key, install them on every machine, then put the new private key in the CI secret and publish. A machine still on the old binary rejects bundles signed with the new key, keeps its last policy, and logs a signature error until it's updated.

## Security notes

- The agent doesn't yet refuse a bundle older than the one it has. Anyone who can write to the bundle host could put back an older, correctly signed bundle, so keep write access to the bundle host limited to the pipeline.
- The machine token only reads. Even so, anyone who copies it can download your bundle, which contains every profile, internal server addresses and group names. Treat it as confidential.

## Troubleshooting

Logs: `journalctl -u agent-edict` on Linux, `/var/log/agent-edict.log` and `/var/log/agent-edict.err` on macOS, and `C:\ProgramData\AgentEdict\service.log` on Windows.

| Message | Cause |
| --- | --- |
| `bundle server returned HTTP 401` or `403` | The token is wrong, expired, revoked, or lacks read access to the bundle. On GitHub, a 403 can also mean the rate limit was reached. |
| `bundle server returned HTTP 404` | The bundle URL is wrong, or nothing has been published yet. |
| `Ed25519 signature verification failed` | The binary doesn't trust the key that signed the bundle. Check that you built it with your public key, and that the CI secret holds the matching private key. |
| `cross-origin bundle redirect rejected` | The host redirected to another domain. GitHub release downloads do this; use the method in the GitHub guide. |
| `bundle URL must be HTTPS with a host and no userinfo, query, or fragment` | Remove anything after `?` or `#`, and any `user:password@`. |
