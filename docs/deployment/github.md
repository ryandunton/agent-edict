# Deploy from GitHub

GitHub Actions runs `.github/workflows/agentedict.yml`, which is already in this repository. On every pull request it tests the agent and validates your policies. On every push to `main` it also signs the bundle and commits it to a second private repository. Machines download it from there through GitHub's API, with a token that can only read that repository.

Read [Deploying AgentEdict](README.md) first. It covers the policy files, the signing key, building the agent and installing it, which are the same on every host.

## Why a second repository

- **Least access for machines.** The machine token can read the bundle repository and nothing else, not your policy history or pull requests.
- **A fixed address.** The agent needs a bundle URL without a query string, so it can't ask for a branch. The bundle sits on the bundle repository's default branch, which the API serves by default.
- **No redirects.** GitHub release downloads redirect to a separate download host, which the agent refuses. The contents API returns the file itself.

## 1. Create the two repositories

- **The policy repository:** a private repository holding this code. Import or push this repository into it.
- **The bundle repository,** for example `agentedict-bundles`: private, and created **with a README** so it has a `main` branch for the workflow to push to.

Both should belong to your organization rather than to a person.

## 2. Create the publish token

The workflow pushes to the bundle repository with a fine-grained personal access token. Create it under **Settings → Developer settings → Personal access tokens → Fine-grained tokens**, ideally signed in as a dedicated machine account rather than a person, so it keeps working when someone leaves:

| Setting | Value |
| --- | --- |
| Resource owner | Your organization |
| Repository access | Only select repositories: the bundle repository |
| Repository permissions | Contents: **Read and write** |
| Expiration | The longest your organization allows; note the date |

Your organization may require an owner to approve fine-grained tokens before they work.

## 3. Add the signing key and publish token

In the policy repository, open **Settings → Environments** and create an environment called `policy-signing`:

- **Deployment branches and tags:** selected branches only, `main`.
- **Required reviewers (optional):** add people here, and every publish waits for one of them to approve it. This gives you two-person publishing.
- **Environment secrets:**

| Name | Value |
| --- | --- |
| `EDICT_SIGNING_PRIVATE_KEY` | The one-line Base64 of your private key, from [step 2 of the deployment guide](README.md#2-create-the-signing-key) |
| `AGENTEDICT_BUNDLE_PUBLISH_TOKEN` | The token from step 2 |

Environments in private repositories need GitHub Team for organizations, or GitHub Pro for personal accounts. On GitHub Free, add the two values as repository secrets under **Settings → Secrets and variables → Actions** instead, and delete the `environment: policy-signing` line from the workflow. The workflow then works the same way, but without the branch restriction or approvals.

## 4. Tell the workflow where to publish

Under **Settings → Secrets and variables → Actions → Variables**, add a repository variable:

| Name | Value |
| --- | --- |
| `AGENTEDICT_BUNDLE_REPO` | `<owner>/agentedict-bundles` |

Until this variable exists, the workflow only runs its checks and skips publishing. That way a copy of this repository on GitHub, such as a mirror, never tries to sign anything.

## 5. Create the machine token

Machines need a second fine-grained token that can only read:

| Setting | Value |
| --- | --- |
| Resource owner | Your organization |
| Repository access | Only select repositories: the bundle repository |
| Repository permissions | Contents: **Read-only** |
| Expiration | The longest your organization allows; you'll replace it on every machine before then |

Use the same machine account, or a second one if you need more machines than one account's [rate limit](#rate-limits) allows. Save the token in a file, for example `agentedict-token`, and copy it to machines through your secret-management process.

## 6. Publish the first bundle

Push to `main`, or run it by hand from **Actions → AgentEdict policy → Run workflow** on `main`. The workflow runs two jobs:

| Job | Runs on | What it does |
| --- | --- | --- |
| `verify` | Pull requests and `main` | Checks dependencies, tests the agent, then compiles and validates every policy the map can select, for every OS. |
| `publish` | `main` (pushes and manual runs), once `AGENTEDICT_BUNDLE_REPO` is set | Builds and validates the bundle again, signs it, and commits `policy-bundle.tar.gz` and `policy-bundle.tar.gz.sig` to the bundle repository. Waits for approval first if the environment has required reviewers. |

When it finishes, the bundle repository has a commit called "Publish policy bundle from …" with both files.

## 7. Install on machines

The bundle URL is:

```
https://api.github.com/repos/<owner>/agentedict-bundles/contents/policy-bundle.tar.gz
```

On GitHub Enterprise Server, use `https://<your-host>/api/v3/repos/<owner>/agentedict-bundles/contents/policy-bundle.tar.gz`.

Install with the token file from step 5, as described in [step 4 of the deployment guide](README.md#4-install-on-every-machine):

```bash
sudo ./scripts/install-agent.sh \
  "https://api.github.com/repos/example-org/agentedict-bundles/contents/policy-bundle.tar.gz" \
  --deploy-token-file /secure/agentedict-token
```

The agent recognizes a GitHub token by its `github_pat_` or `ghp_` prefix. It sends the token as `Authorization: Bearer` with GitHub's raw media type, so the API returns the file itself.

## Rate limits

Each sync is two API requests, one for the bundle and one for its signature. GitHub allows 5,000 requests an hour for each account that owns tokens, shared across all of that account's tokens:

| Sync interval | Machines per account |
| --- | --- |
| 15 minutes (the default) | about 625 |
| 30 minutes | about 1,250 |
| 60 minutes | about 2,500 |

Past the limit, GitHub answers with a 403 or 429. The agent keeps its last verified policy and tries again at the next interval, so nothing breaks, but updates arrive later. For a bigger fleet:

- Sync less often. Pass `-SyncIntervalMinutes` to the Windows installer, or `--sync-interval-minutes` to the Linux and macOS installer.
- Use one machine account, and so one machine token, per group of machines.
- Or publish the bundle somewhere without a per-account limit, such as GitLab's package registry or your own HTTPS server.

## Day to day

- **Changing policy:** open a pull request. The `verify` job shows whether every profile still compiles for every agent and OS. Merge it, and machines pick up the new bundle at their next sync.
- **Going back:** revert the commit in the policy repository. The workflow signs and publishes the reverted files as a new commit in the bundle repository.
- **History:** every publish is a commit in the bundle repository, linked to the policy commit it came from.

## Notes

- Keep write access to the bundle repository limited to the publish token. Anyone who can push there could put back an older signed bundle; see [security notes](README.md#security-notes).
- A classic personal access token (`ghp_…`) also works, but it reaches every repository its owner can, so use a fine-grained token.
- `.github/workflows/ci.yml` and `pages.yml` are for the AgentEdict project itself. In your policy repository, `ci.yml` runs the agent's own tests, and `pages.yml` does nothing because it only runs in `ryandunton/agent-edict`. You can delete both.
- The workflow runs in the `golang:1.27.2` container and installs only `openssl`. It uses `actions/checkout@v4`; to pin it, replace the tag with the commit SHA of the release you've reviewed.
- Bundles are small, around 13 KB for the example policies. The contents API serves files up to 100 MB.
