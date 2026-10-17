# Deploy from GitLab

GitLab runs `.gitlab-ci.yml`, which is already in this repository. On every merge request it tests the agent and validates your policies. On every push to `main` it also signs the bundle and publishes it to the project's package registry. Machines download it with a deploy token that can only read that registry.

Read [Deploying AgentEdict](README.md) first. It covers the policy files, the signing key, building the agent and installing it, which are the same on every host.

## Quick setup on gitlab.com

`scripts/setup-gitlab.sh` does the setup in one run:

```bash
GITLAB_TOKEN=<token with the api scope> ./scripts/setup-gitlab.sh "" <group-or-username>
```

It asks for the token if you leave `GITLAB_TOKEN` unset, and never prints it. In order, it:

1. Checks the token.
2. Creates an Ed25519 key pair in `keys/`, or reuses one already there.
3. Puts the public key into `cmd/edict/main.go`.
4. Creates a private project called `agent-edict` in the namespace, if it doesn't exist.
5. Commits this folder and pushes it to the project.
6. Saves the private key as the protected CI variable `EDICT_SIGNING_PRIVATE_KEY`.
7. Creates a deploy token limited to `read_package_registry` and saves it as `keys/agent-edict-deploy-token-<date and time>`. Then it starts the first pipeline and prints the install commands for Windows, Linux and macOS.

Then:

- Move `keys/agent-edict-signing-key.pem` into your secret store and delete it from the folder. See [step 2 of the deployment guide](README.md#2-create-the-signing-key).
- Move the deploy-token file the same way. It's the file your machines need.
- Build the agent with `make build`. The script has already put your public key into the source.

The script talks to gitlab.com only. For a self-managed GitLab instance, follow the manual steps below.

## Manual setup

### 1. Create the project

Create a private project and push this repository to it. Keep `main` as the default branch and leave it protected, which is GitLab's default: the signing variable is only given to protected branches.

### 2. Add the signing key

In **Settings → CI/CD → Variables**, add:

| Key | Value | Settings |
| --- | --- | --- |
| `EDICT_SIGNING_PRIVATE_KEY` | The one-line Base64 of your private key | **Protected** on. **Masked** on if GitLab accepts the value; the job never prints it either way. |

### 3. Check the pipeline settings

The top of `.gitlab-ci.yml` has these variables. The defaults fit this repository's layout:

| Variable | Default | Meaning |
| --- | --- | --- |
| `POLICY_BUILD_MODE` | `bundle` | Compile a version 2 policy map and every profile it can select. |
| `POLICY_MAP_FILE` | `policy-map.yaml` | The map. |
| `POLICY_SOURCE` | `profiles/` | The folder of profiles. |

### 4. Create the machine token

In **Settings → Repository → Deploy tokens**, create a token with only the `read_package_registry` scope. Give it an expiry date if your policy requires one. Copy the token into a file once, for example `agentedict-token`; GitLab shows it only once.

### 5. Publish the first bundle

Push to `main`, or run a pipeline on it. These jobs matter for policy:

| Job | Runs on | What it does |
| --- | --- | --- |
| `verify-code` | Merge requests and `main` | Tests the agent and builds it for every platform. |
| `validate-policies` | Merge requests and `main` | Compiles and validates every policy the map can select, for every OS. |
| `validate-role-example` | Merge requests and `main` | Checks the role policy example in `examples/`. |
| `sign-bundle` | `main` only | Builds the bundle again, validates it, and signs it with `EDICT_SIGNING_PRIVATE_KEY`. |
| `publish-registry` | `main` only | Uploads the bundle and signature to the package registry, as version `1.0.<pipeline number>` and again as `latest`. |


When the pipeline finishes, **Deploy → Package registry** lists `agent-edict-bundle` with the new version and `latest`.

### 6. Install on machines

The bundle URL is:

```
https://<gitlab-host>/api/v4/projects/<project-id>/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz
```

The project ID is on the project's overview page. Install with the token file from step 4, as described in [step 4 of the deployment guide](README.md#4-install-on-every-machine):

```bash
sudo ./scripts/install-agent.sh \
  "https://gitlab.example.com/api/v4/projects/123/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" \
  --deploy-token-file /secure/agentedict-token
```

## Day to day

- **Changing policy:** open a merge request. `validate-policies` shows whether every profile still compiles for every agent and OS. Merge it, and machines pick up the new `latest` at their next sync.
- **Going back:** revert the commit on `main`. The pipeline signs and publishes the reverted files as a new `latest`.
- **History:** every publish stays in the package registry under its own version number, alongside `latest`.

## Notes

- The agent sends a deploy token in GitLab's `Deploy-Token` header. A personal access token (`glpat-…`) also works, in the `PRIVATE-TOKEN` header, but it can do far more than read one registry, so use a deploy token.
- Anyone who can publish to the project's package registry, which in GitLab means the Developer role and above, could replace `latest` with an older signed bundle. Give that role only to people you'd trust to publish policy; see [security notes](README.md#security-notes).
