# Knowledge-worker Codex gateway

`profiles/knowledge-worker.yaml` selects the Codex gateway for this profile:

These are public example values. Keep them in this repository. For a real deployment, copy the profile and policy map to a private policy source and set the approved host and model alias there. Never commit those values to this public repository.

```yaml
model_provider: company-gateway
codex_model: company-coding-model
model_providers:
  company-gateway:
    name: Company AI Gateway
    base_url: https://aigateway.internal.company.com/v1
    wire_api: responses
    env_key: AI_GATEWAY_API_KEY
    requires_openai_auth: false
```

AgentEdict compiles these fields into `knowledge-worker.codex.toml` in the bundle and installs the selected profile at `C:\ProgramData\OpenAI\Codex\requirements.toml` on Windows or `/etc/codex/requirements.toml` on Linux and macOS. The relevant managed settings are:

```toml
model_provider = "company-gateway"

[model_providers.company-gateway]
name = "Company AI Gateway"
base_url = "https://aigateway.internal.company.com/v1"
wire_api = "responses"
env_key = "AI_GATEWAY_API_KEY"
requires_openai_auth = false

[models.new_thread]
model = "company-coding-model"
```

The provider is enforced by Codex requirements. The model is a default for new threads; an explicit client model or reasoning override can replace it. Restrict permitted aliases at the gateway if the alias must be mandatory. Other AgentEdict sandbox, approval, filesystem, and browser controls remain in the generated requirements file.

Deliver a scoped gateway credential to each user's Codex process through a client-side secret manager or a managed launcher that sets `AI_GATEWAY_API_KEY` in that process environment. The AgentEdict daemon does not read, copy, or install it. A terminal environment variable may not reach a desktop app launched separately. Do not put the credential in the profile, repository, bundle, requirements file, or logs.

The custom alias needs matching Codex model catalog metadata for reliable reasoning, context, and tool behavior. The gateway team must supply a compatible catalog file and distribute it with a top-level `model_catalog_json` setting in a Codex config layer; no catalog metadata was supplied here. A remote `model_catalog_url` would have to be added to this managed provider definition because Codex replaces the entire user provider with the managed one. Verify gateway support for streamed `POST /v1/responses`, function calls and outputs, and the alias route with a real Codex turn before deployment. AgentEdict's bundle validator checks required files, TOML syntax, and supported gateway fields, but not live client acceptance or gateway behavior.

Claude Code remains on its existing model route in this public example. AgentEdict can compile a separate Claude Code CLI gateway when a private profile supplies an Anthropic-compatible Messages endpoint and a client-side credential variable. Codex's Responses alias cannot be reused without an actual Claude route. See [gateway support by client](gateway-support.md) for Claude, OpenCode, and the native adapter limits.
