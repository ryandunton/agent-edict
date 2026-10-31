# Model API gateways

AgentEdict routes a client only when its selected profile has a gateway section for that client and the client's managed configuration can express the route. `profiles/knowledge-worker.yaml` is a **public example**, not a list of all supported clients or a deployment policy. Keep actual endpoint names, model aliases, and credentials outside this public repository. The version 2 policy map decides which clients and profiles a bundle must contain; a compiled file alone does not prove the client used it.

| Client AgentEdict targets | Client gateway mechanism | AgentEdict coverage |
| --- | --- | --- |
| Codex | Managed `model_provider`, Responses API, and `env_key` | Compiles and validates `requirements.toml`; see [Codex example](codex-gateway.md). |
| Claude Code CLI | Managed `env.ANTHROPIC_BASE_URL` and `allowedProviders: ["customEndpoint"]`; credential supplied to the client as `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY` | Compiles and validates the gateway URL, provider pin, and optional initial `model` in `managed-settings.json`. The pin requires Claude Code v2.1.285 or later. Claude Desktop has a separate third-party inference configuration that AgentEdict does not generate. [Claude gateway routing](https://code.claude.com/docs/en/llm-gateway), [model configuration](https://code.claude.com/docs/en/model-config). |
| OpenCode v1 | Managed custom provider with `options.baseURL`, an environment-variable key reference, and a model | Compiles and validates `opencode.json`, allows only the managed provider, and uses its model for main and light tasks. Existing profiles with `filesystem.deny_read` still cannot be compiled for OpenCode. [Provider configuration](https://opencode.ai/docs/providers), [managed settings](https://opencode.ai/docs/config/). OpenCode v2 has a different provider schema and is not covered. |
| Gemini CLI | `GOOGLE_GEMINI_BASE_URL` in the client environment for Gemini API-key authentication | The current native adapter manages tool policy and system settings, but no documented managed base-URL setting. AgentEdict cannot guarantee delivery of this client environment variable. The endpoint must speak Gemini API, not Codex Responses. [Gemini CLI configuration](https://geminicli.com/docs/reference/configuration/). |
| GitHub Copilot CLI | `COPILOT_PROVIDER_*` environment variables or user `providers.json` | The managed-settings file AgentEdict installs has no provider URL key. `providers.json` stores credential values in plain text and does not expand `$ENV` references; AgentEdict does not generate it. [Copilot CLI configuration](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference). |
| Cline | User provider UI, or the enterprise hosted admin console for VS Code and JetBrains extensions | The local adapter manages hooks, not Cline's hosted provider configuration. That enterprise route requires Chat Completions. [Cline enterprise setup](https://docs.cline.bot/enterprise-solutions/configuration/remote-configuration/openai-compatible/admin-configuration). |
| Cursor | User BYOK “Override OpenAI Base URL” | The adapter manages hooks; no documented machine-managed route is generated. The override is shared, not per-model. [Cursor staff explanation](https://forum.cursor.com/t/custom-base-urls-for-each-custom-model/147219/17). |
| Antigravity App | No documented App gateway setting found. The separate Antigravity CLI supports `GOOGLE_GEMINI_BASE_URL`. | AgentEdict targets App hooks, not CLI environment configuration. [Antigravity CLI setup](https://antigravity.google/docs/install/). |
| Kiro | No documented custom model API endpoint found for the managed CLI surface. | Rule policy only. [Kiro models](https://kiro.dev/docs/models/). |
| Windsurf / Devin Desktop | No documented native Cascade gateway setting found. | Hooks only. [Devin Desktop models](https://docs.devin.ai/desktop/models). |

## Claude Code CLI

Add this to a unified profile that Claude can otherwise enforce. The gateway must expose the Anthropic Messages API and serve the model IDs Claude will request. `model` is optional and sets only the initial choice; it does not lock model selection. All Claude API requests still use the managed base URL. The public `knowledge-worker` example omits this section because it has no Claude gateway alias.

```yaml
claude:
  sandbox: required
  gateway:
    base_url: https://aigateway.internal.company.com/anthropic
    credential_env: ANTHROPIC_AUTH_TOKEN
    model: company-claude-model
```

The relevant generated managed settings are:

```json
{
  "env": {"ANTHROPIC_BASE_URL": "https://aigateway.internal.company.com/anthropic"},
  "allowedProviders": ["customEndpoint"],
  "model": "company-claude-model"
}
```

`allowedProviders` pins the configured custom endpoint as the only Claude API provider. Bundle validation rejects a gateway file without that exact pin or one that also allows another provider. `credential_env` accepts only `ANTHROPIC_AUTH_TOKEN` (Bearer) or `ANTHROPIC_API_KEY` (`x-api-key`). Its **name** is validated but not emitted with a value. Provision the credential to each Claude Code CLI process through a client-side secret manager or managed launcher. A shell variable may not reach a separately launched application. The gateway should enforce any required model allowlist and map Claude's background-model requests. Verify `/status` and a real request before deployment. The [Claude gateway guide](https://code.claude.com/docs/en/llm-gateway-connect) describes credential precedence, surface coverage, and verification.

## OpenCode v1

Use a profile with no restrictions the OpenCode adapter rejects. The sample policy map excludes OpenCode because every sample unified profile uses `filesystem.deny_read`; adding the gateway section does not weaken that check.

```yaml
opencode:
  gateway:
    provider: company-gateway
    name: Company AI Gateway
    base_url: https://aigateway.internal.company.com/v1
    wire_api: responses
    env_key: AI_GATEWAY_API_KEY
    model: company-coding-model
```

The relevant generated `opencode.json` settings are:

```json
{
  "provider": {
    "company-gateway": {
      "npm": "@ai-sdk/openai",
      "name": "Company AI Gateway",
      "options": {
        "baseURL": "https://aigateway.internal.company.com/v1",
        "apiKey": "{env:AI_GATEWAY_API_KEY}"
      },
      "models": {"company-coding-model": {"name": "company-coding-model"}}
    }
  },
  "enabled_providers": ["company-gateway"],
  "model": "company-gateway/company-coding-model",
  "small_model": "company-gateway/company-coding-model"
}
```

For a Chat Completions gateway, set `wire_api: chat_completions`; AgentEdict selects `@ai-sdk/openai-compatible`. OpenCode resolves `{env:AI_GATEWAY_API_KEY}` in its own process. Deliver that variable through a client-side secret manager or managed launcher. It is a reference in JSON, never the key. Validate the client version and a real streamed tool-call turn before deployment.

## Validation and rollout

The YAML parser rejects unknown and malformed gateway fields. Bundle validation rechecks the generated Claude and OpenCode gateway URLs, Claude provider pin, credential references, model selection, and OpenCode provider allowlist; it rejects embedded credential values. It cannot test DNS, TLS, gateway protocol behavior, model capabilities, or whether a launched client inherited its credential. The installer copies the selected managed artifact; it does not copy secrets or change a client's process environment.

When adding another client gateway, first verify its current official configuration and API format, whether AgentEdict's managed artifact is actually consumed, and how a client-side credential reaches that process. Add only a route the compiler and bundle validator can represent without dropping existing policy restrictions. Update this matrix, the builder catalog, tests, and client integration guide together.
