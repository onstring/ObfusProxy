# ObfusProxy

A local LLM privacy proxy for DevOps. Transparently obfuscates sensitive data (PII, credentials, IPs, domains, API keys) in prompts sent to cloud LLMs and de-obfuscates responses before returning them to the client.

## Features

- **Transparent privacy** — Prompts are obfuscated before leaving your machine; responses are restored invisibly
- **Pluggable detectors** — Stage 1 uses regex (fast, zero dependencies); future backends (Presidio, BERT, API) can be added without code changes
- **Session persistence** — Same entity always gets the same placeholder within a session (coherent conversation)
- **Streaming-safe** — Handles placeholders split across streaming chunks with lookahead buffering
- **DevOps-focused** — Detects emails, IPs (with safe-list), CIDRs, domains, API keys, secrets, AWS ARNs, ports
- **Configurable whitelist** — Public infrastructure like `github.com` or `api.anthropic.com` never gets obfuscated
- **Dual protocol** — Native Anthropic `/v1/messages` (for Claude Code) and OpenAI-compatible `/v1/chat/completions`
- **Role-aware** — Only `user` and `tool` messages are obfuscated; assistant turns and system prompts pass through unchanged

## Quick Start

### 1. Activate Virtual Environment

```bash
source .venv/bin/activate
```

### 2. Set API Key and Run the Proxy

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

### 3. Point Your Tool at the Proxy

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-proxy-dummy-key
claude
```

> **Important:** Claude Code validates that the key matches the `sk-ant-` prefix format before starting. A value like `unused` will cause a "not logged in" error. Any `sk-ant-` prefixed string works — the proxy ignores it and uses the real key set in the proxy's terminal.

All prompts are automatically obfuscated. Responses are automatically de-obfuscated.

## Configuration

Edit `config.yaml`:

```yaml
server:
  host: "127.0.0.1"
  port: 8080

privacy:
  enabled: true
  backend: "regex"        # Only backend in Stage 1
  entities:               # Entity types to detect
    - EMAIL_ADDRESS
    - IP_ADDRESS
    - CIDR
    - DOMAIN
    - API_KEY
    - SECRET
    - AWS_ARN
    - PORT
  whitelist:              # Never obfuscate these
    - "github.com"
    - "api.anthropic.com"

providers:                # Model aliases (used by /v1/chat/completions only)
  - alias: "fast"
    model: "claude-haiku-4-5-20251001"
  - alias: "smart"
    model: "claude-sonnet-4-6"

router:
  default_alias: "fast"
  fallback_chain: ["fast", "smart"]
```

API keys come from environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.).

> **Note:** `providers` and `router` only apply to the `/v1/chat/completions` path. Claude Code uses `/v1/messages` and passes its own model through directly — the proxy does not override it.

## Entity Types Detected

| Type | Examples | Safe List |
|---|---|---|
| `EMAIL_ADDRESS` | `dev@corp.internal` | — |
| `IP_ADDRESS` | `10.0.0.1` | `127.0.0.1`, `0.0.0.0`, RFC-DOC ranges |
| `CIDR` | `10.0.0.0/8` | — |
| `DOMAIN` | `db.corp.internal` | Configurable whitelist |
| `API_KEY` | `sk-abc123...`, `Bearer ABC...` | — |
| `SECRET` | URLs with creds, PEM keys, DSN passwords | — |
| `AWS_ARN` | `arn:aws:iam::123456789012:role/DevRole` | — |
| `PORT` | `:8080`, `port 5432` | — |

**Not detected (not sensitive):** UUID, DOCKER_IMAGE, K8S_RESOURCE

## What Gets Obfuscated

Only messages that can carry user-supplied or tool-output content are obfuscated:

| Message role | Obfuscated? |
|---|---|
| `user` | Yes |
| `tool` / `tool_result` | Yes |
| `assistant` | No — LLM-generated |
| `system` | No — client-controlled instructions |

## Architecture

```
Client
  │
  ├─→ FastAPI gateway (mints/reads X-Session-Id)
  │
  ├─→ PrivacyEngine.obfuscate (user/tool messages only)
  │     RegexDetector → entities → [TYPE_N] placeholders
  │
  ├─→ SessionMap (stores {[TYPE_N] → original} per session)
  │
  ├─→ /v1/messages      → httpx → api.anthropic.com  (Claude Code path)
  │   /v1/chat/completions → ProviderRouter → litellm.acompletion
  │
  ├─→ ResponseDeobfuscator (streaming-safe [TYPE_N] → original replacement)
  │
  └─← Client receives clean response
```

### Session Map (In-Process Memory)

```
{
  "session-id-123": {
    "[IP_ADDRESS_0]": "10.1.2.3",
    "[EMAIL_ADDRESS_1]": "dev@corp.internal",
    "[DOMAIN_2]": "db.corp.internal"
  }
}
```

- Placeholders use entity type names for readability (`[IP_ADDRESS_0]`, not `[ENTITY_0]`)
- Scoped to process lifetime (no disk persistence by design — sensitive data stays volatile)
- Per-session asyncio.Lock for concurrent safety
- Idempotent: same entity → same placeholder within session
- Cleared via `DELETE /session/{id}` or process restart

## Logging

Control verbosity with `OBFUSPROXY_LOG_LEVEL` (default: `INFO`):

| Level | Shows |
|---|---|
| `INFO` | Entity count per request |
| `DEBUG` | Entity type, original value, placeholder, message role/index |
| `TRACE` | Full scrubbed request body sent to LLM + full raw response received |

```bash
# Default (counts only)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Show entity details
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Show full prompts/responses
OBFUSPROXY_LOG_LEVEL=TRACE uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

## Testing

### Unit Tests

```bash
pytest tests/test_regex.py           # RegexDetector patterns
pytest tests/test_session.py         # SessionMap
pytest tests/test_engine.py          # Round-trip obfuscate/deobfuscate
pytest tests/test_deobfuscator.py    # Streaming split logic
```

### Manual Integration Testing

```bash
# Health check
curl http://localhost:8080/health

# Chat with PII (OpenAI-compatible path)
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: test-session" \
  -d '{
    "model": "fast",
    "messages": [{
      "role": "user",
      "content": "My email is dev@corp.internal and server is 10.1.2.3"
    }]
  }' | jq .

# Delete session
curl -X DELETE http://localhost:8080/session/test-session
```

## Key Constraints (Stage 1)

- **Single worker only** — `--workers 1` required (session map is in-process memory)
- **No session TTL** — restart to clear sensitive data
- **IPv6 not detected** — only loopback `::1` in safe list
- **No authentication** — operates on localhost only
- **Volatile storage** — session map is memory-only
- **Placeholder collision edge case** — if user types `[IP_ADDRESS_0]` literally, it will be back-substituted (acceptable for Stage 1)

## Project Structure

```
ObfusProxy/
├── .venv/              # Virtual environment (uv)
├── app/
│   ├── main.py        # FastAPI app + routes
│   ├── config.py      # Pydantic config schema
│   ├── log.py         # TRACE log level definition
│   ├── pipeline.py    # Obfuscate → route → deobfuscate
│   ├── router.py      # LiteLLM wrapper
│   ├── deobfuscator.py # Streaming de-obfuscation
│   └── privacy/
│       ├── engine.py       # PrivacyEngine
│       ├── session.py      # SessionMap
│       ├── factory.py      # Detector factory
│       └── backends/
│           ├── base.py     # Detector ABC
│           └── regex.py    # RegexDetector (Stage 1)
├── config.yaml        # Configuration
├── pyproject.toml     # Dependencies
├── CLAUDE.md          # Claude Code guide (setup, testing, troubleshooting)
└── README.md          # This file
```

## Future Stages

- **Stage 2:** Presidio + spacy backend, Redis session store, multi-worker, rate limiting
- **Stage 3:** BERT NER backend, IPv6 CIDR, session TTL + eviction, Prometheus metrics
- **Stage 4+:** API-based NER, keyring integration, hot-config reload, audit logging

## Development

### Adding a New Entity Pattern

Edit `app/privacy/backends/regex.py` — add to `_PATTERNS` list. No other files change.

### Adding a New Backend (e.g., Presidio)

1. Create `app/privacy/backends/presidio.py` implementing `Detector` ABC
2. Add one `elif` block in `app/privacy/factory.py`
3. Done — zero changes to rest of codebase

## License

MIT
