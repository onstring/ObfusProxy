# ObfusProxy — Claude Code Guide

## Project Overview

**ObfusProxy** is a local LLM privacy proxy for DevOps daily use. It sits between developer tools (Claude Code, curl, any OpenAI-SDK client) and cloud LLM providers, transparently obfuscating sensitive data in prompts and de-obfuscating responses.

**Current stage:** Stage 2 — regex backend for context-bearing DevOps PII + detect-secrets backend for secret-class entities (one-way redaction) + optional Presidio NER backend. Backends compose via `CompositeDetector`.

## Quick Start

### 1. Activate the Virtual Environment

```bash
source .venv/bin/activate
```

All commands below assume this environment is active.

### 2. Run the Proxy

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

**Important:** Always use `--workers 1`. The session map is in-process memory; multiple workers cause silent de-obfuscation failures.

No API key is required in the proxy's environment — the proxy forwards whatever credentials the client sends (pass-through auth).

### 3. Point Claude Code at the Proxy

In a separate terminal:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-<your-real-key>   # or use: claude login
claude
```

The proxy extracts the `Authorization: Bearer` header (or `x-api-key`) from each request and forwards it to Anthropic unchanged. This means:
- **API key users**: set your real `ANTHROPIC_API_KEY` on the client side
- **Subscription users**: run `claude login` — the OAuth token is forwarded transparently
- **Fallback**: if neither header is present, the proxy falls back to `ANTHROPIC_API_KEY` in its own environment (for shared/team setups where one key serves multiple clients)

The proxy intercepts all requests, obfuscates PII in `user` and `tool` messages, forwards to the real API, and returns de-obfuscated responses.

## Configuration

Edit `config.yaml` to control:

- **Server host/port** — where the proxy listens
- **Privacy backends** — `regex` (context-bearing PII), `detect_secrets` (secret redaction), and/or `presidio` (optional NER)
- **Entity types to detect** — filters which types any backend may emit
- **Whitelist** — structured into `loopback`, `ip_ranges` (CIDR), and `domains`

Model selection and provider routing are handled entirely by the client and LiteLLM — not configured here. Clients pass real model strings (`claude-sonnet-4-6`, `gpt-4o`, `ollama/llama3`); LiteLLM auto-detects the upstream provider from the model name and reads credentials from environment variables.

### Backends

The `backends` list is ordered. When multiple backends are configured, a `CompositeDetector` wraps them all — results are merged and overlaps resolved (first-listed backend wins on ties).

**Default (regex + detect_secrets):**
```yaml
privacy:
  backends:
    - type: "regex"           # context-bearing: email, IP, CIDR, domain, port
    - type: "detect_secrets"  # secrets: redacted one-way, not round-tripped
```

**Install detect-secrets (required for default config):**
```bash
uv pip install "detect-secrets>=1.5.0"
```

**With Presidio NER (optional, adds PERSON / PHONE_NUMBER / CREDIT_CARD):**
```yaml
privacy:
  backends:
    - type: "regex"
    - type: "detect_secrets"
    - type: "presidio"
      model: "en_core_web_lg"
```

**Install Presidio (optional):**
```bash
uv pip install "presidio-analyzer>=2.2.0"
python -m spacy download en_core_web_lg
```

That's it — no torch, no transformers, no NumPy pin. `en_core_web_lg` is a 560 MB static-vector
model that gives good NER quality with ~10–50 ms per-request latency. Combined with the proxy's
`_is_plausible_person` filter, false positives on technical/markdown text are well-controlled.

**Model alternatives:**
- `en_core_web_sm` (12 MB) — far more false positives on code/markdown; only useful if disk is constrained.
- `en_core_web_trf` (440 MB) — transformer-backed, marginally better NER quality, but pulls in
  `torch` + `transformers` (~2.5 GB of dependencies). On Intel macOS it additionally requires
  `numpy<2` because PyTorch dropped Intel-Mac wheels after 2.2.2 and that build was compiled
  against the NumPy 1.x C API. Not worth the complexity for the quality gain.

### Whitelist

The whitelist is structured into three categories:

```yaml
whitelist:
  loopback:         # Exact-match strings (never obfuscated)
    - "localhost"
    - "127.0.0.1"
    - "::1"
    - "0.0.0.0"
  ip_ranges: []     # Extra CIDR ranges — IPs/CIDRs falling inside are skipped
                    # RFC 1918 private ranges are hardcoded safe (see below)
  domains:          # Exact-match domain names
    - "api.anthropic.com"
    - "github.com"
```

**Hardcoded safe ranges (always applied, regardless of config):**
- RFC 1918 private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- RFC documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`

These are never obfuscated because internal/private IPs identify infrastructure topology, not secrets. Use `ip_ranges` in config for any additional non-sensitive ranges beyond RFC 1918.

### Provider and Model Routing

There is no provider or model config. The proxy is fully transparent:

- **`/v1/messages`** — forwards to `api.anthropic.com` verbatim; model passes through unchanged
- **`/v1/chat/completions`** — passes model string to LiteLLM; LiteLLM auto-detects the upstream provider from the model name (`claude-*` → Anthropic, `gpt-*` → OpenAI, `ollama/*` → Ollama, etc.) and reads credentials from environment variables

## Logging

Control verbosity with `OBFUSPROXY_LOG_LEVEL` (default: `INFO`). Three tiers:

| Level | Shows |
|---|---|
| `INFO` | Entity count per obfuscated text block |
| `DEBUG` | The obfuscation mapping table — entity type, original value, placeholder, message role/index. Clean output focused on what was redacted to what. |
| `TRACE` | Everything in `DEBUG` plus the full obfuscated prompt sent to the LLM and the raw response received before de-obfuscation. Verbose; use when you need to inspect actual payloads. |

```bash
# Counts only (default)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Mapping table only — recommended when you want to see what's being redacted
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Mapping table + full payloads (sent prompts and raw responses)
OBFUSPROXY_LOG_LEVEL=TRACE uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

Sample DEBUG output:
```
00:03:39 INFO   app.privacy.engine  [obfuscate] session=feea... entities=3
00:03:39 DEBUG  app.privacy.engine  [obfuscate] msg[0] role=user
00:03:39 DEBUG  app.privacy.engine  [obfuscate]   IP_ADDRESS           '10.1.2.3' -> [IP_ADDRESS_0]
00:03:39 DEBUG  app.privacy.engine  [obfuscate]   PORT                 '5432' -> [PORT_1]
00:03:39 DEBUG  app.privacy.engine  [obfuscate]   DOMAIN               'db.corp.internal' -> [DOMAIN_2]
```

`httpcore` and `httpx` internal logs are suppressed regardless of level.

## Testing

### Unit Tests

```bash
# All tests
pytest

# Individual modules
pytest tests/test_regex.py           -v  # RegexDetector — context-bearing entities, safe ranges, whitelist
pytest tests/test_secrets_backend.py -v  # DetectSecretsBackend — service tokens, redact_only flag
pytest tests/test_session.py         -v  # SessionMap — idempotency, counters, concurrency
pytest tests/test_engine.py          -v  # PrivacyEngine — round-trip, redact-only path, role filtering
pytest tests/test_deobfuscator.py    -v  # Streaming de-obfuscation, split-placeholder buffering
pytest tests/test_composite.py       -v  # CompositeDetector — merging, overlap priority
pytest tests/test_config.py          -v  # Config loading and Pydantic validation

# With coverage
pytest --cov=app --cov-report=term-missing
```

### Manual Integration Testing

Start the proxy (with `ANTHROPIC_API_KEY` set), then in another terminal:

```bash
# Health check
curl http://localhost:8080/health

# Non-streaming chat (OpenAI-compatible path)
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: test-session-1" \
  -d '{
    "model": "fast",
    "messages": [
      {"role": "user", "content": "My email is dev@corp.internal and server is at 10.1.2.3"}
    ]
  }' | jq .

# Streaming chat
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: test-session-2" \
  -d '{
    "model": "fast",
    "messages": [
      {"role": "user", "content": "My API key is sk-abc123def456ghi789jkl0123"}
    ],
    "stream": true
  }'

# Delete a session (clear obfuscation mappings)
curl -X DELETE http://localhost:8080/session/test-session-1
```

### Using with Claude Code

```bash
# Terminal 1: Start proxy (no API key needed — client key is forwarded automatically)
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Terminal 2: Point Claude Code at proxy (use real key or subscription)
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-<your-real-key>   # or: claude login
claude
```

## Project Structure

```
ObfusProxy/
├── .venv/                  # Local virtual environment (uv)
├── app/
│   ├── __init__.py
│   ├── main.py            # FastAPI app, routes, lifespan, logging config
│   ├── config.py          # Pydantic config schema + loader
│   ├── log.py             # TRACE log level (level 5) definition
│   ├── pipeline.py        # Wires engine → router/httpx → deobfuscator
│   ├── router.py          # LiteLLM wrapper, model alias resolution
│   ├── deobfuscator.py    # Streaming de-obfuscation
│   └── privacy/
│       ├── __init__.py
│       ├── engine.py      # PrivacyEngine: obfuscate/deobfuscate, role filtering
│       ├── session.py     # SessionMap: asyncio-safe in-memory store
│       ├── factory.py     # Factory: config → Detector (or CompositeDetector)
│       └── backends/
│           ├── __init__.py
│           ├── base.py             # Detector ABC, Entity dataclass, resolve_overlaps()
│           ├── regex.py            # RegexDetector — context-bearing PII (email, IP, domain…)
│           ├── secrets_backend.py  # DetectSecretsBackend — secrets, redact-only
│           ├── composite.py        # CompositeDetector — wraps N backends, merges spans
│           └── presidio.py         # PresidioDetector — NER via spaCy (optional)
├── tests/
│   ├── conftest.py            # Shared fixtures
│   ├── test_regex.py              # RegexDetector — context-bearing entities
│   ├── test_secrets_backend.py    # DetectSecretsBackend — service tokens, redact_only
│   ├── test_session.py            # SessionMap
│   ├── test_engine.py             # PrivacyEngine — round-trip + redact-only path
│   ├── test_deobfuscator.py       # Streaming de-obfuscation
│   ├── test_composite.py          # CompositeDetector
│   └── test_config.py             # Config loading and validation
├── config.yaml            # Configuration
├── pyproject.toml         # Dependencies, build config
└── CLAUDE.md              # This file
```

## Architecture Highlights

### Two Request Paths

**Anthropic native (`/v1/messages`)** — used by Claude Code and Anthropic SDK clients:
1. Client sends POST `/v1/messages` with its own model name
2. Proxy obfuscates `user`/`tool` message content
3. Forwards to `api.anthropic.com/v1/messages` via `httpx` using `ANTHROPIC_API_KEY`
4. De-obfuscates response content blocks
5. Returns Anthropic-format response to client

**OpenAI-compatible (`/v1/chat/completions`)** — used by curl, OpenAI SDK clients:
1. Client sends POST `/v1/chat/completions` with a model alias (e.g., `"fast"`)
2. Proxy obfuscates `user`/`tool` messages
3. Resolves alias → real model via `config.yaml` providers, calls `litellm.acompletion()`
4. De-obfuscates response
5. Returns OpenAI-format response

### What Gets Obfuscated

Role-based filtering ensures only user-originated content is obfuscated:

| Message role | Obfuscated? | Reason |
|---|---|---|
| `user` | Yes | User-typed content |
| `tool` / `tool_result` blocks | Yes | Tool output may contain sensitive data |
| `assistant` | No | LLM-generated text |
| `system` | No | Client-controlled instructions |

### Multi-Backend Detection

The factory builds the detector from `config.yaml`:

- **Single backend** → returned directly
- **Multiple backends** → wrapped in `CompositeDetector`

`CompositeDetector` calls each backend in order, merges all entity spans, sorts by start offset, then runs greedy overlap resolution (earlier span wins). This means regex always beats Presidio on any overlapping detection.

### Entity Types

Two obfuscation modes exist:

- **Reversible** — replaced with `[TYPE_N]` placeholder, restored on response (context preserved for the LLM)
- **Redact-only** — replaced with `[REDACTED:TYPE]`, never stored in session map, never restored (secret value is gone)

| Type | Backend | Mode | Examples |
|---|---|---|---|
| `EMAIL_ADDRESS` | regex | reversible | `dev@corp.internal` |
| `IP_ADDRESS` | regex | reversible | `10.0.0.1` |
| `CIDR` | regex | reversible | `10.0.0.0/8` |
| `DOMAIN` | regex | reversible | `db.corp.internal`, `redis.svc.cluster.local` |
| `PORT` | regex | reversible | `:8080` |
| `AWS_KEY` | detect_secrets | redact | `AKIA...`, `ASIA...` |
| `AZURE_KEY` | detect_secrets | redact | Azure storage keys |
| `BASIC_AUTH` | detect_secrets | redact | password extracted from HTTP basic-auth URLs |
| `DISCORD_TOKEN` | detect_secrets | redact | Discord bot tokens |
| `GITHUB_TOKEN` | detect_secrets | redact | `ghp_...`, `gho_...`, `ghu_...` |
| `GITLAB_TOKEN` | detect_secrets | redact | `glpat-...` |
| `JWT` | detect_secrets | redact | `eyJ....eyJ....` |
| `MAILCHIMP_KEY` | detect_secrets | redact | Mailchimp API keys |
| `NPM_TOKEN` | detect_secrets | redact | `npm_...` |
| `OPENAI_KEY` | detect_secrets | redact | OpenAI API keys |
| `PRIVATE_KEY` | detect_secrets | redact | PEM key blocks (all types) |
| `PYPI_TOKEN` | detect_secrets | redact | PyPI upload tokens |
| `SENDGRID_KEY` | detect_secrets | redact | `SG.x.y` |
| `SLACK_TOKEN` | detect_secrets | redact | `xoxb-...`, `xoxp-...` |
| `SQUARE_TOKEN` | detect_secrets | redact | Square OAuth tokens |
| `STRIPE_KEY` | detect_secrets | redact | `sk_live_...`, `sk_test_...`, `rk_...` |
| `TELEGRAM_TOKEN` | detect_secrets | redact | Telegram bot tokens |
| `TWILIO_KEY` | detect_secrets | redact | Twilio auth tokens |
| `AWS_ARN` | detect_secrets | redact | `arn:aws:iam::123456789012:role/DevRole` |
| `SECRET` | detect_secrets | redact | DSN URLs, env-var assignments (`DATABASE_URL=...`, `VAULT_TOKEN=...`), `Password=...` connection strings |
| `PERSON` | presidio | reversible | `John Smith` |
| `PHONE_NUMBER` | presidio | reversible | `+1-555-867-5309` |
| `CREDIT_CARD` | presidio | reversible | `4111 1111 1111 1111` |

**Not detected (not sensitive):** UUID, DOCKER_IMAGE, K8S_RESOURCE.

**Note on PORT detection:** The PORT regex captures `:NNNN` syntax (e.g., `host:8080`). The `port N` word-form alternative is present in the pattern but its digits fall in a different capture group — only `:NNNN` style is currently emitted.

**Design rationale for two modes:** Context-bearing entities (IPs, domains, emails) help the LLM reason about infrastructure topology — the LLM sees `[DOMAIN_0]` and the original is restored on response. Secrets don't have that property: the LLM never needs the real value, keeping it in the session map would prolong its lifetime in memory unnecessarily, and one-way redaction is safer by default.

### Placeholder Format

**Context-bearing entities** — reversible, counter-scoped per session:
```
[IP_ADDRESS_0]   [EMAIL_ADDRESS_1]   [DOMAIN_2]   [PORT_3]
```
Counter is global per session (not per type), ensuring uniqueness. The same original value always maps to the same placeholder within a session.

**Secret entities** — terminal, no session-map entry:
```
[REDACTED:GITHUB_TOKEN]   [REDACTED:AWS_KEY]   [REDACTED:SECRET]
```
The type suffix tells the LLM what kind of value was scrubbed without leaking the value itself — useful when diagnosing auth errors (`"the GITHUB_TOKEN in this call was redacted"`).

### Session Map

In-process volatile dictionary:
```
{
  "session-id-123": {
    "[IP_ADDRESS_0]": "10.1.2.3",
    "[EMAIL_ADDRESS_1]": "dev@corp.internal",
    "[DOMAIN_2]": "db.corp.internal"
  }
}
```

- Scoped to process lifetime (no disk persistence by design)
- Per-session asyncio.Lock for concurrent safety
- Idempotent: same entity → same placeholder within session
- Cleared via `DELETE /session/{id}` or process restart

### Streaming De-obfuscation

Handles split placeholders like `[DOMAIN_5]` arriving as `[DOMA` + `IN_5]` across chunks:

1. Per-chunk buffer accumulates incoming text
2. Finds rightmost unclosed `[` bracket
3. Flushes everything before it (with replacements applied)
4. Keeps partial suffix buffered, waiting for closing `]`
5. On stream end (`content_block_stop` for Anthropic, `[DONE]` for OpenAI), flushes remaining buffer

## Development Workflow

### Adding a New Context-Bearing Entity (reversible)

1. Edit `app/privacy/backends/regex.py` — add pattern to `_PATTERNS` list
2. Add test case to `tests/test_regex.py`
3. Add the entity type to the `entities` list in `config.yaml`

### Adding a New Secret Pattern (redact-only)

1. Edit `app/privacy/backends/secrets_backend.py` — add a `_CustomPattern` entry to `_CUSTOM_PATTERNS`
2. Add test case to `tests/test_secrets_backend.py`
3. Add the entity type to the `entities` list in `config.yaml`

### Adding a New Backend

1. Create `app/privacy/backends/newbackend.py` implementing the `Detector` ABC
2. Add one `elif backend_cfg.type == "newbackend":` block in `app/privacy/factory.py`
3. Optionally add to `[project.optional-dependencies]` in `pyproject.toml`
4. Add tests in `tests/test_composite.py` or a new test file

### Running Tests

```bash
# All tests (~130 tests, ~0.5s)
pytest

# Specific test file with verbose output
pytest tests/test_regex.py -v

# With coverage report
pytest --cov=app --cov-report=term-missing
```

## Known Constraints (Stage 2)

- **Single worker only** — `--workers 1` required; session map is in-process memory
- **No session TTL** — restart to clear sensitive data
- **IPv6 not detected** — only loopback `::1` is in safe list
- **No authentication** — operates on localhost only
- **No persistence** — session map is volatile (by design)
- **Placeholder collision edge case** — if user types `[IP_ADDRESS_0]` literally, it will be back-substituted (acceptable for Stage 2)
- **PORT word-form dead code** — `port N` syntax in PORT regex hits group 2, but code reads group 1; only `:NNNN` style is emitted

## Future Stages

- **Stage 3:** Redis session store, multi-worker support, session TTL + eviction, Prometheus metrics
- **Stage 4+:** BERT NER backend, IPv6 CIDR detection, keyring integration, hot-config reload, audit logging

## Troubleshooting

### "Port 8080 already in use"

```bash
lsof -i :8080
kill -9 <PID>
```

Or use a different port: `uvicorn app.main:app --host 127.0.0.1 --port 8081`

### 401 Unauthorized from upstream

`ANTHROPIC_API_KEY` is not set in the proxy's terminal. The key must be exported before starting uvicorn, not just in the Claude Code terminal.

### "Unknown backend: ..."

Check `config.yaml` — `privacy.backends[*].type` must be `"regex"`, `"detect_secrets"`, or `"presidio"`. For detect_secrets, install with `uv pip install "detect-secrets>=1.5.0"`. For presidio, install with `uv pip install "presidio-analyzer>=2.2.0"`.

### LiteLLM raises "model not found" or 400 error

The client must send a valid model string that LiteLLM recognises (e.g. `claude-haiku-4-5-20251001`, `gpt-4o`). The proxy no longer maps aliases — pass the full model name.

### Session data not de-obfuscated

Check that you're using the same `X-Session-Id` header for both the prompt and any follow-up. If testing with curl, set it explicitly:

```bash
curl -H "X-Session-Id: my-session" ...
```

### Tests fail with import errors

Ensure venv is activated:
```bash
source .venv/bin/activate
pytest
```

## Environment Variables

```bash
# Set on the CLIENT side (Claude Code / curl / SDK) — forwarded to Anthropic by the proxy
export ANTHROPIC_API_KEY=sk-ant-...   # or use: claude login (subscription OAuth)

# Optional fallback on the PROXY side — used only if client sends no Authorization header
# (useful for shared/team setups where one key serves multiple clients)
# export ANTHROPIC_API_KEY=sk-ant-...

# Optional: other providers via LiteLLM (OpenAI-compatible path) — set on client side
export OPENAI_API_KEY=sk-...
export GROQ_API_KEY=gsk-...

# Proxy log verbosity: INFO (default) | DEBUG | TRACE
export OBFUSPROXY_LOG_LEVEL=DEBUG
```
