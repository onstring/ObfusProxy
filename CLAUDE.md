# ObfusProxy — Claude Code Guide

## Project Overview

**ObfusProxy** is a local LLM privacy proxy for DevOps daily use. It sits between developer tools (Claude Code, curl, any OpenAI-SDK client) and cloud LLM providers, transparently obfuscating sensitive data in prompts and de-obfuscating responses.

**Current stage:** Stage 1 (regex-based detection only; architecture ready for Presidio/BERT/API backends in future stages).

## Quick Start

### 1. Activate the Virtual Environment

```bash
source .venv/bin/activate
```

All commands below assume this environment is active.

### 2. Set API Key and Run the Proxy

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

**Important:** Always use `--workers 1`. The session map is in-process memory; multiple workers cause silent de-obfuscation failures. `ANTHROPIC_API_KEY` must be set in the proxy's terminal — it is read at request time to forward to `api.anthropic.com`.

### 3. Point Claude Code at the Proxy

In a separate terminal:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-proxy-dummy-key
claude
```

> **Important:** Claude Code validates the key format before starting — it must begin with `sk-ant-`. Setting it to `unused` or any other non-matching string causes a "not logged in" error. The proxy ignores this value entirely; the real `ANTHROPIC_API_KEY` is read from the proxy's own terminal.

The proxy intercepts all requests, obfuscates PII in `user` and `tool` messages, forwards to the real API, and returns de-obfuscated responses.

## Configuration

Edit `config.yaml` to control:

- **Server host/port** — where the proxy listens
- **Privacy backend** — `regex` (Stage 1) or future `presidio`, `transformer`, `api`
- **Entity types to detect** — `EMAIL_ADDRESS`, `IP_ADDRESS`, `DOMAIN`, `API_KEY`, `SECRET`, `AWS_ARN`, `PORT`, `CIDR`
- **Whitelist** — values that should never be obfuscated (e.g., `github.com`, `api.anthropic.com`)
- **Providers** — model aliases for the `/v1/chat/completions` path only
- **Router** — default model alias and fallback chain (OpenAI-compatible path only)

> Claude Code uses `/v1/messages` and passes its own model through. The `providers`/`router` config is irrelevant for Claude Code — it only applies to curl/SDK clients hitting `/v1/chat/completions`.

## Logging

Control verbosity with `OBFUSPROXY_LOG_LEVEL` (default: `INFO`):

| Level | Shows |
|---|---|
| `INFO` | Entity count per obfuscated text block |
| `DEBUG` | Entity type, original value, assigned placeholder, message role/index |
| `TRACE` | Full scrubbed request body sent to LLM + raw response received |

```bash
# Counts only (default)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Entity details
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Full prompts and responses
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
pytest tests/test_regex.py           # RegexDetector patterns
pytest tests/test_session.py         # SessionMap idempotency
pytest tests/test_engine.py          # Round-trip obfuscate/deobfuscate
pytest tests/test_deobfuscator.py    # Streaming split logic
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
# Terminal 1: Start proxy (real key — used to forward requests to Anthropic)
source .venv/bin/activate
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Terminal 2: Point Claude Code at proxy (dummy key — must match sk-ant- format)
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-proxy-dummy-key
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
│       ├── factory.py     # Factory: config → Detector
│       └── backends/
│           ├── __init__.py
│           ├── base.py    # Detector ABC + Entity dataclass
│           └── regex.py   # RegexDetector (Stage 1)
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

### Placeholder Format

Placeholders are named after their entity type for readability:

```
[IP_ADDRESS_0]   [EMAIL_ADDRESS_1]   [DOMAIN_2]   [PORT_3]
```

Counter is global per session (not per type), ensuring uniqueness. The same original value always maps to the same placeholder within a session.

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

### Entity Types (Stage 1)

| Type | Examples |
|---|---|
| `EMAIL_ADDRESS` | `dev@corp.internal`, `alice@github.com` |
| `IP_ADDRESS` | `10.0.0.1` (not `127.0.0.1`, loopback, or RFC-DOC ranges) |
| `CIDR` | `10.0.0.0/8`, `192.168.0.0/16` |
| `DOMAIN` | `db.corp.internal`, `redis.svc.cluster.local` |
| `API_KEY` | `Bearer ABC...`, `sk-abc123...`, long hex strings |
| `SECRET` | URLs with creds, env var assignments, PEM private keys, DSN passwords |
| `AWS_ARN` | `arn:aws:iam::123456789012:role/DevRole` |
| `PORT` | `:8080`, `port 5432` |

**Not detected (not sensitive):** UUID, DOCKER_IMAGE, K8S_RESOURCE.

### Whitelist

Values that should never be obfuscated (from `config.yaml`):
```yaml
whitelist:
  - "github.com"
  - "api.anthropic.com"
```

Hardcoded safe list: `127.0.0.1`, `0.0.0.0`, `::1`, `localhost`, and RFC documentation ranges (`192.0.2.*`, `198.51.100.*`, `203.0.113.*`).

## Development Workflow

### Adding a New Entity Pattern

1. Edit `app/privacy/backends/regex.py` — add pattern to `_PATTERNS` list
2. Test: `pytest tests/test_regex.py` with new test case
3. No other files change

### Adding a New Backend (e.g., Presidio)

1. Create `app/privacy/backends/presidio.py` implementing `Detector` ABC
2. Add one `elif` block in `app/privacy/factory.py`
3. Update `config.yaml` to support `backend: presidio`
4. No other files change

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_regex.py -v

# With coverage
pytest --cov=app
```

## Known Constraints (Stage 1)

- **Single worker only** — `--workers 1` required; session map is in-process memory
- **No session TTL** — restart to clear sensitive data
- **IPv6 not detected** — only loopback `::1` is in safe list
- **No authentication** — operates on localhost only
- **No persistence** — session map is volatile (by design)
- **Placeholder collision edge case** — if user types `[IP_ADDRESS_0]` literally, it will be back-substituted (acceptable for Stage 1)

## Future Stages

- **Stage 2:** Presidio + spacy backend, Redis session store, multi-worker, rate limiting, basic auth
- **Stage 3:** BERT NER backend, IPv6 CIDR, session TTL + eviction, Prometheus metrics
- **Stage 4+:** API-based NER, keyring integration, hot-config reload, audit logging

## Troubleshooting

### "Port 8080 already in use"

```bash
lsof -i :8080
kill -9 <PID>
```

Or use a different port: `uvicorn app.main:app --host 127.0.0.1 --port 8081`

### 401 Unauthorized from upstream

`ANTHROPIC_API_KEY` is not set in the proxy's terminal. The key must be exported before starting uvicorn, not just in the Claude Code terminal.

### "Unknown backend: regex"

Check `config.yaml` — `privacy.backend` should be `regex`.

### "Provider alias not found"

Check `config.yaml` — ensure the alias in `router.default_alias` and `router.fallback_chain` exists in `providers`.

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
# Required for Anthropic path (Claude Code)
export ANTHROPIC_API_KEY=sk-ant-...

# Optional: other providers via LiteLLM (OpenAI-compatible path)
export OPENAI_API_KEY=sk-...
export GROQ_API_KEY=gsk-...

# Proxy log verbosity: INFO (default) | DEBUG | TRACE
export OBFUSPROXY_LOG_LEVEL=DEBUG
```
