# ObfusProxy — Claude Code Guide

## Project Overview

**ObfusProxy** is a local LLM privacy proxy for DevOps daily use. It sits between developer tools (Claude Code, curl, any OpenAI-SDK client) and cloud LLM providers, transparently obfuscating sensitive data in prompts and de-obfuscating responses.

**Current stage:** Stage 2 — regex backend for structured PII + optional Presidio NER backend for unstructured entities (names, phone numbers, credit cards). Backends compose via `CompositeDetector`.

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
- **Privacy backends** — `regex` (always on) and/or `presidio` (optional NER; requires extra install)
- **Entity types to detect** — filters which types any backend may emit
- **Whitelist** — structured into `loopback`, `ip_ranges` (CIDR), and `domains`

Model selection and provider routing are handled entirely by the client and LiteLLM — not configured here. Clients pass real model strings (`claude-sonnet-4-6`, `gpt-4o`, `ollama/llama3`); LiteLLM auto-detects the upstream provider from the model name and reads credentials from environment variables.

### Backends

The `backends` list is ordered. When multiple backends are configured, a `CompositeDetector` wraps them all — results are merged and overlaps resolved (first-listed backend wins on ties).

**Regex only (default):**
```yaml
privacy:
  backends:
    - type: "regex"
```

**Regex + Presidio NER:**
```yaml
privacy:
  backends:
    - type: "regex"
    - type: "presidio"
      model: "en_core_web_trf"   # transformer model; recommended for DevOps text
  entities:
    - EMAIL_ADDRESS
    - IP_ADDRESS
    - CIDR
    - DOMAIN
    - API_KEY
    - SECRET
    - AWS_ARN
    - PERSON
    - PHONE_NUMBER
    - CREDIT_CARD
```

**Install Presidio (optional):**
```bash
uv pip install "presidio-analyzer>=2.2.0"
# Transformer model (recommended — far fewer false positives on technical/markdown text):
uv pip install "spacy[transformers]"   # pins torch<2.3; requires numpy<2 (see below)
uv pip install "numpy<2"               # spacy[transformers] pulls torch 2.2.2 which was
                                       # compiled against NumPy 1.x C API; NumPy 2.x breaks it
python -m spacy download en_core_web_trf

# Lightweight alternative (more false positives on code/markdown):
# python -m spacy download en_core_web_sm
```

> **Dependency note:** `spacy[transformers]` pins `torch<2.3` (currently installs torch 2.2.2).
> That torch version was compiled against the NumPy 1.x C API. If NumPy 2.x is present in the
> environment, torch crashes at import time with `_ARRAY_API not found`. Pinning `numpy<2` is the
> correct fix. You cannot upgrade torch past 2.2.x without upgrading spacy-transformers first,
> which is a separate upstream dependency issue.

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

Control verbosity with `OBFUSPROXY_LOG_LEVEL` (default: `INFO`):

| Level | Shows |
|---|---|
| `INFO` | Entity count per obfuscated text block |
| `DEBUG` | Entity type, original value, placeholder, message role/index — plus the full obfuscated prompt sent to the LLM and the raw response received before de-obfuscation |

```bash
# Counts only (default)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Entity details + full payload visibility
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
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
pytest tests/test_regex.py        -v  # RegexDetector — all entity types, safe ranges, whitelist
pytest tests/test_session.py      -v  # SessionMap — idempotency, counters, concurrency
pytest tests/test_engine.py       -v  # PrivacyEngine — round-trip, role filtering
pytest tests/test_deobfuscator.py -v  # Streaming de-obfuscation, split-placeholder buffering
pytest tests/test_composite.py    -v  # CompositeDetector — merging, overlap priority
pytest tests/test_config.py       -v  # Config loading and Pydantic validation

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
│       ├── factory.py     # Factory: config → Detector (or CompositeDetector)
│       └── backends/
│           ├── __init__.py
│           ├── base.py        # Detector ABC, Entity dataclass, resolve_overlaps()
│           ├── regex.py       # RegexDetector — structured PII (emails, IPs, keys, …)
│           ├── composite.py   # CompositeDetector — wraps N backends, merges spans
│           └── presidio.py    # PresidioDetector — NER via spaCy (optional)
├── tests/
│   ├── conftest.py            # Shared fixtures
│   ├── test_regex.py          # RegexDetector — all entity types
│   ├── test_session.py        # SessionMap
│   ├── test_engine.py         # PrivacyEngine
│   ├── test_deobfuscator.py   # Streaming de-obfuscation
│   ├── test_composite.py      # CompositeDetector
│   └── test_config.py         # Config loading and validation
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

| Type | Backend | Examples |
|---|---|---|
| `EMAIL_ADDRESS` | regex | `dev@corp.internal` |
| `IP_ADDRESS` | regex | `10.0.0.1` |
| `CIDR` | regex | `10.0.0.0/8` |
| `DOMAIN` | regex | `db.corp.internal`, `redis.svc.cluster.local` |
| `API_KEY` | regex | `Bearer ABC...`, `sk-abc123...`, long hex |
| `SECRET` | regex | DSN URLs, env-var assignments, PEM keys |
| `AWS_ARN` | regex | `arn:aws:iam::123456789012:role/DevRole` |
| `PORT` | regex | `:8080` |
| `PERSON` | presidio | `John Smith` |
| `PHONE_NUMBER` | presidio | `+1-555-867-5309` |
| `CREDIT_CARD` | presidio | `4111 1111 1111 1111` |
| `LOCATION` | presidio | `San Francisco, CA` |

**Not detected (not sensitive):** UUID, DOCKER_IMAGE, K8S_RESOURCE.

**Note on PORT detection:** The PORT regex captures `:NNNN` syntax (e.g., `host:8080`). The `port N` word-form alternative is present in the pattern but its digits fall in a different capture group — only `:NNNN` style is currently emitted.

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

## Development Workflow

### Adding a New Entity Pattern

1. Edit `app/privacy/backends/regex.py` — add pattern to `_PATTERNS` list
2. Add test case to `tests/test_regex.py`
3. No other files change

### Adding a New Backend

1. Create `app/privacy/backends/newbackend.py` implementing the `Detector` ABC
2. Add one `elif backend_cfg.type == "newbackend":` block in `app/privacy/factory.py`
3. Optionally add to `[project.optional-dependencies]` in `pyproject.toml`
4. Add tests in `tests/test_composite.py` or a new test file

### Running Tests

```bash
# All tests (100 tests, ~0.5s)
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

Check `config.yaml` — `privacy.backends[*].type` must be `"regex"` or `"presidio"`. For presidio, the package must be installed (`uv pip install "presidio-analyzer>=2.2.0"`).

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
# Required for Anthropic path (Claude Code)
export ANTHROPIC_API_KEY=sk-ant-...

# Optional: other providers via LiteLLM (OpenAI-compatible path)
export OPENAI_API_KEY=sk-...
export GROQ_API_KEY=gsk-...

# Proxy log verbosity: INFO (default) | DEBUG
export OBFUSPROXY_LOG_LEVEL=DEBUG
```
