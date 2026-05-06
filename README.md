# ObfusProxy

A local LLM privacy proxy for DevOps. Transparently obfuscates sensitive data (PII, credentials, IPs, domains, API keys) in prompts sent to cloud LLMs and de-obfuscates responses before returning them to the client.

## Features

- **Transparent privacy** — Prompts are obfuscated before leaving your machine; responses are restored invisibly
- **Multi-backend detection** — Regex handles structured PII (emails, IPs, API keys, secrets); Presidio NER handles unstructured entities (names, phone numbers, credit cards). Backends compose via `CompositeDetector`
- **Session persistence** — Same entity always gets the same placeholder within a session (coherent conversation)
- **Streaming-safe** — Handles placeholders split across streaming chunks with lookahead buffering
- **DevOps-focused** — Detects emails, IPs, CIDRs, domains, API keys, secrets, AWS ARNs, ports
- **Structured whitelist** — Loopback addresses, RFC-private IP ranges, and well-known domains never get obfuscated
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
  backends:
    - type: "regex"           # Always on — structured PII
    # - type: "presidio"      # Optional — NER (names, phones, credit cards)
    #   model: "en_core_web_lg"   # static-vector model; recommended default
  entities:
    - EMAIL_ADDRESS
    - IP_ADDRESS
    - CIDR
    - DOMAIN
    - API_KEY
    - SECRET
    - AWS_ARN
    # PORT intentionally omitted — port numbers identify services, not secrets
    # NER entities (presidio only — uncomment when presidio backend is enabled)
    # - PERSON
    # - PHONE_NUMBER
    # - CREDIT_CARD
  whitelist:
    loopback:           # Exact strings never obfuscated
      - "localhost"
      - "127.0.0.1"
      - "::1"
      - "0.0.0.0"
    ip_ranges: []       # RFC 1918 (10/8, 172.16/12, 192.168/16) are hardcoded safe
                        # Add extra non-sensitive CIDR ranges here if needed
    domains:            # Exact domain names never obfuscated
      - "api.anthropic.com"
      - "github.com"
```

There is no provider or model configuration. Clients pass real model strings (`claude-haiku-4-5-20251001`, `gpt-4o`, `ollama/llama3`); LiteLLM auto-detects the upstream provider from the model name and reads API keys from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.).

### Enabling Presidio NER (Optional)

Presidio uses spaCy for named entity recognition. Install separately:

```bash
uv pip install "presidio-analyzer>=2.2.0"
python -m spacy download en_core_web_lg
```

`en_core_web_lg` (560 MB) is the recommended default — pure spaCy, no torch dependency, good NER
quality, and ~10–50 ms per-request latency.

Then uncomment the `presidio` backend and NER entities in `config.yaml`.

**Model alternatives:**
- `en_core_web_sm` (12 MB) — many more false positives on code/markdown text; only useful if disk-constrained.
- `en_core_web_trf` (440 MB) — transformer-backed, slightly higher quality but pulls in `torch` +
  `transformers` (~2.5 GB). On Intel macOS it additionally requires `numpy<2` because PyTorch
  dropped Intel-Mac wheels after 2.2.2.

## Entity Types Detected

| Type | Backend | Examples | Safe List |
|---|---|---|---|
| `EMAIL_ADDRESS` | regex | `dev@corp.internal` | Configurable whitelist |
| `IP_ADDRESS` | regex | `8.8.8.8` | Loopback, RFC 1918, RFC-DOC ranges, configured ip_ranges |
| `CIDR` | regex | `203.0.113.0/24` | RFC 1918, RFC-DOC ranges, configured ip_ranges |
| `DOMAIN` | regex | `db.corp.internal` | Configurable domains list |
| `API_KEY` | regex | `sk-abc123...`, `Bearer ABC...` | — |
| `SECRET` | regex | DSN URLs, env-var assignments, PEM keys | — |
| `AWS_ARN` | regex | `arn:aws:iam::123456789012:role/DevRole` | — |
| `PERSON` | presidio | `John Smith` | — |
| `PHONE_NUMBER` | presidio | `+1-555-867-5309` | — |
| `CREDIT_CARD` | presidio | `4111 1111 1111 1111` | — |

**Not enabled by default:** PORT (`:8080` — identifies services, not secrets), LOCATION (high false-positive rate)

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
  │     CompositeDetector
  │       ├─ RegexDetector    → structured PII spans
  │       └─ PresidioDetector → NER spans (optional)
  │     merge + resolve overlaps → [TYPE_N] placeholders
  │
  ├─→ SessionMap (stores {[TYPE_N] → original} per session)
  │
  ├─→ /v1/messages        → httpx → api.anthropic.com
  │   /v1/chat/completions → litellm.acompletion (provider auto-detected from model name)
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
| `DEBUG` | Entity type, original value, placeholder, message role/index — plus the full obfuscated prompt sent to the LLM and the raw response received before de-obfuscation |

```bash
# Default (counts only)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Entity details + full payload visibility
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

## Testing

```bash
# All tests (100 tests)
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

## Key Constraints

- **Single worker only** — `--workers 1` required (session map is in-process memory)
- **No session TTL** — restart to clear sensitive data
- **IPv6 not detected** — only loopback `::1` in safe list
- **No authentication** — operates on localhost only
- **Volatile storage** — session map is memory-only by design
- **Placeholder collision edge case** — if user types `[IP_ADDRESS_0]` literally, it will be back-substituted

## Project Structure

```
ObfusProxy/
├── .venv/                  # Virtual environment (uv)
├── app/
│   ├── main.py            # FastAPI app + routes
│   ├── config.py          # Pydantic config schema
│   ├── log.py             # TRACE log level definition
│   ├── pipeline.py        # Obfuscate → route → deobfuscate
│   ├── router.py          # LiteLLM wrapper
│   ├── deobfuscator.py    # Streaming de-obfuscation
│   └── privacy/
│       ├── engine.py      # PrivacyEngine
│       ├── session.py     # SessionMap
│       ├── factory.py     # Detector factory (single or composite)
│       └── backends/
│           ├── base.py        # Detector ABC + Entity + resolve_overlaps()
│           ├── regex.py       # RegexDetector — structured PII
│           ├── composite.py   # CompositeDetector — wraps N backends
│           └── presidio.py    # PresidioDetector — NER (optional)
├── tests/
│   ├── conftest.py            # Shared fixtures
│   ├── test_regex.py          # RegexDetector (24 tests)
│   ├── test_session.py        # SessionMap (17 tests)
│   ├── test_engine.py         # PrivacyEngine (15 tests)
│   ├── test_deobfuscator.py   # Streaming de-obfuscation (13 tests)
│   ├── test_composite.py      # CompositeDetector (8 tests)
│   └── test_config.py         # Config loading and validation (11 tests)
├── config.yaml            # Configuration
├── pyproject.toml         # Dependencies
├── CLAUDE.md              # Claude Code guide (setup, testing, troubleshooting)
└── README.md              # This file
```

## Future Stages

- **Stage 3:** Redis session store, multi-worker support, session TTL + eviction, Prometheus metrics
- **Stage 4+:** BERT NER backend, IPv6 CIDR detection, keyring integration, hot-config reload, audit logging

## Development

### Adding a New Entity Pattern

Edit `app/privacy/backends/regex.py` — add to `_PATTERNS` list. Add a test case to `tests/test_regex.py`. No other files change.

### Adding a New Backend

1. Create `app/privacy/backends/newbackend.py` implementing the `Detector` ABC
2. Add one `elif` block in `app/privacy/factory.py`
3. Optionally add to `[project.optional-dependencies]` in `pyproject.toml`

## License

MIT
