# ObfusProxy

A local LLM privacy proxy for DevOps. Sits between your tools (Claude Code, curl, any OpenAI-SDK client) and cloud LLM providers — transparently scrubbing sensitive data before it leaves your machine and restoring context in responses.

## How It Works

Two obfuscation modes run in parallel:

| Mode | What | Placeholder | Round-trip |
|---|---|---|---|
| **Reversible** | Emails, IPs, CIDRs, domains, ports | `[DOMAIN_0]`, `[IP_ADDRESS_1]` | ✓ Restored in response |
| **Redact-only** | API keys, tokens, passwords, secrets | `[REDACTED:GITHUB_TOKEN]` | ✗ Gone, never restored |

Context-bearing entities are reversible so the LLM can reason about them (`[DOMAIN_0]` in a question becomes `db.corp.internal` in the answer). Secrets have no useful value to the LLM — they're dropped entirely.

## Quick Start

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Install secret detection (required for default config)
uv pip install "detect-secrets>=1.5.0"

# 3. Start the proxy
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# 4. Point Claude Code at the proxy (in a separate terminal)
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-<your-real-key>   # or: claude login
claude
```

No API key is required in the proxy's environment. The proxy forwards whatever credentials the client sends — real API key or OAuth subscription token.

## Detection Backends

Three composable backends, ordered in `config.yaml`:

| Backend | Type | Entities |
|---|---|---|
| `regex` | context-bearing PII | `EMAIL_ADDRESS`, `IP_ADDRESS`, `CIDR`, `DOMAIN`, `PORT` |
| `detect_secrets` | secret-class, redact-only | API keys, tokens, DSN URLs, env-var credentials, PEM keys, and 20+ service-specific token formats (GitHub, AWS, Stripe, Slack, GitLab, JWT, npm, Twilio, OpenAI, …) |
| `presidio` | unstructured NER (optional) | `PERSON`, `PHONE_NUMBER`, `CREDIT_CARD` |

The `detect_secrets` backend uses [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) plugin patterns directly — no hand-maintained regex for secrets.

### Install Optional Backends

```bash
# Secret detection (included in default config)
uv pip install "detect-secrets>=1.5.0"

# NER (names, phone numbers, credit cards)
uv pip install "presidio-analyzer>=2.2.0"
python -m spacy download en_core_web_lg
```

## Configuration

```yaml
privacy:
  backends:
    - type: "regex"           # context-bearing entities
    - type: "detect_secrets"  # secrets — redacted one-way
    # - type: "presidio"      # optional NER
    #   model: "en_core_web_lg"
  entities:
    - EMAIL_ADDRESS
    - IP_ADDRESS
    - CIDR
    - DOMAIN
    - GITHUB_TOKEN
    - AWS_KEY
    - STRIPE_KEY
    - SECRET          # DSN URLs, env-var assignments, Password= strings
    # ... see config.yaml for full list
  whitelist:
    loopback: ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
    ip_ranges: []     # RFC 1918 always safe; add extra CIDRs here
    domains: ["api.anthropic.com", "github.com"]
```

## Architecture

```
Client (Claude Code / curl / SDK)
  │
  │  Authorization: Bearer <token>  ← forwarded unchanged
  │
  ▼
FastAPI gateway  (X-Session-Id minted or read)
  │
  ├─ PrivacyEngine.obfuscate  (user + tool messages only)
  │    CompositeDetector
  │      ├─ RegexDetector         → [EMAIL_0], [DOMAIN_1], …  (reversible)
  │      ├─ DetectSecretsBackend  → [REDACTED:GITHUB_TOKEN]   (one-way)
  │      └─ PresidioDetector      → [PERSON_2]                (optional)
  │
  ├─ /v1/messages          → httpx         → api.anthropic.com
  │  /v1/chat/completions  → litellm       → any provider
  │
  ├─ ResponseDeobfuscator  (restores reversible placeholders only)
  │
  └─ Client receives clean response
```

### What Gets Obfuscated

| Role | Obfuscated? |
|---|---|
| `user` | Yes |
| `tool` / `tool_result` | Yes |
| `assistant` | No — LLM output |
| `system` | No — client instructions |

## Logging

```bash
# Counts only (default)
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Show what was redacted to what
OBFUSPROXY_LOG_LEVEL=DEBUG uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1

# Full payloads
OBFUSPROXY_LOG_LEVEL=TRACE uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

## Testing

```bash
pytest                          # 130 tests
pytest --cov=app --cov-report=term-missing
```

## Secret Scanning (Pre-commit)

A [detect-secrets](https://github.com/Yelp/detect-secrets) pre-commit hook prevents accidental credential commits. Install once after cloning:

```bash
uv pip install pre-commit
pre-commit install
```

To update the baseline after adding doc examples or other known-safe strings:

```bash
detect-secrets scan --baseline .secrets.baseline
git add .secrets.baseline
```

## Constraints

- **`--workers 1` required** — session map is in-process memory
- **No session TTL** — restart to clear sensitive data
- **No proxy authentication** — localhost-only by design
- **IPv6 not detected** — only loopback `::1` in safe list

## Project Structure

```
app/
├── main.py            # FastAPI app + routes
├── pipeline.py        # obfuscate → route → deobfuscate
├── router.py          # LiteLLM wrapper
├── deobfuscator.py    # streaming-safe placeholder restoration
└── privacy/
    ├── engine.py      # PrivacyEngine
    ├── session.py     # SessionMap (asyncio-safe, in-memory)
    ├── factory.py     # config → Detector (or CompositeDetector)
    └── backends/
        ├── base.py             # Detector ABC, Entity, resolve_overlaps()
        ├── regex.py            # context-bearing PII (email, IP, domain…)
        ├── secrets_backend.py  # detect-secrets wrapper, redact-only
        ├── composite.py        # merges N backends, resolves overlaps
        └── presidio.py         # NER via spaCy (optional)
```

## License

MIT
