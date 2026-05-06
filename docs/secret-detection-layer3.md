# Secret Detection — Layer 3 (Entropy-Based) — Future Reference

**Status:** Not implemented. Layers 1 and 2 (service prefixes + env-var names) cover the common
cases without false-positive risk. This document captures the design for Layer 3 — high-entropy
fallback detection — so the work can be picked up later if real traffic shows unprefixed,
unknown-named secrets slipping through.

## When to revisit

Implement Layer 3 only when you observe in real proxy logs:

- High-entropy random-looking strings in `user`/`tool` content that
- Have no recognizable service prefix (Layer 1 misses), and
- Are not assigned to a known-dangerous env-var name (Layer 2 misses), and
- Are sensitive enough to redact

Until that signal exists, Layer 3 adds noise without proportional value.

## Goal

Detect random-looking, high-entropy tokens (base64 or hex) that lack any structural marker
identifying the issuer or context. Examples that escape Layers 1+2:

```
Some loose token: pdU+abc123XYZ==                     # could be PD, could be base64 image
Random hex:       9f3c8b2a1d7e6f4a8b9c3d2e1f7a8b9c    # could be UUID, hash, key
```

The challenge: free text contains many high-entropy strings that aren't secrets — minified JS,
base64-encoded images, content hashes, UUIDs, Git SHAs, Docker image digests.

## Algorithm — Shannon entropy with context guard

### Core entropy calculation

```python
import math
from collections import Counter

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS = set("0123456789abcdefABCDEF")


def shannon_entropy(s: str, charset: set[str]) -> float:
    counts = Counter(c for c in s if c in charset)
    n = sum(counts.values())
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
```

### Thresholds (defaults from detect-secrets)

| Charset | Min token length | Entropy threshold |
|---|---|---|
| Base64 | 20 chars | 4.5 bits/char |
| Hex | 20 chars | 3.0 bits/char |

These are the values that detect-secrets ships with — proven on millions of code repos. Tune
later if your traffic skews differently.

### Context guard (critical for FP control)

Raw entropy scoring on free text produces ~5–10× more false positives than true positives.
Mitigate by **only scoring tokens that appear in suspicious contexts**:

1. **Following an assignment operator** — `key = TOKEN`, `secret: TOKEN`, `Authorization: Bearer TOKEN`
2. **In a known suspicious key/quote pair** — `"api_key": "TOKEN"`, `password='TOKEN'`
3. **After a keyword token** — case-insensitive proximity (within ~5 chars) to one of:
   `key`, `secret`, `token`, `password`, `auth`, `credential`, `bearer`

Tokens in plain narrative text (not after these markers) are skipped even if high entropy.

### Pseudo-code

```python
class EntropyDetector:
    SUSPICIOUS_KEYWORDS = re.compile(
        r"(?i)\b(key|secret|token|password|auth|credential|bearer)\b"
    )
    ASSIGNMENT = re.compile(r"[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?")

    def detect(self, text: str) -> list[Entity]:
        candidates = []

        # Mode 1: assignment-style
        for m in self.ASSIGNMENT.finditer(text):
            tok = m.group(1)
            if self._is_high_entropy(tok):
                candidates.append((m.start(1), m.end(1), tok))

        # Mode 2: proximity to suspicious keyword
        for kw_match in self.SUSPICIOUS_KEYWORDS.finditer(text):
            window = text[kw_match.end(): kw_match.end() + 80]
            for tok_match in re.finditer(r"[A-Za-z0-9+/=_\-]{20,}", window):
                tok = tok_match.group(0)
                if self._is_high_entropy(tok):
                    abs_start = kw_match.end() + tok_match.start()
                    candidates.append((abs_start, abs_start + len(tok), tok))

        # Deduplicate, sort, build Entity list
        ...

    def _is_high_entropy(self, tok: str) -> bool:
        # Skip if too short
        if len(tok) < 20:
            return False
        # Skip UUIDs (deterministic format, low real entropy in context)
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", tok):
            return False
        # Choose charset and threshold
        if all(c in HEX_CHARS for c in tok):
            return shannon_entropy(tok, HEX_CHARS) >= 3.0
        if all(c in BASE64_CHARS for c in tok):
            return shannon_entropy(tok, BASE64_CHARS) >= 4.5
        return False
```

## Where it fits in the codebase

- New file: `app/privacy/backends/entropy.py` — `EntropyDetector(Detector)` ABC implementation
- Wire into `app/privacy/factory.py` with `elif backend_cfg.type == "entropy":`
- Add to config:
  ```yaml
  privacy:
    backends:
      - type: "regex"
      - type: "presidio"
      - type: "entropy"
        base64_threshold: 4.5    # optional override
        hex_threshold: 3.0       # optional override
  ```
- Composite ordering: regex first (cheap, exact), presidio second, entropy last (fallback)
- The `CompositeDetector` overlap resolver already gives earlier backends priority — entropy
  matches inside an existing regex/presidio span are dropped automatically

## Known false-positive sources to track

If/when this ships, watch for FPs on:

| Source | Mitigation |
|---|---|
| Git SHAs (40 hex chars) | Skip if preceded by "commit" or "sha" — those are not secrets |
| Docker image digests (`sha256:...`) | Skip the full `sha256:HEX` form |
| Content hashes / ETags | Often appear after `etag:` or `digest:` — could whitelist those contexts |
| UUIDs | Already excluded above by exact-format check |
| Minified JS / base64 images | Body usually starts with `data:image/`, `function(`, etc. — context guard helps |
| Long Slack/Discord IDs | Length 18–20 numeric — typically just below entropy threshold |

## Testing strategy

1. **Positive cases** — assemble a corpus of real secrets without prefixes (anonymized PagerDuty
   keys, internal service tokens, etc.). Each should be detected when in an assignment context.
2. **Negative cases** — Git SHAs, UUIDs, Docker digests, base64-encoded 1×1 PNG, minified JS
   snippets. None should fire.
3. **Threshold sweep** — for tuning, run the detector with thresholds 3.0/3.5/4.0/4.5/5.0 on a
   representative DevOps prompt corpus and pick the knee in the precision/recall curve.

## Why not just port detect-secrets directly

`detect-secrets` is a pre-commit / CI tool, not a real-time text processor:

- Its plugin API hashes matched secrets — the original text is unrecoverable
- It returns line numbers, not character offsets — incompatible with the `Entity` dataclass
- It's designed to scan files, not strings — wraps everything in file-IO abstractions

The algorithms inside are open and reusable (Shannon entropy with charset filters), but the
package itself doesn't fit the inline-proxy use case. Port the math, not the framework.

## References

- gitleaks rules (regex patterns already ported into Layer 1):
  https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- detect-secrets entropy plugins (algorithm reference for Layer 3):
  https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins
- TruffleHog has a similar entropy detector with high-recall/low-precision defaults — useful
  baseline for threshold comparison
