# Secret Detection — Layer 3 (Entropy-Based) — Superseded

**Status:** Superseded. The detect-secrets backend (`app/privacy/backends/secrets_backend.py`)
now covers entropy detection via `Base64HighEntropyString` and `HexHighEntropyString` plugins
from the detect-secrets library.

Note: detect-secrets entropy plugins only match secrets in **quoted strings** (e.g., `key = 'TOKEN'`).
Unquoted entropy detection (plain `key = TOKEN` without quotes) requires the custom entropy
algorithm described in this document, which has not been implemented.

If real proxy traffic shows high-entropy secrets in unquoted contexts slipping through,
implement `EntropyDetector` as a fourth backend using the algorithm below and wire it
into `factory.py` as `type: "entropy"`.

---

The original design notes are preserved below for reference.

## Algorithm — Shannon entropy with context guard

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

### Thresholds (from detect-secrets)

| Charset | Min token length | Entropy threshold |
|---|---|---|
| Base64 | 20 chars | 4.5 bits/char |
| Hex | 20 chars | 3.0 bits/char |

### Context guard

Only score tokens after assignment operators or within ~5 chars of keywords:
`key`, `secret`, `token`, `password`, `auth`, `credential`, `bearer`.

### False-positive mitigations

Skip: UUIDs, Git SHAs (preceded by "commit"), Docker digests (`sha256:`), ETags.
