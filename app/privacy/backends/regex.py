import ipaddress
import re
from dataclasses import dataclass
from .base import Detector, Entity, resolve_overlaps


# RFC documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) — always safe
SAFE_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


@dataclass(frozen=True)
class _Pattern:
    entity_type: str
    regex: re.Pattern
    group: int = 0


_PATTERNS = [
    _Pattern(
        "AWS_ARN",
        re.compile(r"arn:[a-z0-9\-]+:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+"),
    ),
    _Pattern(
        "SECRET",
        re.compile(
            r"(postgres|mysql|mongodb|redis|amqp|smtp)://[^\s:]+:[^\s@]+@[^\s/]+",
            re.IGNORECASE,
        ),
    ),
    _Pattern(
        "SECRET",
        re.compile(
            r"(?:DATABASE_URL|CONN_STR|CONNSTRING|CONNECTION_STRING|TRANSPORT_URL|PRIVATE_KEY|SECRET_KEY|PASSWORD|SECRET|API_SECRET|DB_PASSWORD|CELERY_BROKER_URL)\s*=\s*[^\s]+",
            re.IGNORECASE,
        ),
    ),
    _Pattern(
        "SECRET",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ),
    _Pattern(
        "SECRET",
        re.compile(r"(?:Password|PWD)\s*=\s*[^;]+;", re.IGNORECASE),
    ),
    _Pattern(
        "EMAIL_ADDRESS",
        re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    ),
    _Pattern(
        "CIDR",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/(?:3[0-2]|[12]?\d)\b"
        ),
    ),
    _Pattern(
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"sk-[A-Za-z0-9\-]{20,}"),
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32,64}(?![A-Za-z0-9])"),
    ),
    _Pattern(
        "PORT",
        re.compile(r"(?::(\d{1,5})\b)|(?:\bport\s+(\d{1,5})\b)", re.IGNORECASE),
        group=1,
    ),
    _Pattern(
        "DOMAIN",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:internal|local|corp|svc|cluster\.local|dev|staging|qa)\b",
            re.IGNORECASE,
        ),
    ),
]


class RegexDetector(Detector):
    """Regex-based PII/NER detector using stdlib re module."""

    def __init__(
        self,
        enabled_types: list[str] | None = None,
        whitelist: frozenset[str] | None = None,
        ip_ranges: list[str] | None = None,
    ) -> None:
        self._enabled = set(enabled_types) if enabled_types else None
        self._whitelist = whitelist or frozenset()
        self._ip_nets = [ipaddress.ip_network(r, strict=False) for r in (ip_ranges or [])]

    @property
    def name(self) -> str:
        return "regex"

    def detect(self, text: str) -> list[Entity]:
        raw: list[Entity] = []

        for pattern in _PATTERNS:
            if self._enabled and pattern.entity_type not in self._enabled:
                continue

            for m in pattern.regex.finditer(text):
                span_text = m.group(pattern.group)
                if not span_text:
                    continue

                start = m.start(pattern.group)
                end = m.end(pattern.group)

                if self._is_safe(pattern.entity_type, span_text):
                    continue

                raw.append(
                    Entity(
                        type=pattern.entity_type,
                        start=start,
                        end=end,
                        text=span_text,
                    )
                )

        raw.sort(key=lambda e: e.start)
        return resolve_overlaps(raw)

    def _is_safe(self, entity_type: str, text: str) -> bool:
        if text in self._whitelist:
            return True

        if entity_type in ("IP_ADDRESS", "CIDR"):
            if any(text.startswith(p) for p in SAFE_PREFIXES):
                return True
            if self._ip_nets and self._in_safe_range(text):
                return True

        if entity_type == "PORT":
            try:
                if int(text) > 65535:
                    return True
            except ValueError:
                return True

        return False

    def _in_safe_range(self, text: str) -> bool:
        """Return True if text (IP or CIDR) falls within any configured safe ip_range."""
        try:
            net = ipaddress.ip_network(text, strict=False)
            return any(net.overlaps(safe) for safe in self._ip_nets)
        except ValueError:
            return False

