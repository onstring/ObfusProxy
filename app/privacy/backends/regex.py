import ipaddress
import re
from dataclasses import dataclass
from .base import Detector, Entity, resolve_overlaps


# RFC documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) — always safe
SAFE_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

# RFC 1918 private ranges — internal addressing, not externally identifiable
_SAFE_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


@dataclass(frozen=True)
class _Pattern:
    entity_type: str
    regex: re.Pattern
    group: int = 0


_PATTERNS = [
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
        "PORT",
        re.compile(r"(?::(\d{1,5})\b)|(?:\bport\s+(\d{1,5})\b)", re.IGNORECASE),
        group=1,
    ),
    _Pattern(
        "DOMAIN",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:"
            # Internal / infrastructure pseudo-TLDs
            r"internal|local|corp|svc|cluster\.local|consul|nomad|"
            r"dev|staging|qa|test|prod|"
            # Generic TLDs
            r"com|net|org|edu|gov|mil|int|"
            # Tech / cloud new gTLDs
            r"io|co|ai|app|cloud|tech|"
            # Country-code TLDs (omitting short ones that double as English words:
            # in, is, it, at, be, no, me, to, us, as, do)
            r"au|nz|uk|ca|jp|cn|de|fr|nl|se|dk|fi|ch|ru|br|"
            r"sg|hk|tw|kr|pl|cz|es|pt|ie|za|ar|mx|cl|"
            # Other common TLDs
            r"info|biz"
            r")\b",
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
            try:
                net = ipaddress.ip_network(text, strict=False)
                if any(net.overlaps(safe) for safe in _SAFE_PRIVATE_NETS):
                    return True
            except ValueError:
                pass
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

