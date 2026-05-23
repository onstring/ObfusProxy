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
            r"(?:"
            # Generic credentials
            r"DATABASE_URL|CONN_STR|CONNSTRING|CONNECTION_STRING|TRANSPORT_URL|"
            r"PRIVATE_KEY|SECRET_KEY|PASSWORD|SECRET|API_SECRET|DB_PASSWORD|CELERY_BROKER_URL|"
            # Cloud provider credentials
            r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
            r"GCP_SERVICE_ACCOUNT_KEY|GOOGLE_APPLICATION_CREDENTIALS|"
            r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID|"
            # SaaS API tokens
            r"GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|"
            r"GITLAB_TOKEN|GITLAB_PAT|"
            r"STRIPE_SECRET_KEY|STRIPE_API_KEY|STRIPE_WEBHOOK_SECRET|"
            r"DATADOG_API_KEY|DD_API_KEY|DATADOG_APP_KEY|"
            r"PAGERDUTY_API_KEY|PAGERDUTY_TOKEN|"
            r"SENDGRID_API_KEY|MAILGUN_API_KEY|"
            r"TWILIO_AUTH_TOKEN|TWILIO_ACCOUNT_SID|"
            r"SLACK_TOKEN|SLACK_WEBHOOK_URL|SLACK_SIGNING_SECRET|"
            # Infra / secrets management
            r"VAULT_TOKEN|VAULT_ROLE_SECRET_ID|"
            # Datastore URLs (typically embed credentials)
            r"REDIS_URL|MONGO_URL|MONGODB_URI|RABBITMQ_URL|KAFKA_SASL_PASSWORD"
            r")\s*[=:]\s*\S+",
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
    # Service-specific token prefixes — patterns ported from gitleaks rules.
    # Near-zero false-positive rate: each prefix uniquely identifies the issuer.
    _Pattern(
        "API_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS STS temporary access key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),  # Stripe secret key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),  # Stripe restricted key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub PAT / OAuth / user / server / refresh
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20,}\b"),  # GitLab personal access token
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bxox[bpaors]-[0-9]{10,}-[0-9a-zA-Z\-]+"),  # Slack tokens
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),  # npm token
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),  # SendGrid API key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bAC[a-f0-9]{32}\b"),  # Twilio Account SID
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),  # Google API key
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\bhvs\.[A-Za-z0-9_\-]{20,}\b"),  # HashiCorp Vault token (new format)
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"(?<![A-Za-z0-9])s\.[A-Za-z0-9]{24}(?![A-Za-z0-9])"),  # Vault legacy service token
    ),
    _Pattern(
        "API_KEY",
        re.compile(r"\beyJ[A-Za-z0-9_=\-]+\.eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_.+/=\-]+"),  # JWT
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

