"""
Secret detection backend using detect-secrets RegexBasedDetector plugins.

All entities produced here have redact_only=True — they become [REDACTED:TYPE]
placeholders with no session-map entry and no round-trip restoration.

Two detection layers:
  1. detect-secrets plugins (service-specific token prefixes, well-maintained).
     Uses plugin.denylist regex patterns directly via finditer() for full char
     offsets. BasicAuthDetector uses group(1) to isolate the password, preserving
     DSN host/db context.
  2. Custom patterns filling gaps detect-secrets doesn't cover for unquoted text:
     AWS ARN, DSN URLs, env-var assignments, and Password= connection strings.
"""
import importlib
import re
from dataclasses import dataclass

from .base import Detector, Entity, resolve_overlaps


# ---------------------------------------------------------------------------
# detect-secrets plugin registry
# Each entry: (module_path, class_name, entity_type, capture_group)
# capture_group=1 for patterns where group(1) isolates the secret value;
# 0 = use the full match (group 0).
# ---------------------------------------------------------------------------
_PLUGIN_REGISTRY: list[tuple[str, str, str, int]] = [
    ("detect_secrets.plugins.artifactory", "ArtifactoryDetector", "ARTIFACTORY_KEY", 0),
    ("detect_secrets.plugins.aws", "AWSKeyDetector", "AWS_KEY", 0),
    ("detect_secrets.plugins.azure_storage_key", "AzureStorageKeyDetector", "AZURE_KEY", 0),
    ("detect_secrets.plugins.basic_auth", "BasicAuthDetector", "BASIC_AUTH", 1),
    ("detect_secrets.plugins.cloudant", "CloudantDetector", "CLOUDANT_KEY", 0),
    ("detect_secrets.plugins.discord", "DiscordBotTokenDetector", "DISCORD_TOKEN", 0),
    ("detect_secrets.plugins.github_token", "GitHubTokenDetector", "GITHUB_TOKEN", 0),
    ("detect_secrets.plugins.gitlab_token", "GitLabTokenDetector", "GITLAB_TOKEN", 0),
    ("detect_secrets.plugins.ibm_cloud_iam", "IbmCloudIamDetector", "IBM_IAM_KEY", 0),
    ("detect_secrets.plugins.ibm_cos_hmac", "IbmCosHmacDetector", "IBM_HMAC_KEY", 0),
    ("detect_secrets.plugins.jwt", "JwtTokenDetector", "JWT", 0),
    ("detect_secrets.plugins.mailchimp", "MailchimpDetector", "MAILCHIMP_KEY", 0),
    ("detect_secrets.plugins.npm", "NpmDetector", "NPM_TOKEN", 0),
    ("detect_secrets.plugins.openai", "OpenAIDetector", "OPENAI_KEY", 0),
    ("detect_secrets.plugins.private_key", "PrivateKeyDetector", "PRIVATE_KEY", 0),
    ("detect_secrets.plugins.pypi_token", "PypiTokenDetector", "PYPI_TOKEN", 0),
    ("detect_secrets.plugins.sendgrid", "SendGridDetector", "SENDGRID_KEY", 0),
    ("detect_secrets.plugins.slack", "SlackDetector", "SLACK_TOKEN", 0),
    ("detect_secrets.plugins.softlayer", "SoftlayerDetector", "SOFTLAYER_KEY", 0),
    ("detect_secrets.plugins.square_oauth", "SquareOAuthDetector", "SQUARE_TOKEN", 0),
    ("detect_secrets.plugins.stripe", "StripeDetector", "STRIPE_KEY", 0),
    ("detect_secrets.plugins.telegram_token", "TelegramBotTokenDetector", "TELEGRAM_TOKEN", 0),
    ("detect_secrets.plugins.twilio", "TwilioKeyDetector", "TWILIO_KEY", 0),
]


# ---------------------------------------------------------------------------
# Custom patterns filling detect-secrets gaps for unquoted text
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _CustomPattern:
    entity_type: str
    regex: re.Pattern
    group: int = 0


_CUSTOM_PATTERNS: list[_CustomPattern] = [
    # Stripe test-mode keys — detect-secrets StripeDetector only matches sk_live_.
    # Test keys are real credentials (work against Stripe's test API), so redact them.
    _CustomPattern("STRIPE_KEY", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    _CustomPattern("STRIPE_KEY", re.compile(r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b")),
    # npm bare tokens — detect-secrets NpmDetector only matches .npmrc authToken= format.
    _CustomPattern("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b")),
    # AWS ARN — not in detect-secrets; account ID inside is sensitive
    _CustomPattern(
        "AWS_ARN",
        re.compile(r"arn:[a-z0-9\-]+:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+"),
    ),
    # Full PEM key block — detect-secrets PrivateKeyDetector matches only the header line;
    # this pattern redacts the whole block for complete coverage
    _CustomPattern(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----"
            r"[\s\S]*?"
            r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----"
        ),
    ),
    # DSN URLs — BasicAuthDetector only captures the password; this catches the whole URL
    # in unquoted contexts where BasicAuth won't fire (no surrounding quotes)
    _CustomPattern(
        "SECRET",
        re.compile(
            r"(postgres|mysql|mongodb|redis|amqp|smtp)://[^\s:]+:[^\s@]+@[^\s/]+",
            re.IGNORECASE,
        ),
    ),
    # Env-var assignments with known dangerous variable names (YAML/shell/env format)
    _CustomPattern(
        "SECRET",
        re.compile(
            r"(?:"
            r"DATABASE_URL|CONN_STR|CONNSTRING|CONNECTION_STRING|TRANSPORT_URL|"
            r"PRIVATE_KEY|SECRET_KEY|PASSWORD|SECRET|API_SECRET|DB_PASSWORD|CELERY_BROKER_URL|"
            r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
            r"GCP_SERVICE_ACCOUNT_KEY|GOOGLE_APPLICATION_CREDENTIALS|"
            r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID|"
            r"GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|"
            r"GITLAB_TOKEN|GITLAB_PAT|"
            r"STRIPE_SECRET_KEY|STRIPE_API_KEY|STRIPE_WEBHOOK_SECRET|"
            r"DATADOG_API_KEY|DD_API_KEY|DATADOG_APP_KEY|"
            r"PAGERDUTY_API_KEY|PAGERDUTY_TOKEN|"
            r"SENDGRID_API_KEY|MAILGUN_API_KEY|"
            r"TWILIO_AUTH_TOKEN|TWILIO_ACCOUNT_SID|"
            r"SLACK_TOKEN|SLACK_WEBHOOK_URL|SLACK_SIGNING_SECRET|"
            r"VAULT_TOKEN|VAULT_ROLE_SECRET_ID|"
            r"REDIS_URL|MONGO_URL|MONGODB_URI|RABBITMQ_URL|KAFKA_SASL_PASSWORD"
            r")\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
    ),
    # Password= connection string syntax (e.g. ADO.NET, ODBC)
    _CustomPattern(
        "SECRET",
        re.compile(r"(?:Password|PWD)\s*=\s*[^;]+;", re.IGNORECASE),
    ),
]


class DetectSecretsBackend(Detector):
    """
    Secret detection using detect-secrets RegexBasedDetector plugin patterns.

    Accesses each plugin's compiled regex patterns (plugin.denylist) directly
    via finditer() to obtain character offsets — avoiding detect-secrets' line-
    number-only API while reusing its curated, community-maintained pattern sets.

    All entities are flagged redact_only=True for one-way terminal redaction.
    """

    def __init__(self, enabled_types: list[str] | None = None) -> None:
        self._enabled: set[str] | None = set(enabled_types) if enabled_types else None
        self._plugin_denylist = self._build_plugin_denylist()

    @property
    def name(self) -> str:
        return "detect_secrets"

    def _build_plugin_denylist(self) -> list[tuple[str, list[tuple[re.Pattern, int]]]]:
        """Load plugins and extract (entity_type, [(pattern, group), ...]) tuples."""
        result: list[tuple[str, list[tuple[re.Pattern, int]]]] = []
        for mod_path, class_name, entity_type, group in _PLUGIN_REGISTRY:
            try:
                mod = importlib.import_module(mod_path)
                plugin_cls = getattr(mod, class_name)
                plugin = plugin_cls()
                denylist = plugin.denylist
                if denylist:
                    result.append((entity_type, [(pat, group) for pat in denylist]))
            except (ImportError, AttributeError):
                pass
        return result

    def detect(self, text: str) -> list[Entity]:
        raw: list[Entity] = []

        # detect-secrets plugin patterns
        for entity_type, patterns in self._plugin_denylist:
            if self._enabled and entity_type not in self._enabled:
                continue
            for pattern, group in patterns:
                for m in pattern.finditer(text):
                    try:
                        span_text = m.group(group)
                        start = m.start(group)
                        end = m.end(group)
                    except IndexError:
                        span_text = m.group(0)
                        start, end = m.start(0), m.end(0)
                    if span_text:
                        raw.append(Entity(
                            type=entity_type,
                            start=start,
                            end=end,
                            text=span_text,
                            redact_only=True,
                        ))

        # Custom patterns covering detect-secrets gaps
        for cp in _CUSTOM_PATTERNS:
            if self._enabled and cp.entity_type not in self._enabled:
                continue
            for m in cp.regex.finditer(text):
                try:
                    span_text = m.group(cp.group)
                    start = m.start(cp.group)
                    end = m.end(cp.group)
                except IndexError:
                    span_text = m.group(0)
                    start, end = m.start(0), m.end(0)
                if span_text:
                    raw.append(Entity(
                        type=cp.entity_type,
                        start=start,
                        end=end,
                        text=span_text,
                        redact_only=True,
                    ))

        raw.sort(key=lambda e: e.start)
        return resolve_overlaps(raw)
