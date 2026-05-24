"""Tests for DetectSecretsBackend — service-specific token detection and redact_only flag.

Test fixtures use string concatenation to avoid GitHub push-protection scanners
flagging the source file while keeping runtime values intact.
"""
import pytest

from app.privacy.backends.secrets_backend import DetectSecretsBackend


def detect(text: str, **kwargs) -> list:
    return DetectSecretsBackend(**kwargs).detect(text)


def types(text: str, **kwargs) -> set[str]:
    return {e.type for e in detect(text, **kwargs)}


def entity_texts(text: str, **kwargs) -> list[str]:
    return [e.text for e in detect(text, **kwargs)]


# ---------------------------------------------------------------------------
# All entities are redact_only=True
# ---------------------------------------------------------------------------

class TestRedactOnly:
    def test_github_token_is_redact_only(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        entities = detect(f"token: {token}")
        assert entities
        assert all(e.redact_only for e in entities)

    def test_secret_pattern_is_redact_only(self):
        entities = detect("VAULT_TOKEN=randomopaquevalue123")
        assert entities
        assert all(e.redact_only for e in entities)

    def test_aws_arn_is_redact_only(self):
        entities = detect("Role: arn:aws:iam::123456789012:role/DevRole")
        assert entities
        assert all(e.redact_only for e in entities)


# ---------------------------------------------------------------------------
# Service-specific token detection (via detect-secrets plugin denylist)
# ---------------------------------------------------------------------------

class TestServiceTokens:
    def test_github_pat(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        assert token in entity_texts(f"GitHub: {token} fetched")
        assert "GITHUB_TOKEN" in types(f"GitHub: {token} fetched")

    def test_github_oauth(self):
        token = "gho" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        assert "GITHUB_TOKEN" in types(f"OAuth {token} returned")

    def test_gitlab_pat(self):
        token = "glpat" + "-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"
        assert "GITLAB_TOKEN" in types(f"GitLab token {token} ok")

    def test_aws_access_key(self):
        token = "AKIA" + "IOSFODNN7EXAMPLE"
        assert "AWS_KEY" in types(f"Use {token} for access.")

    def test_aws_sts_key(self):
        token = "ASIA" + "IOSFODNN7EXAMPLE"
        assert "AWS_KEY" in types(f"Temp creds: {token} here.")

    def test_stripe_live_key(self):
        token = "sk_" + "live_51Hb3kLJZ8qKO2aBc1234EXAMPLEKEY"
        assert "STRIPE_KEY" in types(f"Stripe key {token} prod")

    def test_stripe_test_key(self):
        token = "sk_" + "test_51Hb3kLJZ8qKO2aBc1234EXAMPLEKEY"
        assert "STRIPE_KEY" in types(f"Test mode {token} ok")

    def test_slack_bot_token(self):
        token = "xoxb" + "-1234567890-abcdef1234567890"
        assert "SLACK_TOKEN" in types(f"Slack bot {token} authorized")

    def test_npm_token(self):
        token = "npm" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        assert "NPM_TOKEN" in types(f"npm publish with {token} done")

    def test_jwt(self):
        token = ("eyJ" + "hbGciOiJIUzI1NiJ9"
                 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
                 + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assert "JWT" in types(f"JWT {token} validated")


# ---------------------------------------------------------------------------
# BasicAuthDetector — password extracted from DSN (group 1)
# ---------------------------------------------------------------------------

class TestBasicAuth:
    def test_http_basic_auth_password_extracted(self):
        # HTTP URLs match BasicAuthDetector (group 1 = password only).
        # DSN URLs (postgres://, redis://) are caught earlier by the DSN custom pattern.
        line = "curl https://user:supersecret@api.example.com/endpoint"
        entities = detect(line)
        basic_auth = [e for e in entities if e.type == "BASIC_AUTH"]
        assert basic_auth, "expected BASIC_AUTH entity"
        assert basic_auth[0].text == "supersecret"

    def test_dsn_url_caught_as_secret(self):
        # DSN URLs are matched by the custom DSN pattern → SECRET (whole URL),
        # not BASIC_AUTH, since the DSN match (start=0) shadows the BasicAuth match.
        line = "postgres://user:supersecret@db.corp.internal/mydb"
        entities = detect(line)
        assert any(e.type == "SECRET" for e in entities)
        # Whole URL is redacted — host/db context is lost, but that's acceptable
        # since env-var form (DATABASE_URL=...) preserves context via label.


# ---------------------------------------------------------------------------
# Custom patterns — AWS ARN, DSN, env-var assignments, PEM, Password=
# ---------------------------------------------------------------------------

class TestCustomPatterns:
    def test_aws_arn_iam_role(self):
        assert "AWS_ARN" in types("Role: arn:aws:iam::123456789012:role/DevRole")

    def test_aws_arn_s3(self):
        assert "AWS_ARN" in types("arn:aws:s3:us-east-1:123456789012:my-bucket/key")

    def test_dsn_url(self):
        assert "SECRET" in types("postgres://user:p@ssw0rd@db.corp.internal/mydb")

    def test_password_env_var(self):
        assert "SECRET" in types("PASSWORD=supersecret123")

    def test_env_var_github_token(self):
        assert "SECRET" in types("GITHUB_TOKEN=somevaluewithoutprefix12345")

    def test_env_var_vault_token(self):
        assert "SECRET" in types("VAULT_TOKEN=randomopaquetoken123")

    def test_env_var_colon_yaml_style(self):
        assert "SECRET" in types("VAULT_TOKEN: hvs.opaquevalue")

    def test_env_var_case_insensitive(self):
        val = "AKIA" + "IOSFODNN7EXAMPLE"
        assert "SECRET" in types(f"aws_access_key_id={val}")

    def test_pem_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----"
        assert "PRIVATE_KEY" in types(pem)

    def test_pem_rsa_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END RSA PRIVATE KEY-----"
        assert "PRIVATE_KEY" in types(pem)

    def test_password_connection_string(self):
        assert "SECRET" in types("Password=abc123;Server=db;")

    def test_pagerduty_api_key_env(self):
        assert "SECRET" in types("PAGERDUTY_API_KEY=pdU+abc123XYZ==")

    def test_datadog_api_key_env(self):
        assert "SECRET" in types("DD_API_KEY=abc123def456")


# ---------------------------------------------------------------------------
# enabled_types filter
# ---------------------------------------------------------------------------

class TestEnabledTypes:
    def test_filter_to_github_token(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        text = f"{token} and also VAULT_TOKEN=secret123"
        d = DetectSecretsBackend(enabled_types=["GITHUB_TOKEN"])
        result = d.detect(text)
        assert all(e.type == "GITHUB_TOKEN" for e in result)
        assert result

    def test_disabled_type_not_detected(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        d = DetectSecretsBackend(enabled_types=["AWS_KEY"])
        result = d.detect(f"token: {token}")
        assert not result

    def test_no_filter_detects_multiple_types(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        text = f"GitHub: {token} and VAULT_TOKEN=secretvalue123"
        detected_types = types(text)
        assert "GITHUB_TOKEN" in detected_types
        assert "SECRET" in detected_types


# ---------------------------------------------------------------------------
# Character offset correctness
# ---------------------------------------------------------------------------

class TestOffsets:
    def test_github_token_offset(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        text = f"token: {token} end"
        entities = detect(text)
        github = [e for e in entities if e.type == "GITHUB_TOKEN"]
        assert github
        e = github[0]
        assert text[e.start:e.end] == e.text

    def test_multiline_offsets_correct(self):
        token = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        text = f"first line\nsecond line with {token}\nthird line"
        entities = detect(text)
        for e in entities:
            assert text[e.start:e.end] == e.text, (
                f"Offset mismatch for {e.type}: expected {repr(e.text)}, "
                f"got {repr(text[e.start:e.end])}"
            )


# ---------------------------------------------------------------------------
# No false positives on benign text
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_plain_english_no_match(self):
        result = detect("The quick brown fox jumps over the lazy dog.")
        assert not result

    def test_short_hex_no_match(self):
        result = detect("Id: abcdef123456")
        assert not result
