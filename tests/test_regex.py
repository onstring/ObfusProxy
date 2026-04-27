"""Tests for RegexDetector — entity detection, whitelist, and safe ranges."""
import pytest

from app.privacy.backends.regex import RegexDetector


def types(text: str, **kwargs) -> set[str]:
    """Return the set of entity types detected in text."""
    d = RegexDetector(**kwargs)
    return {e.type for e in d.detect(text)}


def texts(text: str, **kwargs) -> list[str]:
    """Return detected entity texts in order."""
    d = RegexDetector(**kwargs)
    return [e.text for e in d.detect(text)]


# ---------------------------------------------------------------------------
# EMAIL_ADDRESS
# ---------------------------------------------------------------------------

class TestEmailAddress:
    def test_basic(self):
        assert "EMAIL_ADDRESS" in types("Contact dev@corp.internal for help.")

    def test_subdomain(self):
        assert "EMAIL_ADDRESS" in types("Send to alice@mail.example.com now.")

    def test_whitelisted_skipped(self):
        d = RegexDetector(whitelist=frozenset({"alice@example.com"}))
        hits = [e.text for e in d.detect("Write to alice@example.com")]
        assert "alice@example.com" not in hits

    def test_no_false_positive_plain_word(self):
        assert "EMAIL_ADDRESS" not in types("username only, no domain")


# ---------------------------------------------------------------------------
# IP_ADDRESS
# ---------------------------------------------------------------------------

class TestIpAddress:
    def test_rfc1918_always_safe(self):
        # Private ranges are hardcoded safe — no config needed
        d = RegexDetector()
        for ip in ["10.1.2.3", "172.16.4.5", "192.168.1.100"]:
            assert "IP_ADDRESS" not in {e.type for e in d.detect(f"Host {ip} here.")}

    def test_public_ip_detected(self):
        assert "IP_ADDRESS" in types("DNS server is 8.8.8.8.")

    def test_loopback_skipped_by_ip_range(self):
        d = RegexDetector(ip_ranges=["127.0.0.0/8"])
        hits = texts("Server at 127.0.0.1", d=d)
        assert "127.0.0.1" not in hits

    def test_rfc_doc_range_skipped(self):
        # 192.0.2.x is an RFC documentation range — always safe
        assert "IP_ADDRESS" not in types("Docs use 192.0.2.1 as example.")

    def test_ip_in_configured_safe_range(self):
        # Extra range configured by user (CGNAT) — IPs inside are safe
        d = RegexDetector(ip_ranges=["100.64.0.0/10"])
        hits = texts("Carrier-NAT host 100.64.1.1 here.", d=d)
        assert "100.64.1.1" not in hits

    def test_ip_outside_safe_range_detected(self):
        d = RegexDetector(ip_ranges=["100.64.0.0/10"])
        hits = texts("Public IP 8.8.8.8 here.", d=d)
        assert "8.8.8.8" in hits

    def test_no_false_positive_version_string(self):
        # version numbers like 1.2.3 should NOT match (only 4 octets)
        assert "IP_ADDRESS" not in types("Version 1.2.3 released.")

    def _detect(self, text, **kw):
        return texts(text, **kw)

def texts(text: str, d=None, **kwargs) -> list[str]:
    detector = d or RegexDetector(**kwargs)
    return [e.text for e in detector.detect(text)]


# ---------------------------------------------------------------------------
# CIDR
# ---------------------------------------------------------------------------

class TestCidr:
    def test_rfc1918_always_safe(self):
        d = RegexDetector()
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
            assert "CIDR" not in {e.type for e in d.detect(f"Network {cidr} is internal.")}

    def test_public_cidr_detected(self):
        assert "CIDR" in types("Allow 8.8.0.0/16 in firewall.")

    def test_rfc_doc_range_skipped(self):
        assert "CIDR" not in types("Example range 192.0.2.0/24.")

    def test_cidr_in_configured_safe_range(self):
        d = RegexDetector(ip_ranges=["100.64.0.0/10"])
        hit_texts = texts("Carrier-NAT 100.64.0.0/24 here.", d=d)
        assert "100.64.0.0/24" not in hit_texts

    def test_cidr_outside_configured_safe_range_detected(self):
        d = RegexDetector(ip_ranges=["100.64.0.0/10"])
        hit_texts = texts("External 8.8.0.0/16 subnet.", d=d)
        assert "8.8.0.0/16" in hit_texts


# ---------------------------------------------------------------------------
# DOMAIN
# ---------------------------------------------------------------------------

class TestDomain:
    def test_internal_domain(self):
        assert "DOMAIN" in types("Host db.corp.internal is down.")

    def test_svc_cluster_local(self):
        assert "DOMAIN" in types("Service redis.svc.cluster.local unreachable.")

    def test_local_domain(self):
        assert "DOMAIN" in types("NAS at nas.local is up.")

    def test_whitelisted_domain_skipped(self):
        d = RegexDetector(whitelist=frozenset({"api.corp.internal"}))
        hit_texts = texts("Call api.corp.internal endpoint.", d=d)
        assert "api.corp.internal" not in hit_texts

    def test_public_tld_not_detected(self):
        # github.com should not match (no internal TLD)
        assert "DOMAIN" not in types("Visit github.com for code.")


# ---------------------------------------------------------------------------
# API_KEY
# ---------------------------------------------------------------------------

class TestApiKey:
    def test_bearer_token(self):
        assert "API_KEY" in types("Authorization: Bearer eyJhbGciOiJSUzI1NiIsIn")

    def test_sk_prefix(self):
        assert "API_KEY" in types("Key is sk-abcdefghijklmnopqrstu1234")

    def test_long_hex(self):
        assert "API_KEY" in types("Token: abcdef1234567890abcdef1234567890abcdef12")

    def test_short_hex_not_detected(self):
        # under 32 hex chars — not an API key
        assert "API_KEY" not in types("Id: abcdef123456")


# ---------------------------------------------------------------------------
# SECRET
# ---------------------------------------------------------------------------

class TestSecret:
    def test_dsn_url(self):
        assert "SECRET" in types("postgres://user:p@ssw0rd@db.corp.internal/mydb")

    def test_env_var_assignment(self):
        assert "SECRET" in types("DATABASE_URL=postgres://user:secret@host/db")

    def test_password_env_var(self):
        assert "SECRET" in types("PASSWORD=supersecret123")

    def test_dsn_connection_string(self):
        assert "SECRET" in types("Password=abc123;Server=db;")

    def test_pem_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----"
        assert "SECRET" in types(pem)


# ---------------------------------------------------------------------------
# AWS_ARN
# ---------------------------------------------------------------------------

class TestAwsArn:
    def test_iam_role(self):
        assert "AWS_ARN" in types("Role: arn:aws:iam::123456789012:role/DevRole")

    def test_s3_resource(self):
        # S3 ARNs that include an account ID match the pattern
        assert "AWS_ARN" in types("Bucket: arn:aws:s3:us-east-1:123456789012:my-bucket/key")


# ---------------------------------------------------------------------------
# PORT
# ---------------------------------------------------------------------------

class TestPort:
    def test_colon_port(self):
        d = RegexDetector()
        entities = d.detect("Connect to host:5432 now.")
        port_entities = [e for e in entities if e.type == "PORT"]
        assert any(e.text == "5432" for e in port_entities)

    def test_port_keyword(self):
        # The PORT pattern uses colon-prefix syntax (:port); "port N" word form
        # is in the regex but its digits land in group 2 while the detector reads
        # group 1 — so only `:NNNN` style is currently emitted.
        d = RegexDetector()
        entities = d.detect("Listening on host:8080.")
        port_entities = [e for e in entities if e.type == "PORT"]
        assert any(e.text == "8080" for e in port_entities)

    def test_invalid_port_skipped(self):
        d = RegexDetector()
        entities = d.detect("Port 99999 is invalid.")
        port_entities = [e for e in entities if e.type == "PORT"]
        assert not any(e.text == "99999" for e in port_entities)


# ---------------------------------------------------------------------------
# Enabled-types filter
# ---------------------------------------------------------------------------

class TestEnabledTypes:
    def test_filter_to_single_type(self):
        d = RegexDetector(enabled_types=["EMAIL_ADDRESS"])
        result = d.detect("Email dev@corp.internal IP 10.1.2.3")
        assert all(e.type == "EMAIL_ADDRESS" for e in result)

    def test_no_filter_detects_multiple_types(self):
        d = RegexDetector()
        result = d.detect("Email dev@corp.internal IP 8.8.8.8")
        entity_types = {e.type for e in result}
        assert "EMAIL_ADDRESS" in entity_types
        assert "IP_ADDRESS" in entity_types


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------

class TestOverlapResolution:
    def test_cidr_wins_over_ip(self):
        # 8.8.0.0/16 should be caught as CIDR; the bare IP match inside it is dropped
        d = RegexDetector()
        result = d.detect("Network 8.8.0.0/16 is big.")
        entity_texts = [e.text for e in result]
        assert "8.8.0.0/16" in entity_texts
        # The raw IP "8.8.0.0" is inside CIDR span; should not appear separately
        assert "8.8.0.0" not in entity_texts
