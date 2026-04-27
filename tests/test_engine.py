"""Tests for PrivacyEngine — obfuscation, deobfuscation, role filtering, tool_result."""
import pytest

from app.privacy.backends.regex import RegexDetector
from app.privacy.engine import PrivacyEngine
from app.privacy.session import SessionMap


def make_engine(enabled_types=None, whitelist=None, ip_ranges=None):
    detector = RegexDetector(
        enabled_types=enabled_types,
        whitelist=whitelist,
        ip_ranges=ip_ranges,
    )
    return PrivacyEngine(detector=detector, session_map=SessionMap())


SESSION = "test-session"


@pytest.mark.asyncio
class TestObfuscateText:
    async def test_replaces_email(self):
        engine = make_engine()
        result = await engine._obfuscate_text("Contact dev@corp.internal", SESSION)
        assert "dev@corp.internal" not in result
        assert "[EMAIL_ADDRESS_" in result

    async def test_placeholder_roundtrip(self):
        engine = make_engine()
        original = "Server at 10.1.2.3 ready."
        obfuscated = await engine._obfuscate_text(original, SESSION)
        restored = await engine.deobfuscate(obfuscated, SESSION)
        assert restored == original

    async def test_idempotent_placeholder(self):
        engine = make_engine()
        r1 = await engine._obfuscate_text("email dev@corp.internal", SESSION)
        r2 = await engine._obfuscate_text("email dev@corp.internal", SESSION)
        assert r1 == r2

    async def test_multiple_entities(self):
        engine = make_engine()
        text = "Email dev@corp.internal IP 10.1.2.3"
        result = await engine._obfuscate_text(text, SESSION)
        assert "dev@corp.internal" not in result
        assert "10.1.2.3" not in result

    async def test_no_entities_unchanged(self):
        engine = make_engine()
        text = "Hello world, nothing sensitive here."
        result = await engine._obfuscate_text(text, SESSION)
        assert result == text


@pytest.mark.asyncio
class TestObfuscateMessages:
    async def test_user_role_obfuscated(self):
        engine = make_engine()
        messages = [{"role": "user", "content": "My email is dev@corp.internal"}]
        result = await engine.obfuscate(messages, SESSION)
        assert "dev@corp.internal" not in result[0]["content"]

    async def test_assistant_role_not_obfuscated(self):
        engine = make_engine()
        messages = [{"role": "assistant", "content": "Your IP is 10.1.2.3"}]
        result = await engine.obfuscate(messages, SESSION)
        assert result[0]["content"] == "Your IP is 10.1.2.3"

    async def test_system_role_not_obfuscated(self):
        engine = make_engine()
        messages = [{"role": "system", "content": "API key sk-abcdefghijklmnopqrst1234"}]
        result = await engine.obfuscate(messages, SESSION)
        assert result[0]["content"] == messages[0]["content"]

    async def test_non_string_content_unchanged(self):
        engine = make_engine()
        messages = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
        result = await engine.obfuscate(messages, SESSION)
        # list content is passed through by engine.obfuscate (handled by pipeline)
        assert result[0]["content"] == messages[0]["content"]

    async def test_multiple_messages_mixed_roles(self):
        engine = make_engine()
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "My IP is 10.1.2.3"},
            {"role": "assistant", "content": "Got it."},
        ]
        result = await engine.obfuscate(messages, SESSION)
        assert result[0]["content"] == "You are helpful."
        assert "10.1.2.3" not in result[1]["content"]
        assert result[2]["content"] == "Got it."

    async def test_does_not_mutate_input(self):
        engine = make_engine()
        msg = {"role": "user", "content": "email dev@corp.internal"}
        messages = [msg]
        await engine.obfuscate(messages, SESSION)
        assert messages[0]["content"] == "email dev@corp.internal"


@pytest.mark.asyncio
class TestDeobfuscate:
    async def test_restores_placeholder(self):
        engine = make_engine()
        obfuscated = await engine._obfuscate_text("Send to dev@corp.internal", SESSION)
        restored = await engine.deobfuscate(obfuscated, SESSION)
        assert restored == "Send to dev@corp.internal"

    async def test_unknown_placeholder_left_intact(self):
        engine = make_engine()
        result = await engine.deobfuscate("[EMAIL_ADDRESS_99]", SESSION)
        assert result == "[EMAIL_ADDRESS_99]"

    async def test_empty_session_returns_text_unchanged(self):
        engine = make_engine()
        result = await engine.deobfuscate("no placeholders here", "empty-session")
        assert result == "no placeholders here"

    async def test_multiple_placeholders_all_restored(self):
        engine = make_engine()
        text = "Email dev@corp.internal host 10.1.2.3"
        obfuscated = await engine._obfuscate_text(text, SESSION)
        restored = await engine.deobfuscate(obfuscated, SESSION)
        assert restored == text

    async def test_cross_session_isolation(self):
        engine = make_engine()
        await engine._obfuscate_text("Send to dev@corp.internal", "session-A")
        # session-B has no mappings; placeholder should survive intact
        result = await engine.deobfuscate("[EMAIL_ADDRESS_0]", "session-B")
        assert result == "[EMAIL_ADDRESS_0]"
