"""Tests for ResponseDeobfuscator and StreamingDeobfuscatorSession."""
import pytest

from app.deobfuscator import ResponseDeobfuscator, StreamingDeobfuscatorSession
from app.privacy.backends.regex import RegexDetector
from app.privacy.engine import PrivacyEngine
from app.privacy.session import SessionMap


def make_engine_with_mapping(session_id: str, email: str) -> PrivacyEngine:
    """Helper: create engine and pre-populate a mapping."""
    import asyncio
    engine = PrivacyEngine(
        detector=RegexDetector(),
        session_map=SessionMap(),
    )
    asyncio.get_event_loop().run_until_complete(
        engine._obfuscate_text(email, session_id)
    )
    return engine


SESSION = "deob-session"


# ---------------------------------------------------------------------------
# _split_safe — static utility
# ---------------------------------------------------------------------------

class TestSplitSafe:
    def test_no_bracket(self):
        safe, buf = ResponseDeobfuscator._split_safe("hello world")
        assert safe == "hello world"
        assert buf == ""

    def test_closed_bracket(self):
        safe, buf = ResponseDeobfuscator._split_safe("text [EMAIL_ADDRESS_0] more")
        assert safe == "text [EMAIL_ADDRESS_0] more"
        assert buf == ""

    def test_unclosed_bracket_at_end(self):
        safe, buf = ResponseDeobfuscator._split_safe("prefix [EMAIL_ADDRESS")
        assert safe == "prefix "
        assert buf == "[EMAIL_ADDRESS"

    def test_unclosed_bracket_mid_text(self):
        # '[' is last unclosed one
        safe, buf = ResponseDeobfuscator._split_safe("a [b] c [DOMAIN")
        assert safe == "a [b] c "
        assert buf == "[DOMAIN"

    def test_empty_string(self):
        safe, buf = ResponseDeobfuscator._split_safe("")
        assert safe == ""
        assert buf == ""

    def test_only_open_bracket(self):
        safe, buf = ResponseDeobfuscator._split_safe("[")
        assert safe == ""
        assert buf == "["


# ---------------------------------------------------------------------------
# StreamingDeobfuscatorSession — feed / flush
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestStreamingDeobfuscatorSession:
    async def _make_session(self) -> tuple[StreamingDeobfuscatorSession, str]:
        """Create engine with one mapping, return session and placeholder."""
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        ph = (await engine._obfuscate_text("dev@corp.internal", SESSION)).split()[0]
        # The obfuscated text *is* the placeholder since there's just the one token
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)
        return sess, ph

    async def test_complete_placeholder_restored_on_feed(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        await engine._obfuscate_text("dev@corp.internal", SESSION)
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)
        out = await sess.feed("[EMAIL_ADDRESS_0] arrived")
        assert "dev@corp.internal" in out

    async def test_split_placeholder_buffered_then_flushed(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        await engine._obfuscate_text("dev@corp.internal", SESSION)
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)

        # First chunk has an unclosed bracket
        out1 = await sess.feed("Reply: [EMAIL_AD")
        # Nothing safe to flush yet
        assert "dev@corp.internal" not in out1

        # Second chunk completes the placeholder
        out2 = await sess.feed("DRESS_0]")
        assert "dev@corp.internal" in out2

    async def test_flush_drains_buffer(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        await engine._obfuscate_text("dev@corp.internal", SESSION)
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)

        # Feed an incomplete placeholder — nothing flushed yet
        await sess.feed("[EMAIL_ADDRESS")
        # Flush should emit the buffered partial (it won't match, so it comes through raw)
        out = await sess.flush()
        assert "[EMAIL_ADDRESS" in out

    async def test_flush_empty_buffer_returns_empty(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)
        out = await sess.flush()
        assert out == ""

    async def test_plain_text_chunks_pass_through(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)
        out = await sess.feed("Hello world")
        assert out == "Hello world"

    async def test_multiple_placeholders_in_stream(self):
        engine = PrivacyEngine(detector=RegexDetector(), session_map=SessionMap())
        text = "email dev@corp.internal server 10.1.2.3"
        await engine._obfuscate_text(text, SESSION)
        sess = StreamingDeobfuscatorSession(engine=engine, session_id=SESSION)

        # Build the obfuscated string
        obf = await engine._obfuscate_text(text, SESSION)
        out = await sess.feed(obf)
        final = out + await sess.flush()
        assert "dev@corp.internal" in final
        assert "10.1.2.3" in final
