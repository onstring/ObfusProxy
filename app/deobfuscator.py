from collections.abc import AsyncIterator

from app.privacy.engine import PrivacyEngine


class ResponseDeobfuscator:
    """Handles de-obfuscation of LLM responses (streaming and non-streaming)."""

    def __init__(self, engine: PrivacyEngine) -> None:
        self._engine = engine

    async def restore(self, text: str, session_id: str) -> str:
        """Non-streaming path: simple full-text deobfuscation."""
        return await self._engine.deobfuscate(text, session_id)

    @staticmethod
    def _split_safe(text: str) -> tuple[str, str]:
        """
        Split text into (safe_to_flush, keep_buffered).

        safe_to_flush: everything up to (and excluding) any unclosed `[` bracket.
        keep_buffered: the suffix starting at an unclosed `[`.

        An unclosed `[` is one not followed by a `]` within the same text.
        """
        last_open = text.rfind("[")
        if last_open == -1:
            return text, ""

        after_open = text[last_open:]
        if "]" in after_open:
            return text, ""

        return text[:last_open], text[last_open:]


class StreamingDeobfuscatorSession:
    """
    Stateful per-request session for streaming de-obfuscation.

    Handles split placeholders like [DOMAIN_5] arriving as [DOMA + IN_5]
    across chunk boundaries using a lookahead buffer.
    """

    def __init__(self, engine: PrivacyEngine, session_id: str) -> None:
        self._engine = engine
        self._session_id = session_id
        self._buffer = ""

    async def feed(self, chunk: str) -> str:
        """
        Ingest a chunk, return safe-to-flush text (may be empty).
        Buffers incomplete placeholder tokens.
        """
        self._buffer += chunk
        safe, self._buffer = ResponseDeobfuscator._split_safe(self._buffer)

        if safe:
            return await self._engine.deobfuscate(safe, self._session_id)
        return ""

    async def flush(self) -> str:
        """Call at end of stream to drain remaining buffer."""
        if self._buffer:
            result = await self._engine.deobfuscate(self._buffer, self._session_id)
            self._buffer = ""
            return result
        return ""
