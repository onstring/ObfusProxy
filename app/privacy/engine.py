import logging
import re

from app.privacy.backends.base import Detector
from app.privacy.session import SessionMap

log = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\[[A-Z][A-Z_]*_\d+\]")
_ROLES_TO_OBFUSCATE = frozenset({"user", "tool"})


class PrivacyEngine:
    """
    Orchestrates PII detection and obfuscation/deobfuscation.

    Delegates detection to a pluggable Detector backend and maintains
    placeholder mappings in a SessionMap.
    """

    def __init__(self, detector: Detector, session_map: SessionMap) -> None:
        self._detector = detector
        self._session_map = session_map

    async def obfuscate(self, messages: list[dict], session_id: str) -> list[dict]:
        """
        Obfuscate PII in all messages. For each message with a string content,
        detect entities and replace them with [TYPE_N] placeholders.

        Returns a new list of message dicts (does not mutate input).
        """
        result = []
        for i, msg in enumerate(messages):
            role = msg.get("role", "")
            if role not in _ROLES_TO_OBFUSCATE:
                result.append(msg)
                continue

            content = msg.get("content")
            if not isinstance(content, str):
                result.append(msg)
                continue

            log.debug("[obfuscate] msg[%d] role=%s", i, role)
            scrubbed = await self._obfuscate_text(content, session_id)
            result.append({**msg, "content": scrubbed})

        return result

    async def _obfuscate_text(self, text: str, session_id: str) -> str:
        """Detect entities and replace right-to-left with placeholders."""
        entities = self._detector.detect(text)

        if entities:
            log.info("[obfuscate] session=%s entities=%d", session_id, len(entities))

        for entity in reversed(entities):
            placeholder = await self._session_map.get_or_create(
                session_id, entity.text, entity.type
            )
            log.debug(
                "[obfuscate]   %-20s %r -> %s",
                entity.type,
                entity.text,
                placeholder,
            )
            text = text[: entity.start] + placeholder + text[entity.end :]

        return text

    async def deobfuscate(self, text: str, session_id: str) -> str:
        """Replace all [ENTITY_N] placeholders with originals from session map."""
        mapping = await self._session_map.get_map(session_id)
        if not mapping:
            return text

        def replacer(m: re.Match) -> str:
            return mapping.get(m.group(0), m.group(0))

        return _PLACEHOLDER_RE.sub(replacer, text)
