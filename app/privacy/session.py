import asyncio
from collections.abc import Mapping


class SessionMap:
    """
    Thread/async-safe in-memory session mapping store.

    Maps session_id -> {placeholder -> original}. Each session has its own
    asyncio.Lock for concurrent request safety. Placeholders are allocated
    monotonically per session and are idempotent: the same original text
    always maps to the same placeholder within a session.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._counters: dict[str, int] = {}
        self._global_lock = asyncio.Lock()

    async def _get_lock(self, session_id: str) -> asyncio.Lock:
        """Lazily create and return per-session lock."""
        async with self._global_lock:
            if session_id not in self._locks:
                self._locks[session_id] = asyncio.Lock()
                self._data[session_id] = {}
                self._counters[session_id] = 0
            return self._locks[session_id]

    async def get_or_create(self, session_id: str, original: str, entity_type: str = "ENTITY") -> str:
        """
        Idempotent: if `original` already has a placeholder in this session,
        return that placeholder. Otherwise allocate a new [TYPE_N] and store it.
        """
        lock = await self._get_lock(session_id)
        async with lock:
            mapping = self._data[session_id]

            for placeholder, stored in mapping.items():
                if stored == original:
                    return placeholder

            n = self._counters[session_id]
            self._counters[session_id] += 1
            placeholder = f"[{entity_type}_{n}]"
            mapping[placeholder] = original
            return placeholder

    async def get_map(self, session_id: str) -> Mapping[str, str]:
        """
        Return a snapshot (read-only) mapping for a session.
        Returns an empty dict if session doesn't exist.
        """
        lock = await self._get_lock(session_id)
        async with lock:
            return dict(self._data.get(session_id, {}))

    async def clear(self, session_id: str) -> None:
        """Remove a session and all its data."""
        async with self._global_lock:
            self._data.pop(session_id, None)
            self._locks.pop(session_id, None)
            self._counters.pop(session_id, None)
