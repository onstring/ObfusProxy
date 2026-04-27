"""Tests for SessionMap — idempotency, type-named placeholders, concurrency, clear."""
import asyncio

import pytest
import pytest_asyncio

from app.privacy.session import SessionMap


@pytest.mark.asyncio
class TestGetOrCreate:
    async def test_new_entry_gets_placeholder(self):
        sm = SessionMap()
        ph = await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        assert ph == "[EMAIL_ADDRESS_0]"

    async def test_same_original_returns_same_placeholder(self):
        sm = SessionMap()
        ph1 = await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        ph2 = await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        assert ph1 == ph2

    async def test_different_originals_get_different_placeholders(self):
        sm = SessionMap()
        ph1 = await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        ph2 = await sm.get_or_create("s1", "admin@corp.internal", "EMAIL_ADDRESS")
        assert ph1 != ph2

    async def test_counter_increments(self):
        sm = SessionMap()
        ph0 = await sm.get_or_create("s1", "a@b.com", "EMAIL_ADDRESS")
        ph1 = await sm.get_or_create("s1", "c@d.com", "EMAIL_ADDRESS")
        assert ph0 == "[EMAIL_ADDRESS_0]"
        assert ph1 == "[EMAIL_ADDRESS_1]"

    async def test_type_name_in_placeholder(self):
        sm = SessionMap()
        ip_ph = await sm.get_or_create("s1", "10.1.2.3", "IP_ADDRESS")
        domain_ph = await sm.get_or_create("s1", "db.corp.internal", "DOMAIN")
        assert ip_ph.startswith("[IP_ADDRESS_")
        assert domain_ph.startswith("[DOMAIN_")

    async def test_sessions_are_isolated(self):
        sm = SessionMap()
        ph_a = await sm.get_or_create("session-A", "secret", "SECRET")
        ph_b = await sm.get_or_create("session-B", "secret", "SECRET")
        # Both get index 0 independently
        assert ph_a == "[SECRET_0]"
        assert ph_b == "[SECRET_0]"

    async def test_default_entity_type(self):
        sm = SessionMap()
        ph = await sm.get_or_create("s1", "something")
        assert ph == "[ENTITY_0]"


@pytest.mark.asyncio
class TestGetMap:
    async def test_empty_session(self):
        sm = SessionMap()
        m = await sm.get_map("nonexistent")
        assert m == {}

    async def test_returns_stored_mapping(self):
        sm = SessionMap()
        await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        m = await sm.get_map("s1")
        assert "[EMAIL_ADDRESS_0]" in m
        assert m["[EMAIL_ADDRESS_0]"] == "dev@corp.internal"

    async def test_snapshot_is_independent(self):
        sm = SessionMap()
        await sm.get_or_create("s1", "a@b.com", "EMAIL_ADDRESS")
        snap = await sm.get_map("s1")
        await sm.get_or_create("s1", "c@d.com", "EMAIL_ADDRESS")
        # Snapshot taken before second entry should not contain it
        assert "[EMAIL_ADDRESS_1]" not in snap


@pytest.mark.asyncio
class TestClear:
    async def test_clear_removes_session(self):
        sm = SessionMap()
        await sm.get_or_create("s1", "dev@corp.internal", "EMAIL_ADDRESS")
        await sm.clear("s1")
        m = await sm.get_map("s1")
        assert m == {}

    async def test_clear_resets_counter(self):
        sm = SessionMap()
        await sm.get_or_create("s1", "a@b.com", "EMAIL_ADDRESS")
        await sm.clear("s1")
        ph = await sm.get_or_create("s1", "z@z.com", "EMAIL_ADDRESS")
        assert ph == "[EMAIL_ADDRESS_0]"

    async def test_clear_nonexistent_is_noop(self):
        sm = SessionMap()
        await sm.clear("does-not-exist")  # should not raise


@pytest.mark.asyncio
class TestConcurrency:
    async def test_concurrent_writes_are_safe(self):
        sm = SessionMap()
        originals = [f"user{i}@corp.internal" for i in range(20)]

        async def insert(orig: str) -> str:
            return await sm.get_or_create("concurrent", orig, "EMAIL_ADDRESS")

        results = await asyncio.gather(*[insert(o) for o in originals])
        # All placeholders should be unique
        assert len(set(results)) == len(originals)

    async def test_concurrent_same_value_idempotent(self):
        sm = SessionMap()
        results = await asyncio.gather(*[
            sm.get_or_create("s1", "same@corp.internal", "EMAIL_ADDRESS")
            for _ in range(10)
        ])
        assert len(set(results)) == 1
