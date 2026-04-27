"""Tests for CompositeDetector — merging, overlap resolution, empty guard."""
import pytest

from app.privacy.backends.base import Detector, Entity
from app.privacy.backends.composite import CompositeDetector
from app.privacy.backends.regex import RegexDetector


class _StaticDetector(Detector):
    """Test double: returns a fixed list of entities."""

    def __init__(self, name_: str, entities: list[Entity]) -> None:
        self._name = name_
        self._entities = entities

    @property
    def name(self) -> str:
        return self._name

    def detect(self, text: str) -> list[Entity]:
        return list(self._entities)


class TestCompositeDetector:
    def test_name_joins_backends(self):
        a = _StaticDetector("regex", [])
        b = _StaticDetector("presidio", [])
        c = CompositeDetector([a, b])
        assert c.name == "regex+presidio"

    def test_empty_detectors_raises(self):
        with pytest.raises(ValueError):
            CompositeDetector([])

    def test_single_detector_passthrough(self):
        entity = Entity(type="EMAIL_ADDRESS", start=0, end=20, text="dev@corp.internal   "[:20])
        entity = Entity(type="EMAIL_ADDRESS", start=0, end=17, text="dev@corp.internal")
        d = _StaticDetector("regex", [entity])
        composite = CompositeDetector([d])
        result = composite.detect("dev@corp.internal")
        assert result == [entity]

    def test_merges_non_overlapping_entities(self):
        e1 = Entity(type="EMAIL_ADDRESS", start=0, end=17, text="dev@corp.internal")
        e2 = Entity(type="IP_ADDRESS", start=21, end=29, text="10.1.2.3")
        # Text: "dev@corp.internal    10.1.2.3"  (4-space gap)
        d1 = _StaticDetector("a", [e1])
        d2 = _StaticDetector("b", [e2])
        composite = CompositeDetector([d1, d2])
        result = composite.detect("dev@corp.internal    10.1.2.3")
        assert len(result) == 2
        assert result[0].type == "EMAIL_ADDRESS"
        assert result[1].type == "IP_ADDRESS"

    def test_overlap_first_detector_wins(self):
        # Both detectors claim the same span — first one should win
        e1 = Entity(type="API_KEY", start=5, end=15, text="1234567890")
        e2 = Entity(type="SECRET", start=5, end=15, text="1234567890")
        d1 = _StaticDetector("first", [e1])
        d2 = _StaticDetector("second", [e2])
        composite = CompositeDetector([d1, d2])
        result = composite.detect("key: 1234567890 end")
        assert len(result) == 1
        assert result[0].type == "API_KEY"

    def test_partial_overlap_first_wins(self):
        # e1 covers 0-10; e2 covers 8-18 — partial overlap, e1 first
        e1 = Entity(type="API_KEY", start=0, end=10, text="abcdefghij")
        e2 = Entity(type="SECRET", start=8, end=18, text="ijklmnopqr")
        d1 = _StaticDetector("first", [e1])
        d2 = _StaticDetector("second", [e2])
        composite = CompositeDetector([d1, d2])
        result = composite.detect("abcdefghijklmnopqr")
        assert len(result) == 1
        assert result[0].type == "API_KEY"

    def test_results_sorted_by_start(self):
        e1 = Entity(type="IP_ADDRESS", start=18, end=26, text="10.1.2.3")
        e2 = Entity(type="EMAIL_ADDRESS", start=0, end=17, text="dev@corp.internal")
        d1 = _StaticDetector("a", [e1])
        d2 = _StaticDetector("b", [e2])
        composite = CompositeDetector([d1, d2])
        result = composite.detect("dev@corp.internal  10.1.2.3")
        assert result[0].start <= result[1].start

    def test_with_real_regex_detectors(self):
        d1 = RegexDetector(enabled_types=["EMAIL_ADDRESS"])
        d2 = RegexDetector(enabled_types=["IP_ADDRESS"])
        composite = CompositeDetector([d1, d2])
        result = composite.detect("Email dev@corp.internal IP 8.8.8.8")
        types = {e.type for e in result}
        assert "EMAIL_ADDRESS" in types
        assert "IP_ADDRESS" in types
