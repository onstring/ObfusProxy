from .base import Detector, Entity, resolve_overlaps


class CompositeDetector(Detector):
    """Runs multiple detectors and merges results with overlap resolution.

    Detectors are called in order; earlier detectors win on overlapping spans.
    """

    def __init__(self, detectors: list[Detector]) -> None:
        if not detectors:
            raise ValueError("CompositeDetector requires at least one detector")
        self._detectors = detectors

    @property
    def name(self) -> str:
        return "+".join(d.name for d in self._detectors)

    def detect(self, text: str) -> list[Entity]:
        all_entities: list[Entity] = []
        for d in self._detectors:
            all_entities.extend(d.detect(text))
        all_entities.sort(key=lambda e: e.start)
        return resolve_overlaps(all_entities)
