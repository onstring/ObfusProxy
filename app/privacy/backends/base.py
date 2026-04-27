from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Entity:
    """A detected sensitive span within a text string."""
    type: str
    start: int
    end: int
    text: str

    def __post_init__(self) -> None:
        if self.start >= self.end:
            raise ValueError(f"Entity span [{self.start},{self.end}) is empty or invalid")
        if len(self.text) != self.end - self.start:
            raise ValueError(
                f"Entity.text length ({len(self.text)}) must match span width ({self.end - self.start})"
            )


def resolve_overlaps(entities: list["Entity"]) -> list["Entity"]:
    """Greedy first-match deduplication. Input must be sorted by start offset."""
    if not entities:
        return []
    result = [entities[0]]
    for e in entities[1:]:
        if e.start >= result[-1].end:
            result.append(e)
    return result


class Detector(ABC):
    """Backend-agnostic interface for PII/NER detection."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend identifier (e.g., 'regex')."""
        ...

    @abstractmethod
    def detect(self, text: str) -> list[Entity]:
        """
        Detect entities in text. Returns a list of non-overlapping entities
        sorted by start offset. Earlier entities take priority in overlaps.

        Implementation must be deterministic and side-effect-free.
        """
        ...
