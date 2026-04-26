from app.config import PrivacyConfig
from app.privacy.backends.base import Detector


def create_detector(config: PrivacyConfig) -> Detector:
    """
    Factory function to create a Detector instance based on config.

    Only imports concrete backends here. All references elsewhere use
    the Detector ABC, enabling easy extension without touching other code.
    """
    backend = config.backend
    enabled = config.entities if config.entities else None
    whitelist = frozenset(config.whitelist)

    if backend == "regex":
        from app.privacy.backends.regex import RegexDetector
        return RegexDetector(enabled_types=enabled, whitelist=whitelist)

    raise ValueError(
        f"Unknown privacy backend: {backend!r}. "
        f"Supported in Stage 1: ['regex']"
    )
