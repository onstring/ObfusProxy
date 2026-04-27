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
    wl = config.whitelist
    exact = frozenset(wl.loopback + wl.domains)

    if backend == "regex":
        from app.privacy.backends.regex import RegexDetector
        return RegexDetector(enabled_types=enabled, whitelist=exact, ip_ranges=list(wl.ip_ranges))

    raise ValueError(
        f"Unknown privacy backend: {backend!r}. "
        f"Supported in Stage 1: ['regex']"
    )
