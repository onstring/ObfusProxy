from app.config import PrivacyConfig
from app.privacy.backends.base import Detector


def create_detector(config: PrivacyConfig) -> Detector:
    """
    Factory function to create a Detector instance based on config.

    Only imports concrete backends here. All references elsewhere use
    the Detector ABC, enabling easy extension without touching other code.
    Single backend → returns that detector directly.
    Multiple backends → wraps in CompositeDetector.
    """
    wl = config.whitelist
    exact = frozenset(wl.loopback + wl.domains)
    ip_ranges = list(wl.ip_ranges)
    enabled = config.entities or None

    detectors: list[Detector] = []

    for backend_cfg in config.backends:
        if backend_cfg.type == "regex":
            from app.privacy.backends.regex import RegexDetector
            detectors.append(
                RegexDetector(enabled_types=enabled, whitelist=exact, ip_ranges=ip_ranges)
            )
        elif backend_cfg.type == "presidio":
            from app.privacy.backends.presidio import PresidioDetector
            detectors.append(
                PresidioDetector(enabled_types=enabled, whitelist=exact, model=backend_cfg.model)
            )
        else:
            raise ValueError(
                f"Unknown privacy backend: {backend_cfg.type!r}. "
                f"Supported: ['regex', 'presidio']"
            )

    if len(detectors) == 1:
        return detectors[0]

    from app.privacy.backends.composite import CompositeDetector
    return CompositeDetector(detectors)
