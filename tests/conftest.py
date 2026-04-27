import pytest

from app.privacy.backends.regex import RegexDetector
from app.privacy.engine import PrivacyEngine
from app.privacy.session import SessionMap


@pytest.fixture
def detector() -> RegexDetector:
    return RegexDetector()


@pytest.fixture
def session_map() -> SessionMap:
    return SessionMap()


@pytest.fixture
def engine(detector: RegexDetector, session_map: SessionMap) -> PrivacyEngine:
    return PrivacyEngine(detector=detector, session_map=session_map)
