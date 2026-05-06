import re

from .base import Detector, Entity, resolve_overlaps

# PERSON spans must look like an actual name: two or more words, only letters /
# hyphens / apostrophes, no digits or symbols.  This cuts single-word technical
# terms ("Bug", "Lint", "HTTPS") and code fragments ("cubic-bezier(0.16") while
# keeping "Sarah Chen", "Marcus Webb", "Mary-Jane Watson".
# NOTE: Title-Case two-word headings ("Git Workflow") are sometimes flagged by
# the model — that's a known NER limitation, mitigated by this filter.
_PERSON_RE = re.compile(r"^[A-Za-z][a-zA-Z'\-]*(?:\s[A-Za-z][a-zA-Z'\-]*)+$")


def _is_plausible_person(text: str) -> bool:
    t = text.strip()
    return 5 <= len(t) <= 40 and bool(_PERSON_RE.match(t))


class PresidioDetector(Detector):
    """PII/NER detector backed by Microsoft Presidio + spaCy.

    Handles unstructured entities (PERSON, LOCATION, PHONE_NUMBER, CREDIT_CARD, etc.)
    that regex cannot reliably detect. Requires:
        uv pip install "presidio-analyzer>=2.2.0"
        python -m spacy download en_core_web_lg
    """

    def __init__(
        self,
        enabled_types: list[str] | None = None,
        whitelist: frozenset[str] | None = None,
        model: str = "en_core_web_lg",
    ) -> None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        self._enabled = enabled_types
        self._whitelist = whitelist or frozenset()

    @property
    def name(self) -> str:
        return "presidio"

    def detect(self, text: str) -> list[Entity]:
        results = self._analyzer.analyze(
            text=text,
            entities=self._enabled,
            language="en",
            allow_list=list(self._whitelist),
        )
        entities = []
        for r in results:
            span_text = text[r.start:r.end]
            if r.entity_type == "PERSON" and not _is_plausible_person(span_text):
                continue
            entities.append(
                Entity(type=r.entity_type, start=r.start, end=r.end, text=span_text)
            )
        entities.sort(key=lambda e: e.start)
        return resolve_overlaps(entities)
