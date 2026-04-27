from .base import Detector, Entity, resolve_overlaps


class PresidioDetector(Detector):
    """PII/NER detector backed by Microsoft Presidio + spaCy.

    Handles unstructured entities (PERSON, LOCATION, PHONE_NUMBER, CREDIT_CARD, etc.)
    that regex cannot reliably detect. Requires:
        uv pip install "presidio-analyzer>=2.2.0"
        python -m spacy download en_core_web_sm
    """

    def __init__(
        self,
        enabled_types: list[str] | None = None,
        whitelist: frozenset[str] | None = None,
        model: str = "en_core_web_sm",
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
        entities = [
            Entity(type=r.entity_type, start=r.start, end=r.end, text=text[r.start:r.end])
            for r in results
        ]
        entities.sort(key=lambda e: e.start)
        return resolve_overlaps(entities)
