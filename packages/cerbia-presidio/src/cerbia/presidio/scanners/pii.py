from logging import getLogger

from cerbia.core.models.scans import MatchSpan, ScanOutcome
from cerbia.core.types import Action, ContentType, Severity
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

logger = getLogger(__name__)


class PresidioPiiScanner:
    """Detects PII using Microsoft Presidio's NLP-based analyzer engine.

    Uses the bundled ``en_core_web_sm`` spaCy model.

    Args:
        entities (list[str] | None): Entity types to detect. Defaults to all supported entities.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when PII is detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Content types to scan. Defaults to
            ``(ContentType.TEXT,)``.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when PII is detected.
        content_types (tuple[ContentType, ...] | None): Content types to scan.
    """

    def __init__(
        self,
        entities: list[str] | None = None,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:

        self.scanner_id = "presidio_pii"
        self.scanner_name = "Presidio PII"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None

        self._entities = entities

        nlp_provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
        )
        self._analyzer = AnalyzerEngine(nlp_engine=nlp_provider.create_engine(), supported_languages=["en"])

    def scan(self, text: str) -> ScanOutcome:
        """Analyse text for PII entities using Presidio NER.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and match spans.
        """
        if not text.strip():
            logger.debug(
                "No input provided",
                extra={
                    "operation": "scan",
                    "stage": "pii",
                    "component_kind": "scanner",
                    "outcome": "empty",
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="Empty input")

        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=self._entities,
        )
        candidate_count = len(results)

        if not results:
            logger.debug(
                "No matches found",
                extra={
                    "operation": "scan",
                    "stage": "pii",
                    "component_kind": "scanner",
                    "outcome": "no_result",
                    "candidate_count": len(results),
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="No PII detected")

        hits: list[tuple[str, float]] = []
        matches: list[MatchSpan] = []
        for result in results:
            hits.append((result.entity_type, result.score))
            matches.append(MatchSpan(start=result.start, end=result.end))

        max_risk = max(score for _, score in hits)
        type_counts: dict[str, int] = {}
        for etype, _ in hits:
            type_counts[etype] = type_counts.get(etype, 0) + 1

        summary = ", ".join(f"{etype} ({count})" for etype, count in list(type_counts.items())[:5])
        match_count = len(matches)
        logger.debug(
            "%s matches found",
            match_count,
            extra={
                "operation": "scan",
                "stage": "pii",
                "component_kind": "scanner",
                "outcome": "matched",
                "candidate_count": candidate_count,
                "match_count": match_count,
            },
        )
        return ScanOutcome(
            risk_score=max_risk,
            rationale=f"PII detected ({len(hits)} entity/ies): {summary}",
            matches=matches,
        )
