import logging

from .config import CerbIAConfig
from .exceptions import CerbIAConfigError
from .factories import GateFactory, LoaderFactory, PreprocessorFactory
from .loaders.base import Loader
from .models.entries import Entry
from .models.results import EntryResult, ScanResult
from .preprocessors.base import Preprocessor
from .security_gate._gate import SimpleGate

__all__ = ["Runner"]

logger = logging.getLogger(__name__)


class Runner:
    """Orchestrate the scanning pipeline for a simple or cascade gate.

    Builds loaders, preprocessors, and one security gate from configuration. During a scan, entries are loaded
    from all loaders, preprocessed (producing derived entries), then all entries are run through the gate.

    Args:
        config (CerbIAConfig): Configuration defining loaders, preprocessors, and a simple gate or cascade stages.

    Attributes:
        loaders (list[Loader]): List of configured loaders.
        preprocessors (list[Preprocessor]): List of configured preprocessors.
        scanners (list[Scanner]): Configured scanners; present only for a simple gate.
        score_aggregator (ScoreAggregator): Configured aggregator; present only for a simple gate.
        gate (SimpleGate | CascadeGate): Constructed SecurityGate implementation used to scan each entry.

    Raises:
        CerbIAConfigError: If no loaders are configured or the gate's scanners violate construction requirements.
        FactoryError: If a configured component cannot be imported or does not satisfy its required protocol.
    """

    def __init__(self, config: CerbIAConfig) -> None:
        self._build_loaders(config)
        self._build_preprocessors(config)
        self.gate = GateFactory.build(config)

        if isinstance(self.gate, SimpleGate):
            self.scanners = self.gate.scanners
            self.score_aggregator = self.gate.score_aggregator

    def _build_loaders(self, config: CerbIAConfig) -> None:
        if not config.loaders:
            raise CerbIAConfigError("No loaders configured: set at least one loader")

        self.loaders: list[Loader] = [LoaderFactory.build(lc) for lc in config.loaders]

    def _build_preprocessors(self, config: CerbIAConfig) -> None:
        self.preprocessors: list[Preprocessor] = [PreprocessorFactory.build(pc) for pc in config.preprocessors]

    def _preprocess(self, entries: list[Entry]) -> list[Entry]:
        for preprocessor in self.preprocessors:
            entries = preprocessor.process(entries)

        return entries

    def scan(self) -> ScanResult:
        """Load entries from all configured loaders, preprocess them, and run the security gate.

        Returns:
            ScanResult: Aggregated results for all entries from all loaders.

        Raises:
            Exception: If an unhandled loader, preprocessor, or gate execution failure occurs.
        """
        logger.debug(
            "Runner scan started",
            extra={
                "operation": "scan",
                "stage": "execution",
                "component_kind": "runner",
                "outcome": "started",
            },
        )
        entries: list[Entry] = []
        for loader in self.loaders:
            entries.extend(loader.load())

        entries = self._preprocess(entries)

        entry_results: list[EntryResult] = []
        for entry in entries:
            gate_result = self.gate.scan(entry.text, content_type=entry.content_type)
            entry_results.append(
                EntryResult(
                    entry=entry,
                    is_safe=gate_result.is_safe,
                    aggregated_score=gate_result.score,
                    rationale=gate_result.rationale,
                    findings=gate_result.findings,
                    skipped_scanners=gate_result.skipped_scanners,
                    stages=gate_result.stages,
                )
            )

        result_count = len(entry_results)
        logger.debug(
            "%s Scan results collected",
            result_count,
            extra={
                "operation": "scan",
                "stage": "execution",
                "component_kind": "runner",
                "outcome": "completed",
                "result_count": result_count,
            },
        )
        return ScanResult(entry_results=entry_results)
