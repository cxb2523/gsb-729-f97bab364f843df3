from typing import assert_never

from ..config import CascadeGateConfig, CerbIAConfig, SimpleGateConfig
from ..exceptions import CerbIAConfigError
from ..registries.url import UrlRegistry
from ..security_gate._cascade import CascadeGate
from ..security_gate._gate import SimpleGate
from ..security_gate._stages import BuiltStage
from ..types import Action
from .scanner import ScannerFactory
from .score_aggregator import ScoreAggregatorFactory

__all__ = ["GateFactory"]


class GateFactory:
    """Construct gates and validated leaf stages without executing scanners."""

    @staticmethod
    def build(config: CerbIAConfig) -> SimpleGate | CascadeGate:
        """Construct a simple or cascade gate and initialize its components.

        Args:
            config (CerbIAConfig): Validated root configuration.

        Returns:
            SimpleGate | CascadeGate: Constructed gate satisfying the SecurityGate protocol for the configuration type.

        Raises:
            CerbIAConfigError: If a simple gate has no scanners, cascade scanners violate ID or action requirements,
                or a cascade stage has no BLOCK scanner.
            FactoryError: If a component cannot be imported or fails its required protocol check.
        """
        match config:
            case SimpleGateConfig():
                return GateFactory.build_simple(config)
            case CascadeGateConfig():
                return CascadeGate(
                    config.name,
                    GateFactory.build_stages(config),
                    config.on_scanner_error,
                )
            case unreachable:
                assert_never(unreachable)

    @staticmethod
    def build_simple(config: CerbIAConfig) -> SimpleGate:
        """Build a simple gate with its configured scanners and aggregator.

        Args:
            config (CerbIAConfig): Root configuration, which must be a SimpleGateConfig.

        Returns:
            SimpleGate: Constructed simple gate with a shared URL registry.

        Raises:
            CerbIAConfigError: If config is a cascade configuration or no scanners are configured.
            FactoryError: If a component cannot be imported or fails its required protocol check.
        """
        match config:
            case SimpleGateConfig():
                settings = config
            case CascadeGateConfig():
                raise CerbIAConfigError("build_simple requires a simple gate configuration")
            case unreachable:
                assert_never(unreachable)

        if not settings.scanners:
            raise CerbIAConfigError("No scanners configured: set at least one scanner")

        registry = UrlRegistry()
        scanners = [ScannerFactory.build(scanner, url_registry=registry) for scanner in settings.scanners]
        aggregator = ScoreAggregatorFactory.build(settings.score_aggregator)

        return SimpleGate(
            name=config.name,
            scanners=scanners,
            score_aggregator=aggregator,
            fail_fast=settings.fail_fast,
            threshold=settings.threshold,
            on_scanner_error=settings.on_scanner_error,
        )

    @staticmethod
    def build_stages(config: CascadeGateConfig) -> tuple[BuiltStage, ...]:
        """Build cascade stages with a shared URL registry and validate scanner metadata.

        Args:
            config (CascadeGateConfig): Validated cascade configuration.

        Returns:
            tuple[BuiltStage, ...]: Constructed stages in configuration order.

        Raises:
            CerbIAConfigError: If a scanner ID is blank, invalid, or repeated, an action is invalid, or a stage has
                no BLOCK scanner.
            FactoryError: If a component cannot be imported or fails its required protocol check.
        """
        registry = UrlRegistry()
        seen: dict[str, str] = {}
        stages: list[BuiltStage] = []

        for stage in config.stages:
            scanners = tuple(ScannerFactory.build(scanner, url_registry=registry) for scanner in stage.scanners)

            for scanner in scanners:
                scanner_id = scanner.scanner_id
                if not isinstance(scanner_id, str) or not scanner_id.strip():
                    raise CerbIAConfigError(f"Stage {stage.id!r} has an invalid scanner ID")

                if scanner_id in seen:
                    raise CerbIAConfigError(
                        f"Stage {stage.id!r} repeats scanner ID {scanner_id!r} from stage {seen[scanner_id]!r}"
                    )
                seen[scanner_id] = stage.id

                if scanner.action not in (Action.BLOCK, Action.WARN, Action.PASS):
                    raise CerbIAConfigError(f"Stage {stage.id!r} scanner {scanner_id!r} has an invalid action")

            if not any(scanner.action == Action.BLOCK for scanner in scanners):
                raise CerbIAConfigError(f"Stage {stage.id!r} requires at least one own block-action scanner")

            aggregator = ScoreAggregatorFactory.build(stage.score_aggregator)
            stages.append(BuiltStage(config=stage, scanners=scanners, score_aggregator=aggregator))

        return tuple(stages)
