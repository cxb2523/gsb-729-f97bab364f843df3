from abc import ABC, abstractmethod
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, JsonValue, TypeAdapter, model_validator
from pydantic_core import PydanticCustomError

from .types import ScannerErrorPolicy

__all__ = [
    "ComponentConfig",
    "PreprocessorConfig",
    "ScannerConfig",
    "ScoreAggregatorConfig",
    "LoaderConfig",
    "GateType",
    "SimpleGateConfig",
    "CerbIAConfig",
    "CascadeGateConfig",
    "CascadeStageConfig",
    "CONFIG_ADAPTER",
    "parse_config",
]

type Threshold = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]


class GateType(StrEnum):
    """Discriminator tags for root configurations.

    Attributes:
        SIMPLE (GateType): A single gate with ordered scanners.
        CASCADE (GateType): Ordered stages with score-based routing.
    """

    SIMPLE = "simple"
    CASCADE = "cascade"


class ComponentConfig(BaseModel, ABC):
    """Strict, shallow-frozen component configuration.

    Attributes:
        init_args (dict[str, Any]): Keyword arguments forwarded to the constructor. The dictionary remains mutable.
        component (str): Fully qualified component class path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    init_args: dict[str, Any] = Field(default_factory=dict)

    @property
    @abstractmethod
    def component(self) -> str:
        """Return the fully qualified component class path.

        Returns:
            str: Component class import path.
        """


class PreprocessorConfig(ComponentConfig):
    """Configuration for an individual preprocessor.

    Attributes:
        preprocessor (str): Fully qualified preprocessor class path.
        init_args (dict[str, Any]): Constructor keyword arguments; the dictionary remains mutable.
        component (str): The configured preprocessor class path.
    """

    preprocessor: str

    @property
    def component(self) -> str:
        """Return the configured preprocessor path.

        Returns:
            str: Preprocessor class import path.
        """
        return self.preprocessor


class ScannerConfig(ComponentConfig):
    """Configuration for an individual scanner.

    Attributes:
        scanner (str): Fully qualified scanner class path.
        init_args (dict[str, Any]): Constructor keyword arguments; the dictionary remains mutable.
        component (str): The configured scanner class path.
    """

    scanner: str

    @property
    def component(self) -> str:
        """Return the configured scanner path.

        Returns:
            str: Scanner class import path.
        """
        return self.scanner


class ScoreAggregatorConfig(ComponentConfig):
    """Configuration for an individual score aggregator.

    Attributes:
        score_aggregator (str): Fully qualified score aggregator class path.
        init_args (dict[str, Any]): Constructor keyword arguments; the dictionary remains mutable.
        component (str): The configured score aggregator class path.
    """

    score_aggregator: str

    @property
    def component(self) -> str:
        """Return the configured score aggregator path.

        Returns:
            str: Score aggregator class import path.
        """
        return self.score_aggregator


class LoaderConfig(ComponentConfig):
    """Configuration for an input loader.

    Attributes:
        loader (str): Fully qualified loader class path.
        init_args (dict[str, Any]): Constructor keyword arguments; the dictionary remains mutable.
        component (str): The configured loader class path.
    """

    loader: str

    @property
    def component(self) -> str:
        """Return the configured loader path.

        Returns:
            str: Loader class import path.
        """
        return self.loader


class _GateConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    loaders: list[LoaderConfig] = Field(default_factory=list)
    preprocessors: list[PreprocessorConfig] = Field(default_factory=list)


class SimpleGateConfig(_GateConfig):
    """Configuration for a single gate with ordered scanners.

    Attributes:
        name (str): Gate name.
        type (Literal[GateType.SIMPLE]): Simple gate discriminator; defaults to SIMPLE.
        loaders (list[LoaderConfig]): Loaders that produce entries to scan.
        preprocessors (list[PreprocessorConfig]): Ordered preprocessor pipeline.
        fail_fast (bool): Stop on a blocking scanner error or a non-negligible BLOCK finding whose weighted score
            meets the threshold; defaults to True.
        threshold (float): Blocking aggregate boundary in [0.0, 1.0]; equality blocks. Defaults to 0.0.
        on_scanner_error (ScannerErrorPolicy): Scanner error policy; defaults to BLOCK.
        scanners (list[ScannerConfig]): Ordered scanners.
        score_aggregator (ScoreAggregatorConfig): Aggregator for positive, severity-weighted BLOCK scores.
    """

    type: Literal[GateType.SIMPLE] = GateType.SIMPLE
    on_scanner_error: ScannerErrorPolicy = ScannerErrorPolicy.BLOCK
    fail_fast: bool = True
    threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    scanners: list[ScannerConfig] = Field(default_factory=list)
    score_aggregator: ScoreAggregatorConfig


class CascadeStageConfig(BaseModel):
    """Score-based cascade stage configuration.

    Attributes:
        id (str): Nonempty stage identifier containing a non-whitespace character.
        scanners (list[ScannerConfig]): Nonempty ordered list of this stage's scanners.
        score_aggregator (ScoreAggregatorConfig): Aggregator for this stage's positive, weighted BLOCK scores.
        threshold (Threshold): Finite boundary in [0.0, 1.0]; scores strictly above it block.
        defer_above (Threshold | None): Nonfinal stage's defer boundary, strictly below threshold. Must be omitted
            for the final stage; explicit None is invalid.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, pattern=r"\S")
    scanners: list[ScannerConfig] = Field(min_length=1)
    score_aggregator: ScoreAggregatorConfig
    threshold: Threshold
    defer_above: Threshold | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def check_policy(self) -> Self:
        """Check the stage's defer band.

        Returns:
            Self: This validated stage configuration.

        Raises:
            PydanticCustomError: If defer_above is explicitly None or is not below threshold.
        """
        if "defer_above" in self.model_fields_set and self.defer_above is None:
            raise PydanticCustomError("threshold_band", "defer_above must be a finite number")

        if self.defer_above is not None and self.defer_above >= self.threshold:
            raise PydanticCustomError("threshold_band", "defer_above must be smaller than threshold")

        return self


class CascadeGateConfig(_GateConfig):
    """Configuration for ordered, score-based cascade stages.

    Attributes:
        name (str): Gate name.
        type (Literal[GateType.CASCADE]): Required cascade discriminator.
        loaders (list[LoaderConfig]): Loaders that produce entries to scan.
        preprocessors (list[PreprocessorConfig]): Ordered preprocessor pipeline.
        threshold (Threshold | None): Optional default for omitted stage thresholds. Explicit stage values take
            precedence; an explicit None is invalid.
        on_scanner_error (Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK]): Operational fault policy;
            defaults to FAIL. SKIP is unsupported.
        stages (list[CascadeStageConfig]): Nonempty ordered stages with unique IDs. Nonfinal stages require
            defer_above; the final stage must omit it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal[GateType.CASCADE] = Field(...)
    threshold: Threshold | None = Field(default=None, exclude_if=lambda value: value is None)
    on_scanner_error: Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK] = ScannerErrorPolicy.FAIL
    stages: list[CascadeStageConfig] = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def inherit_thresholds(cls, data: JsonValue) -> JsonValue:
        """Inherit omitted stage thresholds without modifying the input.

        Args:
            data (JsonValue): Configuration input before model parsing.

        Returns:
            JsonValue: A copied mapping with inherited thresholds, or the unchanged input when inapplicable.
        """
        if isinstance(data, dict) and isinstance(data.get("stages"), list) and "threshold" in data:
            stages = data["stages"]
            assert isinstance(stages, list)

            inherited_stages: list[JsonValue] = []
            for stage in stages:
                if isinstance(stage, dict):
                    inherited_stages.append({"threshold": data["threshold"], **stage})
                else:
                    inherited_stages.append(stage)

            return {**data, "stages": inherited_stages}

        return data

    @model_validator(mode="after")
    def check_topology(self) -> Self:
        """Check stage positions and unique IDs.

        Returns:
            Self: This validated cascade configuration.

        Raises:
            PydanticCustomError: If the root threshold is explicitly None, stage defer bands violate their positions,
                or stage IDs repeat.
        """
        if "threshold" in self.model_fields_set and self.threshold is None:
            raise PydanticCustomError("threshold", "threshold must be a finite number")

        seen: set[str] = set()
        for index, stage in enumerate(self.stages):
            final = index == len(self.stages) - 1

            if final and "defer_above" in stage.model_fields_set:
                raise PydanticCustomError(
                    "stage_band", "final stage {stage} must omit defer_above", {"stage": stage.id}
                )
            if not final and stage.defer_above is None:
                raise PydanticCustomError(
                    "stage_band", "nonfinal stage {stage} requires defer_above", {"stage": stage.id}
                )

            if stage.id in seen:
                raise PydanticCustomError("stage_id", "duplicate stage id {stage}", {"stage": stage.id})
            seen.add(stage.id)

        return self


def _default_simple_type[T](value: T) -> T | Mapping[object, object]:
    if isinstance(value, Mapping) and "type" not in value:
        return {**value, "type": GateType.SIMPLE}

    return value


type CerbIAConfig = Annotated[
    SimpleGateConfig | CascadeGateConfig,
    Field(discriminator="type"),
    BeforeValidator(_default_simple_type),
]
CONFIG_ADAPTER: Final[TypeAdapter[CerbIAConfig]] = TypeAdapter(CerbIAConfig)


def parse_config(mapping: Mapping[str, object]) -> CerbIAConfig:
    """Parse a simple or cascade configuration, defaulting an absent type to simple.

    Args:
        mapping (Mapping[str, object]): Configuration fields to validate without modifying the mapping.

    Returns:
        CerbIAConfig: Validated simple or cascade configuration.

    Raises:
        ValidationError: If the discriminator, fields, score bands, or stage topology are invalid.
    """
    return CONFIG_ADAPTER.validate_python(mapping)
