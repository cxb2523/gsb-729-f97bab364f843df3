import importlib
import inspect
import logging
from abc import ABC, abstractmethod
from typing import Any

from ..config import ComponentConfig
from .exceptions import FactoryError

logger = logging.getLogger(__name__)


class Factory[FactoryInput: ComponentConfig, FactoryOutput](ABC):
    """Abstract base class for factories that create components based on configuration."""

    @staticmethod
    def _import_class(dotted_path: str) -> type:
        """Import a class from a fully qualified dotted path.

        Args:
            dotted_path (str): Fully qualified dotted path to the class (e.g., 'module.submodule.ClassName').

        Returns:
            type: The imported class.

        Raises:
            FactoryError: If the dotted path is invalid or the module cannot be imported.
        """
        module_path, _, class_name = dotted_path.rpartition(".")
        if not module_path:
            raise FactoryError(f"Invalid import path '{dotted_path}': must be a fully qualified dotted path")

        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise FactoryError(f"Cannot import module '{module_path}': {exc}") from exc

        try:
            return getattr(module, class_name)
        except AttributeError as exc:
            raise FactoryError(f"Class '{class_name}' not found in module '{module_path}'") from exc

    @staticmethod
    def _verify(instance: Any, expected_type: type, dotted_path: str) -> None:
        """Verify that an instance satisfies the expected type contract.

        Args:
            instance (Any): The instance to verify.
            expected_type (type): The expected type or protocol the instance should satisfy.
            dotted_path (str): The dotted path of the class that produced the instance, used for error reporting.

        Raises:
            FactoryError: If the instance does not satisfy the expected type.
        """
        if not isinstance(instance, expected_type):
            raise FactoryError(
                f"'{dotted_path}' produced {type(instance).__name__} which does not satisfy {expected_type.__name__}"
            )

    @classmethod
    @abstractmethod
    def get_output_type(cls) -> type[FactoryOutput]:
        """Return the expected type of the output produced by the factory.

        Returns:
            type[FactoryOutput]: The expected type of the output.
        """

    @classmethod
    def build(cls, config: FactoryInput, **kwargs: Any) -> FactoryOutput:
        """Build and return an instance of the component based on the provided configuration.

        Args:
            config (FactoryInput): Configuration object containing parameters for building the component.
            **kwargs: Additional keyword arguments to pass to the component constructor, which can override
                config.init_args.

        Returns:
            FactoryOutput: An instance of the component that satisfies the expected type contract.

        Raises:
            FactoryError: If the component cannot be built or does not satisfy the expected type.
        """
        init_args = dict(config.init_args)
        cls_ = Factory._import_class(config.component)

        if kwargs:
            sig = inspect.signature(cls_)
            for key, value in kwargs.items():
                if key in sig.parameters:
                    init_args[key] = value

        logger.debug(
            "Building %s",
            config.component,
            extra={
                "operation": "build",
                "stage": "construction",
                "component_kind": "factory",
                "outcome": "started",
            },
        )
        instance = cls_(**init_args)
        output_type = cls.get_output_type()
        cls._verify(instance, output_type, config.component)
        logger.debug(
            "Built configured component",
            extra={
                "operation": "build",
                "stage": "construction",
                "component_kind": "factory",
                "outcome": "completed",
            },
        )

        return instance
