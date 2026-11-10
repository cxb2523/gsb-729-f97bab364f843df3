import importlib
import inspect
import subprocess
import sys
import textwrap
from typing import get_type_hints

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "protocol,client_name,other_protocol",
    [("decisions", "DecisionsClient", "systemone"), ("systemone", "SystemOneClient", "decisions")],
)
def test_protocol_only_api_when_importing_client(protocol: str, client_name: str, other_protocol: str) -> None:
    # Given
    api = importlib.import_module(f"cerbia.core.apis.{protocol}")
    # When
    client = getattr(api, client_name, None)
    # Then
    assert client is not None
    assert "format" not in inspect.signature(client).parameters
    assert client.__module__ == f"cerbia.core.apis.{protocol}._client"
    assert not {"DecisionClient", "HTTPAssessment"} & set(api.__all__)
    assert not any(name.lower().startswith(other_protocol) for name in api.__all__)


def test_independent_usage_when_protocol_models_are_imported() -> None:
    # Given
    decisions = importlib.import_module("cerbia.core.apis.decisions")
    systemone = importlib.import_module("cerbia.core.apis.systemone")
    # When
    usage_bases = decisions.DecisionsUsage.__mro__
    # Then
    assert systemone.Usage not in usage_bases
    assert {"input_tokens", "output_tokens"} <= decisions.DecisionsUsage.model_fields.keys()


@pytest.mark.parametrize("module", ["_base", "_http"])
def test_generic_shared_module_when_protocols_are_unavailable(module: str) -> None:
    # Given
    script = """
        import importlib
        import importlib.abc
        import sys

        class BlockProtocols(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.startswith(("cerbia.core.scanners", "cerbia.core.apis.decisions",
                                        "cerbia.core.apis.systemone")):
                    raise ModuleNotFoundError(fullname)
                return None

        sys.meta_path.insert(0, BlockProtocols())
        shared = importlib.import_module("cerbia.core.apis.MODULE")
        assert not any(name.startswith("Decision") for name in vars(shared))
        assert not {"ChoiceValue", "Probability", "TokenCount", "distribution",
                    "validate_choice", "validate_score", "HTTPAssessment"} & vars(shared).keys()
    """.replace("MODULE", module)
    # When
    result = subprocess.run([sys.executable, "-c", textwrap.dedent(script)], capture_output=True, text=True, timeout=30)
    # Then
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "protocol,scanner_name,evaluator_name,response_name",
    [
        ("decisions", "DecisionsScanner", "DecisionsEvaluator", "DecisionsResponse"),
        ("systemone", "SystemOneScanner", "SystemOneEvaluator", "SystemOneResponse"),
    ],
)
def test_separate_scanner_protocol_when_importing_policy(
    protocol: str, scanner_name: str, evaluator_name: str, response_name: str
) -> None:
    # Given
    policy = importlib.import_module(f"cerbia.core.scanners.{protocol}")
    api = importlib.import_module(f"cerbia.core.apis.{protocol}")
    # When
    scanner = getattr(policy, scanner_name)
    evaluator = getattr(policy, evaluator_name)
    # Then
    assert set(policy.__all__) == {scanner_name, evaluator_name}
    assert "format" not in inspect.signature(scanner).parameters
    assert get_type_hints(evaluator.__call__)["response"] is getattr(api, response_name)
    assert scanner.__bases__ == (object,)
