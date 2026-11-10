from types import MappingProxyType
from typing import Final

DEFAULT_MODEL_REF: Final = "protectai/deberta-v3-base-prompt-injection-v2"
DEFAULT_MODEL_REVISION: Final = "89b085cd330414d3e7d9dd787870f315957e1e9f"
DEFAULT_MODEL_SUBFOLDER: Final = "onnx"
DEFAULT_MODEL_FILENAME: Final = "model.onnx"
DEFAULT_MODEL_KWARGS: Final = MappingProxyType({"provider": "CPUExecutionProvider"})

DEFAULT_PIPELINE_KWARGS: Final = MappingProxyType(
    {
        "return_token_type_ids": False,
        "max_length": 512,
        "truncation": True,
        "device": "cpu",
    }
)

DEFAULT_TOKENIZER_REF: Final = DEFAULT_MODEL_REF
DEFAULT_TOKENIZER_REVISION: Final = DEFAULT_MODEL_REVISION
DEFAULT_TOKENIZER_SUBFOLDER: Final = None
DEFAULT_TOKENIZER_FILENAME: Final = None
DEFAULT_TOKENIZER_KWARGS: Final = MappingProxyType({})
