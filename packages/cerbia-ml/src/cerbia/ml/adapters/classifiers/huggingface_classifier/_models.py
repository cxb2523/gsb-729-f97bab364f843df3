from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HuggingFaceClassifierAdapterConfig(BaseModel):
    """Configuration for the HuggingFace text-classification runtime.

    Attributes:
        pipeline_kwargs (dict[str, Any]): Extra keyword arguments forwarded to ``transformers.pipeline`` after the
            adapter sets the execution device.
        tokenizer_kwargs (dict[str, Any]): Extra keyword arguments forwarded to ``AutoTokenizer.from_pretrained`` when
            loading the tokenizer.
        model_kwargs (dict[str, Any]): Extra keyword arguments forwarded to
            ``ORTModelForSequenceClassification.from_pretrained`` when loading the ONNX model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    pipeline_kwargs: dict[str, Any] = Field(default_factory=dict)
    tokenizer_kwargs: dict[str, Any] = Field(default_factory=dict)
    model_kwargs: dict[str, Any] = Field(default_factory=dict)
