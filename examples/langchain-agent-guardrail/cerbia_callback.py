# SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
#
# SPDX-License-Identifier: Apache-2.0

"""CerbIA LangChain Callback Handler.

Provides multi-boundary guardrail scanning for autonomous agents and LLM chains:
- Input Boundary: Scans user prompts and chat messages before LLM execution.
- Tool Boundary: Scans tool call parameters before invocation (SSRF, malicious URLs, prompt injection).
- Tool Output Boundary: Scans tool return values before re-entering context (Indirect Prompt Injection).
- Output Boundary: Scans generated text before returning to the caller (Canary leaks, secrets, PII).
"""

from __future__ import annotations

import time
from typing import Any

from cerbia.core.security_gate import GateVerdict, SecurityGate
from cerbia.core.types import ContentType
from cerbia_middleware import (
    CerbiaAgentMiddleware,
    CerbiaSecurityException,
    ScanAuditRecord,
    _extract_text_content,
)
from langchain_core.callbacks.base import BaseCallbackHandler

__all__ = [
    "CerbiaAgentMiddleware",
    "CerbiaCallbackHandler",
    "CerbiaSecurityException",
    "ScanAuditRecord",
    "_extract_text_content",
]


class CerbiaCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler enforcing CerbIA guardrail gates at agent boundaries."""

    def __init__(
        self,
        input_gate: SecurityGate | None = None,
        output_gate: SecurityGate | None = None,
        tool_gate: SecurityGate | None = None,
        tool_output_gate: SecurityGate | None = None,
        raise_error: bool = True,
    ) -> None:
        """Initialize the CerbIA callback handler.

        Args:
            input_gate: Gate scanning prompts and incoming chat messages.
            output_gate: Gate scanning LLM generated responses.
            tool_gate: Gate scanning inputs passed to tools.
            tool_output_gate: Gate scanning external tool outputs (guards against indirect injection).
            raise_error: If True, raises `CerbiaSecurityException` on blocked content.
                         If False, logs the verdict in history and allows execution to continue.
        """
        super().__init__()
        self.input_gate = input_gate
        self.output_gate = output_gate
        self.tool_gate = tool_gate
        self.tool_output_gate = tool_output_gate
        self.raise_error = raise_error
        self.history: list[ScanAuditRecord] = []

    def _evaluate(
        self,
        gate: SecurityGate | None,
        content: str,
        boundary: str,
        metadata: dict[str, Any] | None = None,
    ) -> GateVerdict | None:
        """Evaluate content against the specified security gate."""
        if gate is None or not content:
            return None

        verdict = gate.scan(content, content_type=ContentType.TEXT)
        record = ScanAuditRecord(
            timestamp=time.time(),
            boundary=boundary,
            is_safe=verdict.is_safe,
            score=verdict.score,
            rationale=verdict.rationale or "",
            metadata=metadata or {},
        )
        self.history.append(record)

        if not verdict.is_safe and self.raise_error:
            raise CerbiaSecurityException(
                f"CerbIA security gate blocked content at boundary '{boundary}': {verdict.rationale}",
                boundary=boundary,
                verdict=verdict,
            )

        return verdict

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Scan LLM prompt strings before model invocation."""
        for idx, prompt in enumerate(prompts):
            self._evaluate(
                gate=self.input_gate,
                content=_extract_text_content(prompt),
                boundary="input",
                metadata={"prompt_index": idx, "caller": "llm"},
            )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before chat model invocation."""
        for msg_group in messages:
            for msg in msg_group:
                # Handle LangChain BaseMessage objects (msg.content) or raw strings/dicts
                content = getattr(msg, "content", msg.get("content") if isinstance(msg, dict) else msg)
                text = _extract_text_content(content)

                self._evaluate(
                    gate=self.input_gate,
                    content=text,
                    boundary="input",
                    metadata={"caller": "chat_model"},
                )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Scan LLM generated text before returning to the user/chain."""
        texts_to_check: list[str] = []

        if hasattr(response, "generations"):
            for generation_group in response.generations:
                for gen in generation_group:
                    if hasattr(gen, "text"):
                        texts_to_check.append(_extract_text_content(gen.text))
                    elif hasattr(gen, "message") and hasattr(gen.message, "content"):
                        texts_to_check.append(_extract_text_content(gen.message.content))
        elif isinstance(response, str):
            texts_to_check.append(response)
        elif hasattr(response, "content"):
            texts_to_check.append(_extract_text_content(response.content))

        for text in texts_to_check:
            self._evaluate(
                gate=self.output_gate,
                content=text,
                boundary="output",
                metadata={"caller": "llm_end"},
            )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Scan tool arguments before tool execution (prevents tool abuse / injection)."""
        tool_name = serialized.get("name", "unknown_tool") if isinstance(serialized, dict) else "unknown_tool"
        self._evaluate(
            gate=self.tool_gate,
            content=_extract_text_content(input_str),
            boundary="tool_input",
            metadata={"tool_name": tool_name},
        )

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Scan tool outputs before feeding back to context (prevents indirect injection)."""
        output_str = _extract_text_content(output)
        self._evaluate(
            gate=self.tool_output_gate,
            content=output_str,
            boundary="tool_output",
            metadata={"caller": "tool_end"},
        )

    def get_summary(self) -> dict[str, Any]:
        """Return a statistical summary of all evaluations performed by this handler."""
        total = len(self.history)
        blocked = sum(1 for r in self.history if not r.is_safe)
        return {
            "total_scans": total,
            "blocked_scans": blocked,
            "safe_scans": total - blocked,
            "boundaries": {
                b: sum(1 for r in self.history if r.boundary == b and not r.is_safe)
                for b in {"input", "output", "tool_input", "tool_output"}
            },
        }

    def clear_history(self) -> None:
        """Clear audit history records."""
        self.history.clear()
