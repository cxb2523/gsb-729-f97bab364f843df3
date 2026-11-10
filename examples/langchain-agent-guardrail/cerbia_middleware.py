# SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
#
# SPDX-License-Identifier: Apache-2.0

"""CerbIA LangChain Agent Middleware.

Provides multi-boundary guardrail interception for autonomous agents using LangChain's
AgentMiddleware architecture:
- Input Boundary (`before_agent` / `before_model`): Scans user prompts and messages before agent reasoning.
- Tool Boundary (`wrap_tool_call`): Validates tool call parameters before execution and
  scans external tool return values to prevent Indirect Prompt Injection.
- Output Boundary (`after_agent` / `after_model`): Scans model responses for secrets, canary leaks, and PII.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cerbia.core.security_gate import GateVerdict, SecurityGate
from cerbia.core.types import ContentType
from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.messages import ToolMessage

if TYPE_CHECKING:
    pass


def _extract_text_content(content: Any) -> str:
    """Extract raw string text from message content, supporting string or structured blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if "text" in item and isinstance(item["text"], str):
                    parts.append(item["text"])
                elif "content" in item and isinstance(item["content"], str):
                    parts.append(item["content"])
            elif hasattr(item, "text") and isinstance(item.text, str):
                parts.append(item.text)
        return " ".join(parts)
    if isinstance(content, dict):
        if "text" in content and isinstance(content["text"], str):
            return content["text"]
        if "content" in content and isinstance(content["content"], str):
            return content["content"]
    return str(content)


class CerbiaSecurityException(Exception):
    """Raised when a CerbIA security gate intercepts an unsafe prompt, response, or tool input."""

    def __init__(self, message: str, boundary: str, verdict: GateVerdict) -> None:
        super().__init__(message)
        self.boundary = boundary
        self.verdict = verdict


@dataclass
class ScanAuditRecord:
    """Audit record capturing the security scan verdict at a specific agent boundary."""

    timestamp: float
    boundary: str
    is_safe: bool
    score: float
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)


class CerbiaAgentMiddleware(AgentMiddleware):
    """LangChain Agent Middleware enforcing CerbIA guardrail gates at agent boundaries."""

    def __init__(
        self,
        input_gate: SecurityGate | None = None,
        output_gate: SecurityGate | None = None,
        tool_gate: SecurityGate | None = None,
        tool_output_gate: SecurityGate | None = None,
        raise_error: bool = True,
    ) -> None:
        """Initialize the CerbIA agent middleware.

        Args:
            input_gate: Gate scanning prompts and incoming chat messages.
            output_gate: Gate scanning LLM generated responses.
            tool_gate: Gate scanning inputs passed to tools.
            tool_output_gate: Gate scanning external tool outputs (guards against indirect injection).
            raise_error: If True, raises `CerbiaSecurityException` on blocked content.
                         If False, logs the verdict in history, blocks unsafe tools from executing,
                         and returns error messages into the agent context.
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

    def _scan_input_state(self, state: Any, caller: str = "before_agent") -> dict[str, Any] | None:
        """Scan input messages or prompt from state before agent/model execution."""
        messages: list[Any] = []
        if isinstance(state, dict):
            if "messages" in state:
                msgs = state["messages"]
                messages = msgs if isinstance(msgs, list) else [msgs]
            elif "input" in state:
                messages = [state["input"]]
        elif isinstance(state, list):
            messages = state
        elif hasattr(state, "messages"):
            msgs = state.messages
            messages = msgs if isinstance(msgs, list) else [msgs]
        elif isinstance(state, str):
            messages = [state]

        for msg in messages:
            content = getattr(msg, "content", msg.get("content") if isinstance(msg, dict) else msg)
            text = _extract_text_content(content)
            self._evaluate(
                gate=self.input_gate,
                content=text,
                boundary="input",
                metadata={"caller": caller},
            )
        return None

    def _scan_output_state(self, state: Any, caller: str = "after_agent") -> dict[str, Any] | None:
        """Scan generated output messages or response from state after agent/model execution."""
        messages: list[Any] = []
        if isinstance(state, dict):
            if "messages" in state:
                msgs = state["messages"]
                messages = msgs if isinstance(msgs, list) else [msgs]
            elif "output" in state:
                messages = [state["output"]]
        elif isinstance(state, list):
            messages = state
        elif hasattr(state, "messages"):
            msgs = state.messages
            messages = msgs if isinstance(msgs, list) else [msgs]
        elif isinstance(state, str):
            messages = [state]

        if messages:
            # Evaluate the last message (representing the latest model generation)
            last_msg = messages[-1]
            content = getattr(last_msg, "content", last_msg.get("content") if isinstance(last_msg, dict) else last_msg)
            text = _extract_text_content(content)
            self._evaluate(
                gate=self.output_gate,
                content=text,
                boundary="output",
                metadata={"caller": caller},
            )
        return None

    def before_agent(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Intercept input boundary before agent execution starts."""
        return self._scan_input_state(state, caller="before_agent")

    def before_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Intercept input boundary before model is called."""
        return self._scan_input_state(state, caller="before_model")

    def after_agent(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Intercept output boundary after agent execution completes."""
        return self._scan_output_state(state, caller="after_agent")

    def after_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Intercept output boundary after model is called."""
        return self._scan_output_state(state, caller="after_model")

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Any],
    ) -> ToolMessage | Any:
        """Intercept tool call arguments and results for security scanning."""
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown_tool") if isinstance(tool_call, dict) else "unknown_tool"
        tool_args = tool_call.get("args", {}) if isinstance(tool_call, dict) else {}
        call_id = tool_call.get("id", "call_unknown") if isinstance(tool_call, dict) else "call_unknown"

        if isinstance(tool_args, dict):
            arg_texts = [_extract_text_content(v) for v in tool_args.values()]
            args_content = " ".join(arg_texts)
        else:
            args_content = _extract_text_content(tool_args)

        # 1. Tool Input Gate Evaluation
        verdict_in = self._evaluate(
            gate=self.tool_gate,
            content=args_content,
            boundary="tool_input",
            metadata={"tool_name": tool_name, "call_id": call_id},
        )
        if verdict_in and not verdict_in.is_safe:
            return ToolMessage(
                content=f"CerbIA security gate blocked tool execution: {verdict_in.rationale}",
                tool_call_id=call_id,
                status="error",
            )

        # 2. Execute the tool
        result = handler(request)

        # 3. Tool Output Gate Evaluation (indirect prompt injection prevention)
        if isinstance(result, ToolMessage) or hasattr(result, "content"):
            output_text = _extract_text_content(result.content)
        else:
            output_text = str(result)

        verdict_out = self._evaluate(
            gate=self.tool_output_gate,
            content=output_text,
            boundary="tool_output",
            metadata={"tool_name": tool_name, "call_id": call_id},
        )
        if verdict_out and not verdict_out.is_safe:
            return ToolMessage(
                content=f"CerbIA security gate blocked tool output: {verdict_out.rationale}",
                tool_call_id=call_id,
                status="error",
            )

        return result

    async def abefore_agent(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Async hook before agent execution starts."""
        return self.before_agent(state, runtime)

    async def abefore_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Async hook before model is called."""
        return self.before_model(state, runtime)

    async def aafter_agent(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Async hook after agent execution completes."""
        return self.after_agent(state, runtime)

    async def aafter_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        """Async hook after model is called."""
        return self.after_model(state, runtime)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Any]],
    ) -> ToolMessage | Any:
        """Async intercept tool call arguments and results for security scanning."""
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown_tool") if isinstance(tool_call, dict) else "unknown_tool"
        tool_args = tool_call.get("args", {}) if isinstance(tool_call, dict) else {}
        call_id = tool_call.get("id", "call_unknown") if isinstance(tool_call, dict) else "call_unknown"

        if isinstance(tool_args, dict):
            arg_texts = [_extract_text_content(v) for v in tool_args.values()]
            args_content = " ".join(arg_texts)
        else:
            args_content = _extract_text_content(tool_args)

        verdict_in = self._evaluate(
            gate=self.tool_gate,
            content=args_content,
            boundary="tool_input",
            metadata={"tool_name": tool_name, "call_id": call_id},
        )
        if verdict_in and not verdict_in.is_safe:
            return ToolMessage(
                content=f"CerbIA security gate blocked tool execution: {verdict_in.rationale}",
                tool_call_id=call_id,
                status="error",
            )

        result = await handler(request)

        if isinstance(result, ToolMessage) or hasattr(result, "content"):
            output_text = _extract_text_content(result.content)
        else:
            output_text = str(result)

        verdict_out = self._evaluate(
            gate=self.tool_output_gate,
            content=output_text,
            boundary="tool_output",
            metadata={"tool_name": tool_name, "call_id": call_id},
        )
        if verdict_out and not verdict_out.is_safe:
            return ToolMessage(
                content=f"CerbIA security gate blocked tool output: {verdict_out.rationale}",
                tool_call_id=call_id,
                status="error",
            )

        return result

    def get_summary(self) -> dict[str, Any]:
        """Return a statistical summary of all evaluations performed by this middleware."""
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
