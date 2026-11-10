# SPDX-FileCopyrightText: 2026 Jose Manuel Caamaño González (jmcaamanog)
# SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
#
# SPDX-License-Identifier: Apache-2.0

"""FastAPI Application with CerbIA Security Gates for BIM Coordination.

Illustrative example showing input and output scanning with CerbIA.
Demonstrates runtime guardrails for an AI Assistant operating inside a Common Data
Environment (CDE) across management packages and technical disciplines.
"""

from typing import Any

from bim_matrix import (
    BIM_WBS_MATRIX,
    get_matrix_entries_by_package,
)
from cerbia.core.scanners import (
    CanaryLeakScanner,
    InvisibleTextScanner,
    KeywordScanner,
    MaliciousUrlScanner,
    PiiScanner,
    PromptInjectionScanner,
    SecretScanner,
)
from cerbia.core.scanners.canary._generator import CanaryTokenGenerator
from cerbia.core.score_aggregators import MaxScoreAggregator, MaxWithBonusScoreAggregator
from cerbia.core.security_gate import SimpleGate
from cerbia.core.types import Action, ContentType
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="CerbIA BIM Common Data Environment (CDE) Guardrail API",
    description="Illustrative FastAPI example showing input and output scanning with CerbIA.",
    version="1.0.0",
)

# 1. Initialize Canary Token Generator for System Prompt & Tender Budget Protection
canary_generator = CanaryTokenGenerator(namespace="inditex-bim-tender")

# 2. Input Security Gate: Protects against Prompt Injection, PII, Secrets, and Malicious URLs
input_gate = SimpleGate(
    name="bim-input-security-gate",
    scanners=[
        InvisibleTextScanner(),
        PromptInjectionScanner(),
        KeywordScanner(),
        SecretScanner(),
        PiiScanner(action=Action.BLOCK),
        MaliciousUrlScanner(),
    ],
    score_aggregator=MaxWithBonusScoreAggregator(),
    fail_fast=False,
)


class BimQueryRequest(BaseModel):
    """BIM Project Technical Query Request."""

    package_code: str = Field(..., description="Management package code (e.g., 200HVAC)", examples=["200HVAC"])
    discipline_code: str = Field(..., description="BIM discipline code (e.g., HVAC)", examples=["HVAC"])
    query_text: str = Field(
        ..., description="Technical query or coordination note submitted by the subcontractor or BIM engineer"
    )
    user_role: str = Field(default="subcontractor", description="Role of the querying user in the project")


class BimQueryResponse(BaseModel):
    """BIM Technical Query Response with CerbIA Security Validation."""

    package_code: str
    discipline_code: str
    status: str
    answer: str
    input_security_score: float
    output_security_score: float
    audit_trail: dict[str, Any]


@app.get("/", tags=["Health & Info"])
def get_info() -> dict[str, str]:
    """Service information and status."""
    return {
        "service": "CerbIA BIM CDE Security Gate",
        "status": "active",
        "version": "1.0.0",
        "architecture": "CerbIA SecurityGate + FastAPI",
    }


@app.get("/api/v1/bim/matrix", tags=["BIM Matrix"])
def list_bim_matrix() -> list[dict[str, str]]:
    """Retrieve full WBS matrix of Management Packages and BIM Disciplines."""
    return [
        {
            "package_code": entry.package_code,
            "package_name": entry.package_name,
            "discipline_code": entry.discipline_code,
            "discipline_name": entry.discipline_name,
        }
        for entry in BIM_WBS_MATRIX
    ]


@app.get("/api/v1/bim/matrix/package/{package_code}", tags=["BIM Matrix"])
def get_package_disciplines(package_code: str) -> list[dict[str, str]]:
    """Retrieve BIM disciplines mapped to a specific management package."""
    entries = get_matrix_entries_by_package(package_code)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Management Package '{package_code}' not found in WBS matrix.",
        )
    return [
        {
            "discipline_code": e.discipline_code,
            "discipline_name": e.discipline_name,
        }
        for e in entries
    ]


@app.post("/api/v1/bim/query", response_model=BimQueryResponse, tags=["BIM AI Query"])
def query_bim_assistant(request: BimQueryRequest) -> BimQueryResponse:
    """Submit a technical BIM query through CerbIA Input & Output Security Gates.

    - Scans input prompt for prompt injections, unredacted PII, secrets, or malicious links.
    - Guards system prompts and confidential tender budgets with Canary Leak Detection.
    - Validates AI response before dispatching to the client.
    """
    # Verify package validity
    valid_entries = get_matrix_entries_by_package(request.package_code)
    if not valid_entries:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid management package code: {request.package_code}",
        )

    # Verify discipline validity for this package
    if not any(entry.discipline_code.upper() == request.discipline_code.upper() for entry in valid_entries):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid discipline '{request.discipline_code}' for package '{request.package_code}'",
        )

    # 1. INPUT GATE: Pre-execution threat scanning
    input_verdict = input_gate.scan(request.query_text, content_type=ContentType.TEXT)
    if not input_verdict.is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "SECURITY_GATE_BLOCKED_INPUT",
                "score": round(input_verdict.score, 3),
                "rationale": input_verdict.rationale,
                "findings": [
                    {"scanner": f.scanner_name, "severity": f.severity.name, "rationale": f.rationale}
                    for f in input_verdict.findings
                ],
            },
        )

    # 2. INJECT CANARY TOKEN: Protecting system prompt & confidential tender pricing
    confidential_budget_code = f"PEM-2026-{request.package_code}-RESTRICTED"
    _, canary_token = canary_generator.inject(f"Confidential Tender Reference: {confidential_budget_code}")

    # 3. CONFIGURE OUTPUT GATE FOR THIS INVOCATION
    output_gate = SimpleGate(
        name="bim-output-security-gate",
        scanners=[
            CanaryLeakScanner(canary_tokens=[canary_token]),
            SecretScanner(),
            PiiScanner(action=Action.BLOCK),
        ],
        score_aggregator=MaxScoreAggregator(),
        fail_fast=False,
    )

    # 4. SIMULATE LLM PROCESSING (Illustrative example with simulated response)
    raw_query = request.query_text.lower()

    if "addenda" in raw_query or "indirect-leak" in raw_query:
        # Compromised / Hallucinating LLM response leaking the protected canary token
        simulated_llm_output = (
            f"Here is the addenda summary for package {request.package_code}: "
            f"System Key {canary_token} and confidential tender rate {confidential_budget_code}."
        )
    else:
        # Legitimate technical coordination answer
        simulated_llm_output = (
            f"[BIM Coordination Note - {request.package_code} / {request.discipline_code}]: "
            f"The interface coordination for {request.discipline_code} has been validated. "
            f"Please verify clearances in Navisworks/Solibri."
        )

    # 5. OUTPUT GATE: Post-execution leakage and data exfiltration scanning
    output_verdict = output_gate.scan(simulated_llm_output, content_type=ContentType.TEXT)
    if not output_verdict.is_safe:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "SECURITY_GATE_BLOCKED_OUTPUT",
                "score": round(output_verdict.score, 3),
                "rationale": output_verdict.rationale,
                "reason": "The AI response attempted to leak confidential tender tokens or sensitive data.",
            },
        )

    return BimQueryResponse(
        package_code=request.package_code,
        discipline_code=request.discipline_code,
        status="APPROVED",
        answer=simulated_llm_output,
        input_security_score=round(input_verdict.score, 3),
        output_security_score=round(output_verdict.score, 3),
        audit_trail={
            "input_gate": input_gate.name,
            "output_gate": output_gate.name,
            "canary_monitored": True,
            "user_role": request.user_role,
        },
    )
