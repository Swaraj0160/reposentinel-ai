"""Structured schemas and validation for local AI model responses."""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class AITriageResponse:
    """Validated structured triage from local model."""
    risk_level: str  # Critical, High, Medium, Low
    prioritized_findings: List[Dict[str, Any]] = field(default_factory=list)
    remediation_guidance: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    raw_markdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "prioritized_findings": self.prioritized_findings,
            "remediation_guidance": self.remediation_guidance,
            "uncertainties": self.uncertainties,
            "raw_markdown": self.raw_markdown,
        }


@dataclass
class AITestPlanResponse:
    """Validated structured test generation response."""
    function_name: str
    edge_cases: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    test_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "edge_cases": self.edge_cases,
            "assumptions": self.assumptions,
            "test_code": self.test_code,
        }


def validate_triage_json(raw_text: str) -> Tuple[Optional[AITriageResponse], Optional[str]]:
    """
    Validates and extracts structured triage response from raw model text.
    Handles pure JSON or JSON embedded in markdown code blocks.
    """
    if not raw_text or not raw_text.strip():
        return None, "Empty model response"

    cleaned = raw_text.strip()
    # Strip markdown code blocks if wrapped
    if "```json" in cleaned:
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in cleaned:
        cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            return None, "Root JSON must be an object"

        risk_level = str(data.get("risk_level", "Medium")).capitalize()
        if risk_level not in ("Critical", "High", "Medium", "Low"):
            risk_level = "Medium"

        findings = data.get("prioritized_findings", [])
        if not isinstance(findings, list):
            findings = []

        remediation = data.get("remediation_guidance", [])
        if not isinstance(remediation, list):
            remediation = [str(remediation)] if remediation else []

        uncertainties = data.get("uncertainties", [])
        if not isinstance(uncertainties, list):
            uncertainties = [str(uncertainties)] if uncertainties else []

        return AITriageResponse(
            risk_level=risk_level,
            prioritized_findings=findings,
            remediation_guidance=[str(r) for r in remediation],
            uncertainties=[str(u) for u in uncertainties],
            raw_markdown=raw_text,
        ), None

    except json.JSONDecodeError as exc:
        return None, f"JSON parsing failed: {exc}"


def validate_test_plan_json(raw_text: str) -> Tuple[Optional[AITestPlanResponse], Optional[str]]:
    """
    Validates and extracts structured test plan response from raw model text.
    """
    if not raw_text or not raw_text.strip():
        return None, "Empty model response"

    cleaned = raw_text.strip()
    if "```json" in cleaned:
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned.strip("` \n")

    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            return None, "Root JSON must be an object"

        func_name = str(data.get("function_name", "unknown_function"))
        edge_cases = data.get("edge_cases", [])
        if not isinstance(edge_cases, list):
            edge_cases = [str(edge_cases)] if edge_cases else []

        assumptions = data.get("assumptions", [])
        if not isinstance(assumptions, list):
            assumptions = [str(assumptions)] if assumptions else []

        test_code = str(data.get("test_code", ""))
        # Strip code markdown ticks if embedded inside string
        if test_code.startswith("```"):
            test_code = test_code.split("\n", 1)[1] if "\n" in test_code else test_code
            test_code = test_code.rsplit("```", 1)[0].strip()

        return AITestPlanResponse(
            function_name=func_name,
            edge_cases=[str(ec) for ec in edge_cases],
            assumptions=[str(a) for a in assumptions],
            test_code=test_code,
        ), None

    except json.JSONDecodeError:
        # Fallback: if model returned python code directly instead of json
        if "def test_" in raw_text or "import pytest" in raw_text:
            return AITestPlanResponse(
                function_name="analyzed_function",
                edge_cases=["Direct Python test output generated"],
                assumptions=["Model returned direct test script"],
                test_code=raw_text.strip("` \n"),
            ), None
        return None, "Could not extract valid test plan or Python code"
