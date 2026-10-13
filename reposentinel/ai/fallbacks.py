"""Deterministic fallback engines when local Ollama is offline or unavailable."""

import ast
from typing import List, Dict, Any, Tuple

from reposentinel.ai.schemas import AITriageResponse, AITestPlanResponse
from reposentinel.core.models import SecretFinding, Advisory


def generate_deterministic_triage(
    secrets: List[SecretFinding],
    advisories: List[Advisory],
) -> AITriageResponse:
    """
    Produces deterministic, evidence-backed security triage without calling an LLM.
    Ensures the user always gets actionable analysis even when Ollama is offline.
    """
    has_critical = any(s.severity == "Critical" for s in secrets) or any(a.severity == "Critical" for a in advisories)
    has_high = any(s.severity == "High" for s in secrets) or any(a.severity == "High" for a in advisories)
    has_medium = any(s.severity == "Medium" for s in secrets) or any(a.severity == "Medium" for a in advisories)

    if has_critical:
        risk_level = "Critical"
    elif has_high:
        risk_level = "High"
    elif has_medium:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    prioritized: List[Dict[str, Any]] = []

    # Prioritize critical and high secrets first
    for s in secrets:
        if s.severity in ("Critical", "High"):
            prioritized.append({
                "target": f"{s.file}:{s.line}",
                "severity": s.severity,
                "rationale": f"Exposed {s.rule}. Credentials in source control risk credential compromise and unauthorized access.",
            })

    # Prioritize advisories with fixed versions
    for a in advisories:
        if a.severity in ("Critical", "High"):
            fix_text = f" Patched in version {a.fixed_version}." if a.fixed_version else " Review advisory for mitigation."
            prioritized.append({
                "target": f"{a.package} ({a.version})",
                "severity": a.severity,
                "rationale": f"Vulnerability {a.id} ({a.summary[:100]}...).{fix_text}",
            })

    # Build remediation guidance
    guidance: List[str] = []
    if secrets:
        guidance.append(
            "1. Revoke and rotate exposed credentials immediately. Do not simply delete them from the file without revoking the active token."
        )
        guidance.append(
            "2. Extract credentials into environment variables (.env) or a secret manager, and add .env to .gitignore."
        )

    for a in advisories:
        if a.fixed_version:
            guidance.append(f"Upgrade '{a.package}' from {a.version} to {a.fixed_version} or newer.")
        elif a.id:
            guidance.append(f"Inspect advisory {a.id} for package '{a.package}' and apply upstream mitigation.")

    if not guidance:
        guidance.append("No critical issues detected by deterministic heuristic rules. Continue regular code reviews.")

    uncertainties = [
        "Analysis generated via deterministic rule engine because local Ollama was unreachable or not selected.",
        "Secret scanner relies on pattern heuristics and entropy; false negatives (custom token formats) are possible.",
        "Dependency checks rely on OSV database entries matching parsed package versions.",
    ]

    # Build a clean markdown summary
    md_lines = [
        f"### 🛡️ Deterministic Security Triage (Risk Level: {risk_level})",
        "",
        "**Prioritized Findings:**",
    ]
    for item in prioritized[:10]:
        md_lines.append(f"- **[{item['severity']}] {item['target']}**: {item['rationale']}")

    md_lines.extend(["", "**Recommended Remediations:**"])
    for g in guidance[:8]:
        md_lines.append(f"- {g}")

    md_lines.extend(["", "**Assumptions & Uncertainties:**"])
    for u in uncertainties:
        md_lines.append(f"- {u}")

    return AITriageResponse(
        risk_level=risk_level,
        prioritized_findings=prioritized,
        remediation_guidance=guidance,
        uncertainties=uncertainties,
        raw_markdown="\n".join(md_lines),
    )


def generate_deterministic_test_plan(
    function_name: str,
    source_code: str,
) -> AITestPlanResponse:
    """
    Parses Python source code with AST and generates deterministic pytest test cases
    covering zero-division, invalid types, boundary values, and negative inputs.
    """
    edge_cases: List[str] = []
    assumptions: List[str] = [
        "Function is deterministic and self-contained",
        "Deterministic AST test generator synthesized boundary and type edge cases",
    ]

    # Parse AST to inspect parameters and operations
    params: List[str] = []
    has_division = False
    has_subtraction = False

    try:
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and (node.name == function_name or not params):
                function_name = node.name
                params = [arg.arg for arg in node.args.args]
            elif isinstance(node, ast.Div):
                has_division = True
            elif isinstance(node, ast.Sub):
                has_subtraction = True
    except SyntaxError:
        params = ["a", "b"]

    if not params:
        params = ["x"]

    test_lines = [
        "import pytest",
        "",
        "# Target function under test",
        source_code.strip(),
        "",
        "# Deterministic edge-case test suite generated by RepoSentinel AI",
    ]

    # 1. Normal standard test
    test_lines.append(f"def test_{function_name}_standard_case():")
    if len(params) == 2:
        test_lines.append(f"    result = {function_name}(50, 100)")
        test_lines.append("    assert result is not None")
        edge_cases.append("Standard positive input baseline (50, 100)")
    elif len(params) == 1:
        test_lines.append(f"    result = {function_name}(10)")
        test_lines.append("    assert result is not None")
        edge_cases.append("Standard positive input baseline (10)")
    else:
        args_str = ", ".join(["10"] * len(params))
        test_lines.append(f"    result = {function_name}({args_str})")
        test_lines.append("    assert result is not None")
        edge_cases.append("Standard positive input baseline")
    test_lines.append("")

    # 2. Zero / Division boundary test
    if has_division and len(params) >= 2:
        test_lines.append(f"def test_{function_name}_zero_denominator_boundary():")
        test_lines.append("    # Boundary: zero denominator should either raise ZeroDivisionError or return controlled fallback")
        test_lines.append(f"    with pytest.raises((ZeroDivisionError, ValueError)):")
        test_lines.append(f"        {function_name}(10, 0)")
        edge_cases.append("Zero denominator boundary condition (division by zero)")
        test_lines.append("")

    # 3. Negative inputs test
    test_lines.append(f"def test_{function_name}_negative_inputs():")
    if len(params) == 2:
        test_lines.append(f"    # Negative input behavior test")
        test_lines.append(f"    result = {function_name}(-10, 50)")
        test_lines.append("    assert isinstance(result, (int, float))")
        edge_cases.append("Negative input boundary (-10, 50)")
    else:
        test_lines.append(f"    result = {function_name}(-5)")
        test_lines.append("    assert result is not None")
        edge_cases.append("Negative input boundary (-5)")
    test_lines.append("")

    # 4. Type mismatch test (string instead of number)
    test_lines.append(f"def test_{function_name}_invalid_types():")
    test_lines.append("    # Robustness: passing non-numeric string should raise TypeError")
    test_lines.append("    with pytest.raises((TypeError, ValueError)):")
    if len(params) >= 2:
        test_lines.append(f"        {function_name}('invalid_str', 100)")
    else:
        test_lines.append(f"        {function_name}('invalid_str')")
    edge_cases.append("Invalid type error handling (string passed to numeric function)")
    test_lines.append("")

    # 5. None value test
    test_lines.append(f"def test_{function_name}_none_value():")
    test_lines.append("    # Robustness: passing None should raise TypeError or ValueError")
    test_lines.append("    with pytest.raises((TypeError, ValueError)):")
    if len(params) >= 2:
        test_lines.append(f"        {function_name}(None, 100)")
    else:
        test_lines.append(f"        {function_name}(None)")
    edge_cases.append("Null / None parameter handling")
    test_lines.append("")

    generated_code = "\n".join(test_lines)

    return AITestPlanResponse(
        function_name=function_name,
        edge_cases=edge_cases,
        assumptions=assumptions,
        test_code=generated_code,
    )
