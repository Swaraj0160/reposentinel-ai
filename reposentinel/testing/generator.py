"""Coordinates AI-based and deterministic test plan generation."""

from typing import Tuple

from reposentinel.ai.fallbacks import generate_deterministic_test_plan
from reposentinel.ai.ollama_client import OllamaClient
from reposentinel.ai.prompts import build_test_gen_prompt
from reposentinel.ai.schemas import validate_test_plan_json
from reposentinel.core.models import TestPlan
from reposentinel.testing.validator import validate_test_code_ast


class TestGenerator:
    """Generates and validates edge-case pytest suites."""

    def __init__(self, ollama_client: OllamaClient = None):
        self.ollama = ollama_client or OllamaClient()

    def generate_tests_for_function(
        self,
        function_name: str,
        source_code: str,
        model_name: str = "qwen2.5-coder:7b",
        force_deterministic: bool = False,
    ) -> TestPlan:
        """
        Generates edge-case tests using local Ollama model if available,
        falling back deterministically if Ollama is unreachable.
        """
        if not force_deterministic:
            # Check Ollama connection
            conn_ok, _ = self.ollama.check_connection()
            if conn_ok:
                prompt = build_test_gen_prompt(function_name, source_code)
                raw_resp, err = self.ollama.generate(prompt=prompt, model=model_name, format_json=True)
                if not err and raw_resp:
                    plan_resp, val_err = validate_test_plan_json(raw_resp)
                    if plan_resp and plan_resp.test_code:
                        is_safe, sec_msg = validate_test_code_ast(plan_resp.test_code)
                        if is_safe:
                            return TestPlan(
                                function_name=function_name,
                                module_or_file="user_code.py",
                                edge_cases_identified=plan_resp.edge_cases,
                                generated_code=plan_resp.test_code,
                                assumptions=plan_resp.assumptions,
                                is_validated=True,
                                validation_error=None,
                            )

        # Fallback to deterministic AST test generator
        fallback = generate_deterministic_test_plan(function_name, source_code)
        is_safe, sec_msg = validate_test_code_ast(fallback.test_code)

        return TestPlan(
            function_name=function_name,
            module_or_file="user_code.py",
            edge_cases_identified=fallback.edge_cases,
            generated_code=fallback.test_code,
            assumptions=fallback.assumptions,
            is_validated=is_safe,
            validation_error=None if is_safe else sec_msg,
        )
