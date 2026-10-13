"""Subprocess-isolated test runner with strict resource limits and safe cleanup."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict

from reposentinel.core.config import TEST_EXECUTION_TIMEOUT
from reposentinel.core.models import TestExecutionResult
from reposentinel.testing.validator import validate_test_code_ast


class IsolatedTestRunner:
    """Executes validated pytest suites in an isolated temporary process."""

    def __init__(self, timeout: int = TEST_EXECUTION_TIMEOUT):
        self.timeout = timeout

    @staticmethod
    def _create_isolated_env() -> Dict[str, str]:
        """Creates a restricted environment dictionary excluding user secrets."""
        allowed_vars = {
            "PATH",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "PATHEXT",
            "COMSPEC",
            "HOMEDRIVE",
            "HOMEPATH",
            "USERPROFILE",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "PWD",
        }
        clean_env = {k: v for k, v in os.environ.items() if k.upper() in allowed_vars}
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        clean_env["PYTHONUNBUFFERED"] = "1"
        return clean_env

    def run_test_code(self, test_code: str) -> TestExecutionResult:
        """
        Validates code safety and executes pytest in a standalone temporary sandbox directory.
        """
        # Step 1: Pre-execution AST security check
        is_safe, error_msg = validate_test_code_ast(test_code)
        if not is_safe:
            return TestExecutionResult(
                status="ERROR",
                exit_code=-1,
                stdout="",
                stderr=error_msg,
                error_message=f"Pre-execution security validation failed: {error_msg}",
            )

        # Step 2: Create temporary isolated directory
        temp_dir = tempfile.mkdtemp(prefix="reposentinel_test_sandbox_")
        test_file = Path(temp_dir) / "test_suite.py"

        start_time = time.time()
        try:
            test_file.write_text(test_code, encoding="utf-8")

            # Determine Python executable (use current virtual environment interpreter)
            py_exec = sys.executable

            cmd = [
                py_exec,
                "-m",
                "pytest",
                "-v",
                "--tb=short",
                "-s",
                str(test_file.name),
            ]

            proc = subprocess.run(
                cmd,
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=self._create_isolated_env(),
            )
            duration = time.time() - start_time

            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode

            # Parse pytest summary line (e.g. "2 passed, 1 failed in 0.05s")
            passed_match = re.search(r"(\d+)\s+passed", stdout)
            failed_match = re.search(r"(\d+)\s+failed", stdout)
            passed_cnt = int(passed_match.group(1)) if passed_match else 0
            failed_cnt = int(failed_match.group(1)) if failed_match else 0

            # Pytest exit codes: 0 = All passed, 1 = Tests failed, 2 = Interrupted, 3 = Internal error, 4 = Usage error, 5 = No tests
            if exit_code == 0:
                status = "PASSED"
            elif exit_code == 1:
                status = "FAILED"
            else:
                status = "ERROR"

            return TestExecutionResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                passed_count=passed_cnt,
                failed_count=failed_cnt,
                execution_time_seconds=round(duration, 3),
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return TestExecutionResult(
                status="TIMEOUT",
                exit_code=-1,
                stdout="",
                stderr=f"Test execution exceeded the {self.timeout} second timeout limit.",
                execution_time_seconds=round(duration, 3),
                error_message=f"Timeout after {self.timeout}s (possible infinite loop or resource stall).",
            )
        except Exception as exc:
            duration = time.time() - start_time
            return TestExecutionResult(
                status="ERROR",
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                execution_time_seconds=round(duration, 3),
                error_message=f"Execution failed: {exc}",
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
