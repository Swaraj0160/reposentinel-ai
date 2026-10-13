"""Unit tests for subprocess-isolated test execution sandbox."""

import pytest
from reposentinel.testing.runner import IsolatedTestRunner


def test_runner_passing_test_suite():
    runner = IsolatedTestRunner(timeout=10)
    code = """
import pytest

def add(a, b):
    return a + b

def test_add_positive():
    assert add(2, 3) == 5

def test_add_zero():
    assert add(5, 0) == 5
"""
    result = runner.run_test_code(code)
    assert result.status == "PASSED"
    assert result.exit_code == 0
    assert result.passed_count == 2
    assert result.failed_count == 0


def test_runner_failing_assertion():
    runner = IsolatedTestRunner(timeout=10)
    code = """
def test_will_fail():
    assert 1 == 2
"""
    result = runner.run_test_code(code)
    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert result.failed_count == 1


def test_runner_blocks_malicious_code_before_subprocess():
    runner = IsolatedTestRunner(timeout=10)
    code = """
import os

def test_pwn():
    assert True
"""
    result = runner.run_test_code(code)
    assert result.status == "ERROR"
    assert result.exit_code == -1
    assert "prohibited module import" in result.stderr.lower() or "os" in result.stderr.lower()


def test_runner_timeout_handling():
    # Test runner with short 1 second timeout
    runner = IsolatedTestRunner(timeout=1)
    # Using busy loop without imports that are blocked
    code = """
def test_infinite_loop():
    x = 0
    while True:
        x += 1
    assert x > 0
"""
    result = runner.run_test_code(code)
    assert result.status == "TIMEOUT"
    assert "timeout" in result.stderr.lower() or "timeout" in str(result.error_message).lower()
