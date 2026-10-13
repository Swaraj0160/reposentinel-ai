"""Unit tests for AST-based test code validator."""

import pytest
from reposentinel.testing.validator import validate_test_code_ast


def test_valid_pytest_code_passes():
    valid_code = """
import pytest
import math

def calculate(x, y):
    return x + y

def test_calculate_standard():
    assert calculate(2, 3) == 5

def test_calculate_negative():
    assert calculate(-1, -1) == -2
"""
    is_safe, msg = validate_test_code_ast(valid_code)
    assert is_safe is True
    assert "passed" in msg.lower()


def test_syntax_error_fails():
    broken_code = """
def test_broken(
    assert True
"""
    is_safe, msg = validate_test_code_ast(broken_code)
    assert is_safe is False
    assert "syntax error" in msg.lower()


def test_blocked_os_import_fails():
    malicious_code = """
import os

def test_something():
    os.system("whoami")
    assert True
"""
    is_safe, msg = validate_test_code_ast(malicious_code)
    assert is_safe is False
    assert "prohibited module import" in msg.lower() or "os" in msg.lower()


def test_blocked_subprocess_import_fails():
    malicious_code = """
import subprocess

def test_run():
    subprocess.run(["calc.exe"])
    assert True
"""
    is_safe, msg = validate_test_code_ast(malicious_code)
    assert is_safe is False
    assert "subprocess" in msg.lower()


def test_blocked_eval_call_fails():
    malicious_code = """
def test_eval():
    eval("__import__('os').system('dir')")
    assert True
"""
    is_safe, msg = validate_test_code_ast(malicious_code)
    assert is_safe is False
    assert "prohibited call" in msg.lower() or "eval" in msg.lower()


def test_missing_test_functions_fails():
    non_test_code = """
def helper(x):
    return x * 2
"""
    is_safe, msg = validate_test_code_ast(non_test_code)
    assert is_safe is False
    assert "does not contain any functions starting with 'test_'" in msg.lower()
