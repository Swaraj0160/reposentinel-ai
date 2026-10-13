"""AST-based safety validator for model-generated test code."""

import ast
from typing import Tuple, Set

# Allowed safe standard library modules for generated unit tests
ALLOWED_MODULES: Set[str] = {
    "pytest",
    "math",
    "typing",
    "dataclasses",
    "datetime",
    "decimal",
    "collections",
    "re",
    "json",
    "itertools",
    "functools",
    "copy",
    "string",
}

# Strictly blocked calls and attributes that could compromise the host
BLOCKED_CALLS: Set[str] = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "breakpoint",
    "input",
    "exit",
    "quit",
}

BLOCKED_MODULES: Set[str] = {
    "os",
    "sys",
    "subprocess",
    "shutil",
    "socket",
    "urllib",
    "requests",
    "http",
    "pickle",
    "ctypes",
    "multiprocessing",
    "threading",
    "asyncio",
    "builtins",
    "importlib",
    "platform",
}


def validate_test_code_ast(code: str) -> Tuple[bool, str]:
    """
    Validates Python test code before allowing execution.
    
    Checks:
    1. Python syntax correctness
    2. Imports whitelist (disallows os, sys, subprocess, network, etc.)
    3. Blocked dangerous builtins (eval, exec, compile, etc.)
    
    Returns:
        (is_safe, reason_or_error_message)
    """
    if not code or not code.strip():
        return False, "Test code is empty."

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error in generated code: {e.msg} at line {e.lineno}"

    has_test_function = False

    for node in ast.walk(tree):
        # Check imports: import x
        if isinstance(node, ast.Import):
            for alias in node.names:
                base_module = alias.name.split(".")[0]
                if base_module in BLOCKED_MODULES:
                    return False, f"Prohibited module import: '{base_module}' is not allowed in sandbox tests."
                if base_module not in ALLOWED_MODULES:
                    return False, f"Module '{base_module}' is not in the allowed test whitelist."

        # Check imports: from x import y
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                base_module = node.module.split(".")[0]
                if base_module in BLOCKED_MODULES:
                    return False, f"Prohibited module import: 'from {base_module}' is not allowed in sandbox tests."
                if base_module not in ALLOWED_MODULES:
                    return False, f"Module '{base_module}' is not in the allowed test whitelist."

        # Check dangerous calls
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in BLOCKED_CALLS:
                    return False, f"Prohibited call: '{node.func.id}()' is not permitted in test code."
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in ("system", "popen", "spawn", "execv", "execve", "unlink", "remove", "rmdir"):
                    return False, f"Prohibited system call attribute: '.{node.func.attr}()'"

        # Verify at least one test function is defined
        elif isinstance(node, ast.FunctionDef):
            if node.name.startswith("test_"):
                has_test_function = True

    if not has_test_function:
        return False, "Generated code does not contain any functions starting with 'test_'."

    return True, "AST security validation passed: test code is syntactically valid and adheres to sandbox constraints."
