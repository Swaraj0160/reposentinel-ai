"""Secret detection engine with high-precision heuristic rules and entropy analysis."""

import math
import os
import re
from pathlib import Path
from typing import List, Tuple, Optional

from reposentinel.core.config import MAX_FILE_BYTES, SKIP_DIRS, TEXT_EXTS, CONFIG_FILENAMES
from reposentinel.core.models import SecretFinding

# Secret detection rule definitions: (Rule Name, Severity, Regex, Redaction Label, Capturing Group Index)
SECRET_RULES = [
    (
        "Private Key",
        "Critical",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
        0,
    ),
    (
        "AWS Access Key ID",
        "High",
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY]",
        0,
    ),
    (
        "AWS Secret Access Key",
        "Critical",
        re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "[REDACTED_AWS_SECRET_KEY]",
        1,
    ),
    (
        "GitHub Personal Access Token",
        "Critical",
        re.compile(r"\b(?:ghp_[A-Za-z0-9_]{30,40}|github_pat_[A-Za-z0-9_]{82})\b"),
        "[REDACTED_GITHUB_PAT]",
        0,
    ),
    (
        "GitHub OAuth/App Token",
        "High",
        re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
        "[REDACTED_GITHUB_TOKEN]",
        0,
    ),
    (
        "Slack Bot/User Token",
        "High",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b"),
        "[REDACTED_SLACK_TOKEN]",
        0,
    ),
    (
        "Stripe Secret Key",
        "Critical",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        "[REDACTED_STRIPE_KEY]",
        0,
    ),
    (
        "OpenAI API Key",
        "High",
        re.compile(r"\bsk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,}\b"),
        "[REDACTED_OPENAI_KEY]",
        0,
    ),
    (
        "Anthropic API Key",
        "High",
        re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{32,}\b"),
        "[REDACTED_ANTHROPIC_KEY]",
        0,
    ),
    (
        "Google / Firebase API Key",
        "Medium",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "[REDACTED_GOOGLE_KEY]",
        0,
    ),
    (
        "Database Connection URI with Password",
        "Critical",
        re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:'\"]+:([^\s@'\"]+)@[^\s'\"]+"),
        "[REDACTED_DB_PASSWORD]",
        1,
    ),
    (
        "Generic High-Entropy API Token Assignment",
        "Medium",
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-\/+=]{16,})['\"]"),
        "[REDACTED_API_TOKEN]",
        1,
    ),
    (
        "Hardcoded Password Assignment",
        "Medium",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\r\n]{6,})['\"]"),
        "[REDACTED_PASSWORD]",
        1,
    ),
    (
        "JSON Web Token (JWT)",
        "Low",
        re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
        "[REDACTED_JWT]",
        0,
    ),
]

# Obvious placeholder / dummy indicators that signal a mock or sample credential
PLACEHOLDER_KEYWORDS = [
    "example",
    "placeholder",
    "dummy",
    "fake",
    "changeme",
    "replace_me",
    "replace-me",
    "test_key",
    "test-key",
    "do_not_use",
    "mock_token",
    "mock-token",
    "your_key",
    "your_token",
    "your_api_key",
    "your_password",
    "your-api-key",
    "your-secret",
    "foobar",
]

DUMMY_EXACT_VALUES = {
    "123456",
    "12345678",
    "1234567890",
    "00000000",
    "xxxxxxxx",
    "xxxx-xxxx-xxxx",
    "abcdefgh",
    "password",
    "admin123",
}

# Patterns for reading secrets from env or config rather than hardcoding
ENV_READ_PATTERNS = [
    re.compile(r"(?i)process\.env\.[A-Z0-9_]+"),
    re.compile(r"(?i)os\.environ(?:\.get)?\s*\["),
    re.compile(r"(?i)os\.getenv\s*\("),
    re.compile(r"(?i)System\.getenv\s*\("),
    re.compile(r"(?i)env\s*\(\s*['\"][A-Z0-9_]+['\"]\s*\)"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder_or_env_read(line: str, matched_val: str, rule_name: str = "") -> bool:
    """Returns True if the finding is an obvious placeholder or reading an env variable."""
    # Check for env reads
    for env_pattern in ENV_READ_PATTERNS:
        if env_pattern.search(line):
            return True

    # Check template variable syntax <TOKEN> or ${API_KEY}
    if re.search(r"<[A-Za-z0-9_.-]+>", line) or re.search(r"\$\{[A-Za-z0-9_.-]+\}", line):
        return True

    # Check exact dummy values
    if matched_val.strip().lower() in DUMMY_EXACT_VALUES:
        return True

    # Check single repeated character (e.g., "aaaaaaaa")
    if len(matched_val) > 6 and len(set(matched_val)) <= 2:
        return True

    line_lower = line.lower()
    val_lower = matched_val.lower()

    # Check placeholder keywords against the line and matched token
    for kw in PLACEHOLDER_KEYWORDS:
        if kw in line_lower or kw in val_lower:
            return True

    # Low entropy heuristic strictly for generic tokens or passwords
    if rule_name in ("Generic High-Entropy API Token Assignment", "Hardcoded Password Assignment"):
        if len(matched_val) > 16 and calculate_shannon_entropy(matched_val) < 2.5:
            return True

    return False


def safe_redact(line: str, matched_val: str, redaction_label: str) -> str:
    """Redacts the sensitive matched value from the evidence line safely."""
    if not matched_val:
        return line.strip()
    # If the line contains the raw matched value, replace it
    if matched_val in line:
        redacted = line.replace(matched_val, redaction_label)
    else:
        # Fallback regex redaction
        redacted = re.sub(re.escape(matched_val), redaction_label, line)

    # General scrub of any remaining generic tokens in the same line
    redacted = re.sub(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]", redacted)
    redacted = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "[REDACTED_GITHUB_TOKEN]", redacted)

    return redacted.strip()[:240]


def is_binary_file(file_path: Path) -> bool:
    """Detects whether a file is binary by looking for null bytes in initial chunk."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def should_skip_path(relative_path: Path) -> bool:
    """Checks whether the file or directory should be ignored."""
    for part in relative_path.parts:
        if part in SKIP_DIRS or part.startswith(".git"):
            return True
    return False


def scan_directory_for_secrets(
    root: Path,
    include_placeholders: bool = False,
) -> Tuple[List[SecretFinding], int]:
    """
    Scans a directory tree for hardcoded secrets and credentials.
    
    Returns:
        (List[SecretFinding], total_scanned_files_count)
    """
    findings: List[SecretFinding] = []
    scanned_count = 0
    finding_counter = 1

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        try:
            rel_path = path.relative_to(root)
        except ValueError:
            rel_path = path

        if should_skip_path(rel_path):
            continue

        # File type check
        if path.suffix.lower() not in TEXT_EXTS and path.name not in CONFIG_FILENAMES:
            continue

        # Size check
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        # Binary check
        if is_binary_file(path):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        scanned_count += 1
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                # Check comments too, but if it says example/dummy, skip
                if any(kw in stripped.lower() for kw in PLACEHOLDER_KEYWORDS):
                    continue

            for rule_name, severity, pattern, redaction_label, group_idx in SECRET_RULES:
                match = pattern.search(line)
                if match:
                    matched_val = match.group(group_idx) if group_idx <= len(match.groups()) else match.group(0)
                    is_placeholder = is_placeholder_or_env_read(line, matched_val, rule_name)

                    if is_placeholder and not include_placeholders:
                        continue

                    # Context window (1 line before, 1 line after)
                    start_ctx = max(0, line_no - 2)
                    end_ctx = min(len(lines), line_no + 1)
                    raw_context = lines[start_ctx:end_ctx]
                    redacted_context = [
                        safe_redact(ctx_line, matched_val, redaction_label)
                        for ctx_line in raw_context
                    ]

                    evidence = safe_redact(line, matched_val, redaction_label)

                    findings.append(
                        SecretFinding(
                            id=f"SEC-{finding_counter:04d}",
                            rule=rule_name,
                            severity=severity,
                            file=str(rel_path).replace("\\", "/"),
                            line=line_no,
                            evidence=evidence,
                            recommendation=(
                                "Revoke and rotate this credential immediately if live. "
                                "Store secrets in environment variables (.env) or a secret manager (e.g. AWS Secrets Manager, Vault)."
                            ),
                            is_placeholder=is_placeholder,
                            context_lines=redacted_context,
                        )
                    )
                    finding_counter += 1
                    break  # One finding per line to avoid duplicate rules on identical token

    return findings, scanned_count
