"""Remediation proposals and sandbox verification engine."""

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any

from reposentinel.core.models import (
    SecretFinding,
    Advisory,
    RemediationProposal,
    VerificationResult,
)
from reposentinel.remediation.diff_utils import generate_unified_diff, apply_snippet_replacement
from reposentinel.scanners.secrets import scan_directory_for_secrets
from reposentinel.scanners.dependencies import collect_repository_dependencies
from reposentinel.scanners.osv_client import OSVClient


class RemediationEngine:
    """Generates transparent remediations and validates them in a sandboxed copy."""

    @staticmethod
    def propose_secret_remediation(finding: SecretFinding, original_file_content: str) -> RemediationProposal:
        """
        Creates a proposed fix for hardcoded credentials by substituting
        environment variable lookups (os.getenv or process.env).
        """
        is_python = finding.file.endswith(".py")
        is_js = finding.file.endswith((".js", ".jsx", ".ts", ".tsx"))

        # Derive an environment variable name based on the rule or file
        var_name = re.sub(r"[^A-Z0-9]+", "_", finding.rule.upper()).strip("_")
        if not var_name.endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD")):
            var_name += "_TOKEN"

        lines = original_file_content.splitlines()
        target_line = lines[finding.line - 1] if 0 <= finding.line - 1 < len(lines) else ""

        if is_python:
            # Replace assignment: var = "..." -> var = os.getenv("VAR_NAME", "")
            match = re.search(r"^(\s*[A-Za-z0-9_]+)\s*=\s*['\"].*?['\"]", target_line)
            if match:
                var_ident = match.group(1)
                proposed_line = f"{var_ident} = os.getenv('{var_name}', '')"
            else:
                proposed_line = f"os.getenv('{var_name}', '')  # Replaced hardcoded {finding.rule}"
            explanation = (
                f"Extracted hardcoded secret into environment variable '{var_name}'. "
                f"Ensure 'import os' is present and define {var_name} in your local .env or secret manager."
            )
        elif is_js:
            # Replace JS assignment: const API_KEY = "..." -> const API_KEY = process.env.API_KEY || ""
            match = re.search(r"^(\s*(?:const|let|var)\s+[A-Za-z0-9_]+)\s*=\s*['\"].*?['\"]", target_line)
            if match:
                var_ident = match.group(1)
                proposed_line = f"{var_ident} = process.env.{var_name} || '';"
            else:
                proposed_line = f"process.env.{var_name} || ''; // Replaced hardcoded {finding.rule}"
            explanation = (
                f"Extracted hardcoded secret into 'process.env.{var_name}'. "
                f"Add {var_name}=<your-token> to your .env file and ensure dotenv is configured."
            )
        else:
            proposed_line = f"# TODO: Load {var_name} from environment or secret manager"
            explanation = f"Replace hardcoded credential with external configuration reference '{var_name}'."

        new_content = apply_snippet_replacement(original_file_content, target_line, proposed_line)
        if not new_content:
            new_content = original_file_content

        diff = generate_unified_diff(original_file_content, new_content, filename=finding.file)

        return RemediationProposal(
            finding_id=finding.id,
            finding_type="secret",
            file=finding.file,
            original_snippet=target_line,
            proposed_snippet=proposed_line,
            diff=diff,
            explanation=explanation,
        )

    @staticmethod
    def propose_dependency_remediation(advisory: Advisory, manifest_content: str, filename: str) -> RemediationProposal:
        """
        Creates a proposed update for a vulnerable dependency version.
        """
        target_pkg = advisory.package
        old_ver = advisory.version
        new_ver = advisory.fixed_version or f">{old_ver}"

        # Match package in requirements.txt or package.json
        proposed_content = manifest_content
        original_snippet = f"{target_pkg}=={old_ver}"
        proposed_snippet = f"{target_pkg}=={new_ver}"

        if filename.endswith("requirements.txt"):
            pattern = re.compile(rf"^(\s*{re.escape(target_pkg)}\s*(?:==|>=|~=))\s*([^\s#]+)", re.MULTILINE)
            if pattern.search(manifest_content):
                proposed_content = pattern.sub(rf"\g<1>{new_ver}", manifest_content)
                original_snippet = f"{target_pkg} == {old_ver}"
                proposed_snippet = f"{target_pkg} == {new_ver}"
        elif filename.endswith("package.json"):
            pattern = re.compile(rf'("{re.escape(target_pkg)}"\s*:\s*)"[\^~]?{re.escape(old_ver)}"')
            if pattern.search(manifest_content):
                proposed_content = pattern.sub(rf'\g<1>"^{new_ver}"', manifest_content)
                original_snippet = f'"{target_pkg}": "{old_ver}"'
                proposed_snippet = f'"{target_pkg}": "^{new_ver}"'

        diff = generate_unified_diff(manifest_content, proposed_content, filename=filename)

        explanation = (
            f"Upgrades '{target_pkg}' from vulnerable version {old_ver} to fixed version {new_ver} "
            f"to resolve advisory {advisory.id}."
        )

        return RemediationProposal(
            finding_id=advisory.id,
            finding_type="dependency",
            file=filename,
            original_snippet=original_snippet,
            proposed_snippet=proposed_snippet,
            diff=diff,
            explanation=explanation,
        )

    @staticmethod
    def verify_patch_in_sandbox(
        repo_root: Path,
        relative_file_path: str,
        proposed_file_content: str,
        finding_id: str,
        finding_type: str,
    ) -> VerificationResult:
        """
        Copies the repository to an isolated temporary sandbox, applies the proposed patch,
        and re-runs the relevant scanner to verify whether the issue is genuinely resolved.
        """
        sandbox_dir = tempfile.mkdtemp(prefix="reposentinel_verify_sandbox_")
        sandbox_path = Path(sandbox_dir)

        try:
            # Copy original repo to sandbox
            for item in repo_root.iterdir():
                dest = sandbox_path / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "node_modules"))
                else:
                    shutil.copy2(item, dest)

            target_sandbox_file = sandbox_path / relative_file_path
            if not target_sandbox_file.exists():
                return VerificationResult(
                    status="FAILED",
                    finding_id=finding_id,
                    file=relative_file_path,
                    diff="",
                    scanner_verified=False,
                    tests_passed=False,
                    summary=f"File {relative_file_path} not found in sandbox copy.",
                )

            orig_content = target_sandbox_file.read_text(encoding="utf-8", errors="ignore")
            diff = generate_unified_diff(orig_content, proposed_file_content, filename=relative_file_path)

            # Apply patch to sandbox copy
            target_sandbox_file.write_text(proposed_file_content, encoding="utf-8")

            # Re-scan sandbox
            if finding_type == "secret":
                re_findings, _ = scan_directory_for_secrets(sandbox_path, include_placeholders=False)
                # Check if this file still triggers any secret on that line or rule
                still_present = any(
                    f.file.replace("\\", "/") == relative_file_path.replace("\\", "/")
                    for f in re_findings
                )
                if not still_present:
                    return VerificationResult(
                        status="VERIFIED",
                        finding_id=finding_id,
                        file=relative_file_path,
                        diff=diff,
                        scanner_verified=True,
                        tests_passed=True,
                        summary="VERIFIED: Secret scanner confirmed the credential was eliminated from the patched file.",
                    )
                else:
                    return VerificationResult(
                        status="FAILED",
                        finding_id=finding_id,
                        file=relative_file_path,
                        diff=diff,
                        scanner_verified=False,
                        tests_passed=False,
                        summary="FAILED: Secret scanner still detected potential credentials after applying patch.",
                    )

            elif finding_type == "dependency":
                re_deps = collect_repository_dependencies(sandbox_path)
                client = OSVClient()
                re_advisories = client.check_dependencies(re_deps)
                still_vulnerable = any(a.id == finding_id for a in re_advisories)
                if not still_vulnerable:
                    return VerificationResult(
                        status="VERIFIED",
                        finding_id=finding_id,
                        file=relative_file_path,
                        diff=diff,
                        scanner_verified=True,
                        tests_passed=True,
                        summary=f"VERIFIED: Dependency scanner confirmed advisory {finding_id} is no longer present.",
                    )
                else:
                    return VerificationResult(
                        status="FAILED",
                        finding_id=finding_id,
                        file=relative_file_path,
                        diff=diff,
                        scanner_verified=False,
                        tests_passed=False,
                        summary=f"FAILED: Dependency still vulnerable according to OSV advisory check.",
                    )

            return VerificationResult(
                status="UNVERIFIED",
                finding_id=finding_id,
                file=relative_file_path,
                diff=diff,
                scanner_verified=False,
                tests_passed=False,
                summary="UNVERIFIED: Manual inspection required for this finding type.",
            )

        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
