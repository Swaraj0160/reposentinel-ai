"""Data models and schemas for RepoSentinel AI."""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class SecretFinding:
    """Represents a potentially exposed credential or token found in source code."""
    id: str
    rule: str
    severity: str  # Critical, High, Medium, Low
    file: str
    line: int
    evidence: str  # Always redacted
    recommendation: str
    is_placeholder: bool = False
    context_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Dependency:
    """Represents an application dependency from a manifest or lockfile."""
    name: str
    version: str
    ecosystem: str  # npm or PyPI
    source: str     # e.g., package.json, requirements.txt, package-lock.json
    direct: bool = True
    transitive_parents: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Advisory:
    """Represents a security vulnerability advisory from OSV."""
    id: str  # e.g., GHSA-xxxx-xxxx-xxxx or CVE-2024-xxxx
    package: str
    version: str
    ecosystem: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str = "Unknown"  # Critical, High, Medium, Low, Unknown
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    source: str = ""
    url: str = ""
    direct: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestCase:
    """Represents an edge-case test item."""
    name: str
    description: str
    category: str  # boundary, invalid_type, empty_input, overflow, special_chars, etc.
    code: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestPlan:
    """Plan for generated tests."""
    function_name: str
    module_or_file: str
    edge_cases_identified: List[str] = field(default_factory=list)
    generated_code: str = ""
    assumptions: List[str] = field(default_factory=list)
    is_validated: bool = False
    validation_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestExecutionResult:
    """Result of running tests in the isolated sandbox."""
    status: str  # "PASSED", "FAILED", "ERROR", "TIMEOUT"
    exit_code: int
    stdout: str
    stderr: str
    passed_count: int = 0
    failed_count: int = 0
    execution_time_seconds: float = 0.0
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationProposal:
    """Proposed remediation for a finding."""
    finding_id: str
    finding_type: str  # "secret" or "dependency" or "code"
    file: str
    original_snippet: str
    proposed_snippet: str
    diff: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    """Outcome of applying a proposed patch in a sandbox and re-scanning/re-testing."""
    status: str  # "VERIFIED", "FAILED", "UNVERIFIED"
    finding_id: str
    file: str
    diff: str
    scanner_verified: bool
    tests_passed: bool
    summary: str
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report summary."""
    project_name: str
    files_scanned: int
    secret_findings: List[SecretFinding] = field(default_factory=list)
    dependency_advisories: List[Advisory] = field(default_factory=list)
    dependencies_parsed: List[Dependency] = field(default_factory=list)
    ai_triage: Optional[str] = None
    verification_results: List[VerificationResult] = field(default_factory=list)
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "timestamp": self.timestamp,
            "files_scanned": self.files_scanned,
            "secret_findings": [f.to_dict() for f in self.secret_findings],
            "dependency_advisories": [a.to_dict() for a in self.dependency_advisories],
            "dependencies_parsed": [d.to_dict() for d in self.dependencies_parsed],
            "ai_triage": self.ai_triage,
            "verification_results": [v.to_dict() for v in self.verification_results],
        }
