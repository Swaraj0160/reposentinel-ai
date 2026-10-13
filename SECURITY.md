# Security Policy — RepoSentinel AI

RepoSentinel AI is an open-source security tool designed to detect vulnerabilities and exposed secrets. We take the security of our own tool and its users with the utmost seriousness.

---

## Reporting a Vulnerability

If you discover a security vulnerability within RepoSentinel AI, **please do NOT open a public GitHub issue**.

Instead, report the vulnerability responsibly by following these steps:

1. **Email:** Send details to `security@reposentinel.local` (or file a private GitHub Security Advisory).
2. **Details to Include:**
   - Detailed description of the issue (e.g., path traversal, sandbox bypass, secret leakage, or regex denial of service).
   - Minimal reproduction code or archive.
   - Operating system and Python version.
   - Potential impact assessment.
3. **Response Timeline:**
   - We will acknowledge receipt of your report within **48 hours**.
   - We will provide a status update or fix within **7 business days**.

---

## Security Architecture & In-Scope Protections

RepoSentinel AI implements defense-in-depth mechanisms designed to be safe against untrusted input:

- **Zip-Slip & Path Traversal Prevention:** Uploaded archives are strictly validated before extraction; path traversal sequences (`..`, absolute paths, symlinks outside destination) are rejected.
- **Archive Size & Memory Bounds:** File size limits (`MAX_FILE_BYTES = 1MB`) and uncompressed archive limits (`50MB`) defend against zip-bomb and denial-of-service attacks.
- **Secret Redaction:** Credential values are sanitized and masked (`safe_redact`) before being rendered in the UI, passed to local models, or exported.
- **Prompt Injection Defense:** Scanned repository contents, comments, and file contents are strictly quarantined within `<UNTRUSTED_SCANNER_EVIDENCE>` delimiters. System prompts command local models to ignore embedded instructions.
- **Test Sandbox Isolation:** Model-generated tests are validated with Python AST (blocking `os`, `sys`, `subprocess`, `socket`, `eval`, `exec`, and file writes) and executed in a dedicated, timeout-bounded subprocess with stripped environment variables.
- **Non-Destructive Remediation:** Automated fixes are evaluated on isolated sandbox copies and never modify the user's repository without explicit manual approval.

---

## Known Boundaries & Disclaimers

- RepoSentinel AI's secret scanner is **heuristic** and pattern-based. It does not replace exhaustive professional security audits or dynamic penetration testing.
- Dependency checking queries the public **OSV.dev** database. A clean report indicates no known matching public advisories, not proof that a package is free of vulnerabilities.
