# RepoSentinel AI — Technical Architecture

RepoSentinel AI is an open-source, evidence-backed developer security and edge-case testing assistant.

Its primary differentiator is connecting **detection**, **verifiable evidence**, **AI-assisted remediation**, and **sandbox test verification** into an integrated developer loop.

---

## 1. System Architecture Overview

```
                                      +------------------------+
                                      | Developer / Repository |
                                      +-----------+------------+
                                                  |
                               +------------------v-------------------+
                               |  Safe Archive Ingestion & Validation  |
                               |  (Zip-Slip / Size Guard / Sandbox)   |
                               +------------------+-------------------+
                                                  |
                    +-----------------------------+-----------------------------+
                    |                                                           |
+-------------------v-------------------+                   +-------------------v-------------------+
|      Deterministic Secret Scanner     |                   |    Multi-Format Dependency Scanner    |
| - High-precision regex rules          |                   | - npm: package.json, package-lock v1/2/3
| - Shannon entropy analysis            |                   | - PyPI: requirements.txt, pyproject,  |
| - Placeholder / fixture filtering     |                   |         poetry.lock, Pipfile.lock     |
| - Safe evidence redaction             |                   +-------------------+-------------------+
+-------------------+-------------------+                                       |
                    |                                                           v
                    |                                           +-----------------------------------+
                    |                                           |     OSV.dev Vulnerability Engine  |
                    |                                           | - In-memory & disk cache          |
                    |                                           | - CVSS severity & fix resolution  |
                    +-----------------------------+             +-------------------+---------------+
                                                  |                                 |
                               +------------------v---------------------------------v---+
                               |              Quarantined Evidence Collector            |
                               |        (Redacted credentials + verified CVE data)      |
                               +------------------+-------------------------------------+
                                                  |
                    +-----------------------------+-----------------------------+
                    |                                                           |
+-------------------v-------------------+                   +-------------------v-------------------+
|     Prompt-Guarded Local Ollama AI    |                   |    Deterministic Rule Fallback Engine |
| - Untrusted data boundary fencing     |                   | - Urgency-weighted severity scoring   |
| - qwen2.5-coder:7b open-weight model  |                   | - Static AST boundary test synthesis  |
| - Structured schema validation        |                   | - Offline-ready, zero cloud calls     |
+-------------------+-------------------+                   +-------------------+-------------------+
                    |                                                           |
                    +-----------------------------+-----------------------------+
                                                  |
                               +------------------v-------------------+
                               |      Edge-Case Test Sandbox Lab      |
                               | - AST Security Validator (Whitelists)|
                               | - Subprocess Execution (Timeouts)    |
                               | - Pytest Result & Failure Inspector  |
                               +------------------+-------------------+
                                                  |
                               +------------------v-------------------+
                               |    Verified Remediation Workflow     |
                               | - Unified Diff Generation            |
                               | - Isolated Temporary Copy Patching   |
                               | - Re-scan & Re-test Validation       |
                               | - Status: VERIFIED / FAILED          |
                               +------------------+-------------------+
                                                  |
                               +------------------v-------------------+
                               |          Multi-Format Exporter       |
                               | - Structured JSON Report             |
                               | - GitHub-Flavored Markdown           |
                               | - OASIS SARIF v2.1.0 Standard        |
                               +--------------------------------------+
```

---

## 2. Core Subsystems

### A. Safe Archive Ingestion (`reposentinel.core.archive`)
- **Zip-Slip Prevention:** Verifies all archive entry paths resolve strictly within the temporary directory. Rejects relative traversal (`..`), absolute paths, and external symlinks.
- **Resource Constraints:** Enforces `MAX_FILE_BYTES = 1MB` and `MAX_ARCHIVE_BYTES = 50MB` to prevent decompression bombs.

### B. Secret Detection Engine (`reposentinel.scanners.secrets`)
- **Deterministic Pattern Rules:** Detects AWS Access Keys, GitHub PATs, Private Keys, Slack tokens, Stripe keys, OpenAI/Anthropic keys, Google/Firebase keys, Database connection strings, and high-entropy assignments.
- **Shannon Entropy Analysis:** Measures character randomness to eliminate low-entropy strings and repetitive words.
- **Test Fixture & Placeholder Intelligence:** Distinguishes mock credentials (`example_placeholder_token_do_not_use`, `changeme`, `your_token`, `admin123`) from active credentials.
- **Safe Redaction:** Automatically scrubs secret values from evidence lines before UI presentation, exports, or AI prompts.

### C. Dependency Analysis & OSV Database (`reposentinel.scanners`)
- **Multi-Ecosystem Parsing:** Parses `package.json`, `package-lock.json` (v1, v2, and v3), `requirements.txt`, `pyproject.toml` (PEP 621 and Poetry), `poetry.lock`, and `Pipfile.lock`.
- **Direct vs. Transitive Lineage:** Distinguishes root dependencies declared by developers from transitive child dependencies introduced by packages.
- **OSV.dev Integration:** Queries the Open Source Vulnerabilities database (`https://api.osv.dev/v1/query`) with in-memory and disk LRU caching to eliminate duplicate queries and respect rate limits.
- **Verifiable Advisories:** Extracts CVE/GHSA IDs, CVSS scores, affected ranges, and patched fix versions without fabricating data.

### D. Local Open-Weight AI Integration (`reposentinel.ai`)
- **Local Inference via Ollama:** Connects to locally running open-weight models (default: `qwen2.5-coder:7b`). Never transmits source code to external paid APIs.
- **Prompt Injection Containment:** Wraps evidence in `<UNTRUSTED_SCANNER_EVIDENCE>` blocks. System prompts command the model to treat all scanned content as passive data and ignore embedded instructions.
- **Deterministic Fallback:** If Ollama is offline or the model is not pulled, RepoSentinel seamlessly activates deterministic rule-based triage and AST test generation.

### E. Edge-Case Test Lab (`reposentinel.testing`)
- **AST Static Safety Validator:** Before executing generated Python tests, code is parsed with `ast`. Blocks dangerous builtins (`eval`, `exec`, `open`, `compile`) and restricted modules (`os`, `sys`, `subprocess`, `socket`, `shutil`).
- **Subprocess Isolation:** Approved tests execute in a separate temporary directory via `subprocess.run` with a 10-second timeout and stripped environment variables.
- **Failure Discrimination:** Distinguishes pytest assertion failures (demonstrating edge-case bugs) from runtime crashes and timeouts.

### F. Verified Remediation Engine (`reposentinel.remediation`)
- **Transparent Diffs:** Generates standard unified diffs showing exact proposed changes.
- **Sandbox Copy Execution:** Copies the repository into a temporary directory and applies the patch in isolation.
- **Objective Re-Scan:** Re-runs the secret scanner, dependency parser, or test suite against the patched sandbox. Fixes are marked **VERIFIED** only if actual scanners confirm resolution. Model assertions are never taken as proof.

### G. Multi-Format Exporters (`reposentinel.export`)
- **JSON:** Fully structured JSON schema with complete metadata.
- **Markdown:** Formatted summary for PR reviews and documentation.
- **SARIF v2.1.0:** OASIS standard Static Analysis Results Interchange Format compatible with GitHub Code Scanning and CI workflows.
