"""
RepoSentinel AI - Evidence-First Repository Security & Edge-Case Testing
Bright, modern cybersecurity SaaS dashboard for Hacktoberfest 2026.
"""

import io
import json
import os
import shutil
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import streamlit as st

from reposentinel.core.config import (
    APP_NAME,
    VERSION,
    DESCRIPTION,
    DEFAULT_MODEL,
    OLLAMA_URL,
)
from reposentinel.core.models import (
    SecretFinding,
    Dependency,
    Advisory,
    ScanReport,
    VerificationResult,
)
from reposentinel.core.archive import extract_archive_safely, ArchiveSecurityError
from reposentinel.scanners.secrets import scan_directory_for_secrets
from reposentinel.scanners.dependencies import collect_repository_dependencies
from reposentinel.scanners.osv_client import OSVClient
from reposentinel.ai.ollama_client import OllamaClient
from reposentinel.ai.prompts import build_triage_prompt
from reposentinel.ai.schemas import validate_triage_json
from reposentinel.ai.fallbacks import generate_deterministic_triage
from reposentinel.testing.generator import TestGenerator
from reposentinel.testing.validator import validate_test_code_ast
from reposentinel.testing.runner import IsolatedTestRunner
from reposentinel.remediation.engine import RemediationEngine
from reposentinel.export.json_exporter import export_report_to_json
from reposentinel.export.markdown_exporter import export_report_to_markdown
from reposentinel.export.sarif_exporter import export_report_to_sarif

# UI Design System & Components
from reposentinel.ui.styles import CUSTOM_CSS
from reposentinel.ui.components import (
    render_header,
    render_metric_card,
    render_empty_state,
    get_severity_badge_html,
    get_type_badge_html,
    get_verification_badge_html,
)

# --- STREAMLIT PAGE CONFIGURATION ---
st.set_page_config(
    page_title=f"{APP_NAME} — Evidence-First Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject Clean Bright SaaS Design System
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# --- SESSION STATE INITIALIZATION ---
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Overview"
if "scan_report" not in st.session_state:
    st.session_state["scan_report"] = None
if "active_repo_path" not in st.session_state:
    st.session_state["active_repo_path"] = None
if "temp_cleanup_dir" not in st.session_state:
    st.session_state["temp_cleanup_dir"] = None
if "selected_finding_for_remediation" not in st.session_state:
    st.session_state["selected_finding_for_remediation"] = None
if "generated_tests" not in st.session_state:
    st.session_state["generated_tests"] = None
if "test_execution_result" not in st.session_state:
    st.session_state["test_execution_result"] = None
if "verification_results" not in st.session_state:
    st.session_state["verification_results"] = []
if "selected_model" not in st.session_state:
    st.session_state["selected_model"] = DEFAULT_MODEL


# --- SERVICES & CLIENTS ---
ollama_client = OllamaClient()
osv_client = OSVClient()
test_generator = TestGenerator(ollama_client=ollama_client)
test_runner = IsolatedTestRunner()

# Check local Ollama health
is_ollama_connected, ollama_msg = ollama_client.check_connection()
available_models = ollama_client.list_models() if is_ollama_connected else []


# --- HELPER: EXECUTE SCAN ---
def execute_scan(target_path: Path, project_name: str):
    """Executes deterministic secret scan, dependency collection, and OSV queries."""
    with st.spinner("Analyzing repository files and checking OSV advisories..."):
        sec_findings, scanned_count = scan_directory_for_secrets(target_path)
        deps = collect_repository_dependencies(target_path)
        advisories = osv_client.check_dependencies(deps)
        triage = generate_deterministic_triage(sec_findings, advisories)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        report = ScanReport(
            project_name=project_name,
            files_scanned=scanned_count,
            secret_findings=sec_findings,
            dependency_advisories=advisories,
            dependencies_parsed=deps,
            ai_triage=triage.raw_markdown,
            timestamp=timestamp,
        )
        st.session_state["scan_report"] = report
        st.session_state["active_repo_path"] = target_path
        st.session_state["verification_results"] = []


# --- SIDEBAR NAVIGATION (Deep Navy Workspace Sidebar) ---
with st.sidebar:
    sidebar_header_html = (
        '<div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:1.25rem; padding-bottom:0.75rem; border-bottom:1px solid #1E2D4A;">'
        '<span style="font-size:1.6rem; line-height:1;">🛡️</span>'
        '<div>'
        '<div style="font-weight:700; color:#FFFFFF; font-size:1.1rem; line-height:1.2;">RepoSentinel AI</div>'
        '<div style="font-size:0.75rem; color:#94A3B8;">Evidence-first security</div>'
        '</div></div>'
    )
    st.markdown(sidebar_header_html, unsafe_allow_html=True)

    # Navigation Menu
    NAV_ITEMS = [
        "Overview",
        "Scan Repository",
        "Findings",
        "AI Analysis",
        "Test Lab",
        "Remediation",
        "Reports",
        "Learn & Architecture",
    ]

    if st.session_state["current_page"] not in NAV_ITEMS:
        st.session_state["current_page"] = "Overview"

    selected_nav = st.radio(
        "Navigation",
        NAV_ITEMS,
        index=NAV_ITEMS.index(st.session_state["current_page"]),
        label_visibility="collapsed",
    )
    if selected_nav != st.session_state["current_page"]:
        st.session_state["current_page"] = selected_nav
        st.rerun()

    st.markdown("<div style='margin-top:2rem;'></div>", unsafe_allow_html=True)

    # Quick Action: Load Sample Project
    st.caption("DEMO WORKSPACE")
    if st.button("Load Sample Project", use_container_width=True, type="secondary"):
        sample_path = Path(__file__).resolve().parent / "sample_project"
        if sample_path.exists():
            execute_scan(sample_path, "sample_project (Demo)")
            st.session_state["current_page"] = "Overview"
            st.rerun()

    st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)

    # Settings / Local AI Config
    with st.expander("Configuration", expanded=False):
        if available_models:
            curr_sel = st.session_state.get("selected_model", DEFAULT_MODEL)
            idx = 0
            for i, m in enumerate(available_models):
                if curr_sel.lower() in m.lower() or m.lower() in curr_sel.lower():
                    idx = i
                    break
            model_choice = st.selectbox(
                "Installed Models",
                options=available_models,
                index=idx,
                help="Select from currently pulled Ollama models",
            )
            st.session_state["selected_model"] = model_choice
        else:
            model_input = st.text_input(
                "Target Model",
                value=st.session_state.get("selected_model", DEFAULT_MODEL),
                help="Ollama open-weight model name (default: qwen2.5-coder:7b)",
            )
            st.session_state["selected_model"] = model_input.strip()

        st.caption(f"Endpoint: `{OLLAMA_URL}`")
        if is_ollama_connected:
            st.caption(f"Available models: {len(available_models)}")
        else:
            st.caption("Ollama offline — deterministic fallback is active.")


# Render Global SaaS Header Bar
render_header(
    ollama_connected=is_ollama_connected,
    available_models=available_models,
    selected_model=st.session_state.get("selected_model", DEFAULT_MODEL),
    version=VERSION,
)


# ==============================================================================
# PAGE 1: OVERVIEW DASHBOARD
# ==============================================================================
def render_overview_page():
    report: Optional[ScanReport] = st.session_state.get("scan_report")

    # Welcome Section
    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Repository Security Overview</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0 0 1rem 0;">'
        'Detect exposed secrets, investigate vulnerable dependencies, test edge cases, and verify proposed fixes.'
        '</p></div>',
        unsafe_allow_html=True
    )

    # Action Buttons Row
    col_act1, col_act2, col_spacer = st.columns([1.6, 1.8, 3.5])
    with col_act1:
        if st.button("Scan Repository", type="primary", use_container_width=True):
            st.session_state["current_page"] = "Scan Repository"
            st.rerun()
    with col_act2:
        if st.button("Load Sample Project", type="secondary", use_container_width=True):
            sample_path = Path(__file__).resolve().parent / "sample_project"
            if sample_path.exists():
                execute_scan(sample_path, "sample_project (Demo)")
                st.rerun()

    st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)

    # Metric Cards Row
    if report:
        crit_count = sum(1 for s in report.secret_findings if s.severity == "Critical") + sum(1 for a in report.dependency_advisories if a.severity == "Critical")
        high_count = sum(1 for s in report.secret_findings if s.severity == "High") + sum(1 for a in report.dependency_advisories if a.severity == "High")
        vuln_count = len(report.dependency_advisories)
        files_count = report.files_scanned

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_metric_card("Critical Findings", crit_count, "Requires immediate attention", variant="critical" if crit_count > 0 else "default")
        with m2:
            render_metric_card("High Findings", high_count, "High risk security issues", variant="warning" if high_count > 0 else "default")
        with m3:
            render_metric_card("OSV Vulnerabilities", vuln_count, "Matched public advisories", variant="info" if vuln_count > 0 else "default")
        with m4:
            render_metric_card("Files Scanned", files_count, f"{len(report.dependencies_parsed)} dependencies parsed", variant="default")

        st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)

        # Recent Scan Panel & Priority Findings
        col_panel_left, col_panel_right = st.columns([1.3, 2.2])

        with col_panel_left:
            st.markdown(
                '<div class="rs-card" style="height:100%;">'
                '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.75rem;">📋 Recent Scan Details</div>'
                f'<p style="margin:0 0 0.35rem 0; font-size:0.88rem; color:#18263D;"><strong>Target:</strong> <code>{report.project_name}</code></p>'
                f'<p style="margin:0 0 0.35rem 0; font-size:0.88rem; color:#18263D;"><strong>Audited:</strong> {report.timestamp or "Just now"}</p>'
                '<p style="margin:0 0 0.35rem 0; font-size:0.88rem; color:#18263D;"><strong>Status:</strong> <span class="rs-pill rs-pill-success" style="padding:0.15rem 0.5rem; font-size:0.75rem;">Completed</span></p>'
                f'<p style="margin:0 0 0.35rem 0; font-size:0.88rem; color:#18263D;"><strong>Files Scanned:</strong> {report.files_scanned}</p>'
                f'<p style="margin:0 0 0.35rem 0; font-size:0.88rem; color:#18263D;"><strong>Secrets Found:</strong> {len(report.secret_findings)}</p>'
                f'<p style="margin:0 0 0.85rem 0; font-size:0.88rem; color:#18263D;"><strong>Advisories:</strong> {len(report.dependency_advisories)}</p>'
                '</div>',
                unsafe_allow_html=True
            )
            if st.button("Review All Findings →", use_container_width=True, type="secondary"):
                st.session_state["current_page"] = "Findings"
                st.rerun()

        with col_panel_right:
            st.markdown(
                '<div class="rs-card">'
                '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.75rem;">⚡ Priority Findings</div>',
                unsafe_allow_html=True
            )

            priority_items = []
            for s in report.secret_findings:
                if s.severity in ("Critical", "High"):
                    priority_items.append(("secret", s))
            for a in report.dependency_advisories:
                if a.severity in ("Critical", "High"):
                    priority_items.append(("dependency", a))

            if not priority_items:
                st.markdown(
                    '<p style="color:#64748B; font-size:0.88rem; padding:0.5rem 0;">✓ No critical or high-severity findings detected.</p>',
                    unsafe_allow_html=True
                )
            else:
                for p_type, item in priority_items[:4]:
                    sev_badge = get_severity_badge_html(item.severity)
                    type_badge = get_type_badge_html("Secret" if p_type == "secret" else "Dependency")
                    title = item.rule if p_type == "secret" else f"{item.package} ({item.version}) — {item.id}"
                    loc = f"{item.file}:{item.line}" if p_type == "secret" else (item.source or "package.json")

                    row_html = (
                        '<div class="rs-row">'
                        f'<div style="display:flex; align-items:center; gap:0.65rem; flex-wrap:wrap;">'
                        f'{sev_badge} {type_badge}'
                        f'<span style="font-weight:600; color:#18263D; font-size:0.88rem;">{title}</span>'
                        f'<span style="color:#64748B; font-size:0.8rem; font-family:monospace;">{loc}</span>'
                        '</div></div>'
                    )
                    st.markdown(row_html, unsafe_allow_html=True)

                if st.button("Inspect All Findings in Detail →", key="btn_inspect_detail", use_container_width=True):
                    st.session_state["current_page"] = "Findings"
                    st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

    else:
        # Empty State when no scan has been run
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_metric_card("Critical Findings", "—", "Awaiting scan", variant="default")
        with m2:
            render_metric_card("High Findings", "—", "Awaiting scan", variant="default")
        with m3:
            render_metric_card("OSV Vulnerabilities", "—", "Awaiting scan", variant="default")
        with m4:
            render_metric_card("Files Scanned", "—", "Awaiting scan", variant="default")

        render_empty_state(
            icon="🛡️",
            title="No Repository Scanned Yet",
            description="Upload a project ZIP snapshot or provide a local directory path to discover hardcoded secrets, trace OSV vulnerabilities, and verify fixes in an isolated sandbox.",
        )


# ==============================================================================
# PAGE 2: SCAN REPOSITORY (Clear 4-Step Sequence)
# ==============================================================================
def render_scan_page():
    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Scan a Repository</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Follow the 4-step sequence below to perform an evidence-first security scan.'
        '</p></div>',
        unsafe_allow_html=True
    )

    # Step 1: Choose Source
    st.markdown(
        '<div class="rs-card">'
        '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
        '<span class="rs-step-badge">1</span>'
        '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Choose your source</span>'
        '</div>'
        '<p style="font-size:0.85rem; color:#64748B; margin:0 0 0.75rem 0;">'
        'Upload a project archive ZIP, specify a local repository directory path, or load the built-in sample project.'
        '</p>',
        unsafe_allow_html=True
    )

    source_type = st.radio(
        "Source Type",
        ["Upload ZIP Archive", "Local Directory Path", "Built-in Sample Project"],
        horizontal=True,
        label_visibility="collapsed",
    )

    uploaded_zip = None
    local_dir_path = ""

    if source_type == "Upload ZIP Archive":
        uploaded_zip = st.file_uploader(
            "Upload Project ZIP Archive",
            type=["zip"],
            help="Archives are checked for Zip-Slip path traversal and extracted into an isolated temporary folder.",
        )
        st.caption("Supported: ZIP files up to 50MB. node_modules, .git, and .venv are automatically skipped.")

    elif source_type == "Local Directory Path":
        local_dir_path = st.text_input(
            "Local Directory Path",
            value="",
            placeholder="e.g. /path/to/project or C:/Projects/my-app",
            help="Path to an existing project directory on your local machine.",
        )
        st.caption("RepoSentinel will read text files and manifests directly on your filesystem.")

    else:
        st.info("The built-in sample project includes authentic dependency manifests (`requirements.txt`, `package.json`), sample Python functions with edge-case bugs, and synthetic credential fixtures.")

    st.markdown("</div>", unsafe_allow_html=True)

    # Step 2: Review Target
    st.markdown(
        '<div class="rs-card">'
        '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
        '<span class="rs-step-badge">2</span>'
        '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Review target details</span>'
        '</div>',
        unsafe_allow_html=True
    )

    is_ready = False
    if source_type == "Upload ZIP Archive":
        if uploaded_zip:
            size_kb = len(uploaded_zip.getvalue()) / 1024
            st.write(f"✓ **File selected:** `{uploaded_zip.name}` ({size_kb:.1f} KB)")
            is_ready = True
        else:
            st.write("○ Please choose a ZIP file in Step 1.")

    elif source_type == "Local Directory Path":
        if local_dir_path.strip():
            candidate = Path(local_dir_path.strip())
            if candidate.exists() and candidate.is_dir():
                st.write(f"✓ **Directory found:** `{candidate.resolve()}`")
                is_ready = True
            else:
                st.warning("⚠️ Specified directory path does not exist or is not a folder.")
        else:
            st.write("○ Enter a valid folder path in Step 1.")

    else:
        sample_path = Path(__file__).resolve().parent / "sample_project"
        if sample_path.exists():
            st.write(f"✓ **Target:** `sample_project` ({sample_path.resolve()})")
            is_ready = True
        else:
            st.error("Sample project folder is missing from the repository root.")

    st.markdown("</div>", unsafe_allow_html=True)

    # Step 3: Run the Scan
    st.markdown(
        '<div class="rs-card">'
        '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
        '<span class="rs-step-badge">3</span>'
        '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Execute security scan</span>'
        '</div>'
        '<p style="font-size:0.85rem; color:#64748B; margin:0 0 0.75rem 0;">'
        'Runs heuristic secret scanning, extracts dependency manifests, queries the public OSV database, and prepares deterministic evidence.'
        '</p>',
        unsafe_allow_html=True
    )

    scan_button = st.button(
        "Run security scan",
        type="primary",
        disabled=not is_ready,
        use_container_width=True,
    )

    if scan_button and is_ready:
        if source_type == "Upload ZIP Archive" and uploaded_zip:
            try:
                target_path, temp_dir = extract_archive_safely(uploaded_zip.getvalue())
                st.session_state["temp_cleanup_dir"] = temp_dir
                execute_scan(target_path, uploaded_zip.name)
                st.success("Scan completed successfully!")
            except ArchiveSecurityError as exc:
                st.error(f"Archive security check failed: {exc}")
            except Exception as exc:
                st.error(f"Failed to scan archive: {exc}")

        elif source_type == "Local Directory Path":
            target_path = Path(local_dir_path.strip())
            execute_scan(target_path, target_path.name)
            st.success("Scan completed successfully!")

        else:
            sample_path = Path(__file__).resolve().parent / "sample_project"
            execute_scan(sample_path, "sample_project")
            st.success("Scan completed successfully!")

    st.markdown("</div>", unsafe_allow_html=True)

    # Step 4: Review Results
    report = st.session_state.get("scan_report")
    if report:
        st.markdown(
            '<div class="rs-card">'
            '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
            '<span class="rs-step-badge">4</span>'
            '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Review scan results</span>'
            '</div>',
            unsafe_allow_html=True
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Files Scanned", report.files_scanned)
        c2.metric("Secrets Detected", len(report.secret_findings))
        c3.metric("OSV Advisories", len(report.dependency_advisories))
        c4.metric("Dependencies", len(report.dependencies_parsed))

        st.markdown("<div style='margin-top:0.75rem;'></div>", unsafe_allow_html=True)
        if st.button("Review findings →", type="primary", use_container_width=True):
            st.session_state["current_page"] = "Findings"
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# PAGE 3: UNIFIED FINDINGS EXPERIENCE
# ==============================================================================
def render_findings_page():
    report: Optional[ScanReport] = st.session_state.get("scan_report")

    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Security Findings</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Unified repository findings across detected secrets and vulnerable dependencies. All credentials are redacted.'
        '</p></div>',
        unsafe_allow_html=True
    )

    if not report:
        render_empty_state(
            icon="🔍",
            title="No Findings Available",
            description="Run a repository scan first to inspect detected secrets and package vulnerability advisories.",
        )
        if st.button("Go to Scan Repository", type="primary"):
            st.session_state["current_page"] = "Scan Repository"
            st.rerun()
        return

    # Build Unified Finding Items
    unified_items = []
    for s in report.secret_findings:
        unified_items.append({
            "type": "Secret",
            "id": s.id,
            "title": s.rule,
            "severity": s.severity,
            "location": f"{s.file}:{s.line}",
            "file": s.file,
            "obj": s,
        })
    for a in report.dependency_advisories:
        unified_items.append({
            "type": "Dependency",
            "id": a.id,
            "title": f"{a.package} ({a.version})",
            "severity": a.severity,
            "location": f"{a.package} @ {a.version} in {a.source or 'manifest'}",
            "file": a.source or "package.json",
            "obj": a,
        })

    # Search and Filter Toolbar
    f_col1, f_col2, f_col3 = st.columns([2.5, 1.2, 1.2])
    with f_col1:
        search_query = st.text_input(
            "Search findings",
            value="",
            placeholder="Search by rule, package, file path, or advisory ID...",
            label_visibility="collapsed",
        )
    with f_col2:
        filter_sev = st.selectbox(
            "Severity",
            ["All Severities", "Critical", "High", "Medium", "Low"],
            label_visibility="collapsed",
        )
    with f_col3:
        filter_type = st.selectbox(
            "Finding Type",
            ["All Types", "Secret", "Dependency"],
            label_visibility="collapsed",
        )

    # Apply Filters
    filtered = unified_items
    if search_query.strip():
        q = search_query.strip().lower()
        filtered = [
            x for x in filtered
            if q in x["title"].lower() or q in x["id"].lower() or q in x["location"].lower()
        ]
    if filter_sev != "All Severities":
        filtered = [x for x in filtered if x["severity"].lower() == filter_sev.lower()]
    if filter_type != "All Types":
        filtered = [x for x in filtered if x["type"].lower() == filter_type.lower()]

    # Sort items: Critical first
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    filtered.sort(key=lambda x: sev_rank.get(x["severity"].lower(), 5))

    st.markdown(f"<div style='font-size:0.85rem; color:#64748B; margin:0.35rem 0 0.85rem 0;'>Showing <strong>{len(filtered)}</strong> of {len(unified_items)} total findings</div>", unsafe_allow_html=True)

    if not filtered:
        render_empty_state("✓", "No Matching Findings", "No findings match the active search and filter criteria.")
        return

    # Render Compact Finding Rows with Details
    for idx, item in enumerate(filtered):
        sev_badge = get_severity_badge_html(item["severity"])
        type_badge = get_type_badge_html(item["type"])
        title = item["title"]
        loc = item["location"]

        with st.expander(f"[{item['severity'].upper()}] {title} — {loc}", expanded=(idx < 2)):
            col_detail, col_action = st.columns([3, 1])

            with col_detail:
                if item["type"] == "Secret":
                    sec: SecretFinding = item["obj"]
                    st.markdown(f"**Rule:** `{sec.rule}` &nbsp;|&nbsp; **Severity:** `{sec.severity}`")
                    st.markdown(f"**Location:** `{sec.file}:{sec.line}`")
                    st.markdown(f"**Evidence (Redacted):** `{sec.evidence}`")
                    st.markdown(f"**Recommendation:** {sec.recommendation}")
                else:
                    adv: Advisory = item["obj"]
                    st.markdown(f"**Package:** `{adv.package}` @ `{adv.version}` ({adv.ecosystem})")
                    st.markdown(f"**Advisory ID:** `{adv.id}`" + (f" (Aliases: {', '.join(adv.aliases[:3])})" if adv.aliases else ""))
                    if adv.cvss_score:
                        st.markdown(f"**CVSS Score:** `{adv.cvss_score}`")
                    st.markdown(f"**Fixed in Version:** " + (f"`{adv.fixed_version}`" if adv.fixed_version else "*No direct fix reported in advisory*"))
                    st.markdown(f"**Summary:** {adv.summary}")
                    st.markdown(f"[View Verified Advisory Record on OSV.dev ↗]({adv.url})")

            with col_action:
                st.markdown("<div style='margin-top:0.25rem;'></div>", unsafe_allow_html=True)
                if st.button("Remediate in Sandbox", key=f"rem_btn_{item['id']}_{idx}", use_container_width=True, type="secondary"):
                    st.session_state["selected_finding_for_remediation"] = item["obj"]
                    st.session_state["current_page"] = "Remediation"
                    st.rerun()


# ==============================================================================
# PAGE 4: AI ANALYSIS
# ==============================================================================
def render_ai_analysis_page():
    report: Optional[ScanReport] = st.session_state.get("scan_report")

    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">AI Security Analysis</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Prioritized explanation of scanner evidence. Inputs are strictly quarantined to defend against prompt injection.'
        '</p></div>',
        unsafe_allow_html=True
    )

    if not report:
        render_empty_state("🤖", "No Analysis Available", "Run a repository scan first to generate security triage.")
        return

    # Model status callout
    col_st1, col_st2 = st.columns([3, 1])
    with col_st1:
        if is_ollama_connected:
            st.markdown(
                '<div style="padding:0.75rem 1rem; background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; font-size:0.85rem; color:#18263D;">'
                '✓ <strong>Ollama is active locally.</strong> Scanned excerpts are pre-redacted and quarantined with <code>&lt;UNTRUSTED_SCANNER_EVIDENCE&gt;</code> boundaries.'
                '</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div style="padding:0.75rem 1rem; background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; font-size:0.85rem; color:#B45309;">'
                '○ <strong>Ollama is offline.</strong> RepoSentinel\'s deterministic fallback engine is active. Start Ollama (<code>ollama serve</code>) for local LLM inference.'
                '</div>',
                unsafe_allow_html=True
            )

    with col_st2:
        use_ollama = st.checkbox("Use Local LLM", value=is_ollama_connected, disabled=not is_ollama_connected)

    if st.button("Generate Security Triage Analysis", type="primary"):
        sec = report.secret_findings
        vulns = report.dependency_advisories

        active_model = st.session_state.get("selected_model", DEFAULT_MODEL)
        if use_ollama and is_ollama_connected:
            with st.spinner(f"Requesting triage analysis from local {active_model}..."):
                prompt = build_triage_prompt([s.to_dict() for s in sec], [v.to_dict() for v in vulns])
                raw_resp, err = ollama_client.generate(prompt=prompt, model=active_model, format_json=True)
                if not err and raw_resp:
                    triage_resp, val_err = validate_triage_json(raw_resp)
                    if triage_resp:
                        report.ai_triage = triage_resp.raw_markdown
                        st.success(f"Triage generated via local open-weight model ({active_model}).")
                    else:
                        report.ai_triage = raw_resp
                        st.success(f"Triage returned from {active_model} (raw format).")
                else:
                    st.warning(f"Ollama inference error: {err}. Activated deterministic rule fallback.")
                    triage_resp = generate_deterministic_triage(sec, vulns)
                    report.ai_triage = triage_resp.raw_markdown
        else:
            with st.spinner("Generating deterministic heuristic triage..."):
                triage_resp = generate_deterministic_triage(sec, vulns)
                report.ai_triage = triage_resp.raw_markdown
                st.success("Deterministic triage computed successfully.")

    if report.ai_triage:
        st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)
        st.markdown(
            '<div class="rs-card">'
            '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.75rem;">🛡️ Prioritized Risk Assessment & Next Steps</div>',
            unsafe_allow_html=True
        )
        st.markdown(report.ai_triage)
        st.markdown('</div>', unsafe_allow_html=True)


# ==============================================================================
# PAGE 5: TEST LAB
# ==============================================================================
def render_test_lab_page():
    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Edge-Case Test Lab</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Synthesize pytest suites for Python functions and execute them inside an isolated temporary subprocess with strict timeouts.'
        '</p></div>',
        unsafe_allow_html=True
    )

    default_code = """def calculate_percentage(obtained, maximum):
    return (obtained / maximum) * 100"""

    # Stage 1: Input
    st.markdown(
        '<div class="rs-card">'
        '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
        '<span class="rs-step-badge">1</span>'
        '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Source function under test</span>'
        '</div>',
        unsafe_allow_html=True
    )

    c_code, c_info = st.columns([2.5, 1.5])
    with c_code:
        code_input = st.text_area("Python Source", value=default_code, height=140, label_visibility="collapsed")
        func_name = st.text_input("Function Name", value="calculate_percentage")
    with c_info:
        st.markdown(
            '<div style="font-size:0.85rem; color:#64748B; line-height:1.5;">'
            '<strong style="color:#18263D;">Execution Safeguards & Scope:</strong><br>'
            '• Pre-execution AST check blocks dangerous imports (<code>os</code>, <code>subprocess</code>, <code>socket</code>, <code>eval</code>).<br>'
            '• Process runs with stripped environment variables to safeguard host secrets.<br>'
            '• 10-second hard execution timeout limit.<br>'
            '• <em>Note: Subprocess isolation is not a hardware hypervisor jail; never run uninspected malicious binaries.</em>'
            '</div>',
            unsafe_allow_html=True
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # Stage 2: Synthesis & Validation
    col_act1, col_act2 = st.columns(2)
    with col_act1:
        gen_btn = st.button("Generate Edge-Case Tests", type="primary", use_container_width=True)
    with col_act2:
        run_btn = st.button("Run Tests in Guarded Subprocess", type="secondary", use_container_width=True)

    if gen_btn:
        active_model = st.session_state.get("selected_model", DEFAULT_MODEL)
        with st.spinner("Analyzing function structure and synthesizing boundary cases..."):
            plan = test_generator.generate_tests_for_function(
                function_name=func_name,
                source_code=code_input,
                model_name=active_model,
                force_deterministic=not is_ollama_connected,
            )
            st.session_state["generated_tests"] = plan
            st.session_state["test_execution_result"] = None

    plan = st.session_state.get("generated_tests")
    if plan:
        st.markdown(
            '<div class="rs-card">'
            '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
            '<span class="rs-step-badge">2</span>'
            '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Generated pytest test suite</span>'
            '</div>',
            unsafe_allow_html=True
        )

        st.write(f"**Identified Edge Cases for `{plan.function_name}`:**")
        for ec in plan.edge_cases_identified:
            st.write(f"• {ec}")

        # AST Validation Status
        is_safe, val_msg = validate_test_code_ast(plan.generated_code)
        if is_safe:
            st.markdown('<span class="rs-badge" style="background:#DCFCE7; color:#15803D; border:1px solid #BBF7D0;">✓ AST Static Security Validation Passed</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="rs-badge rs-badge-critical">✕ AST Security Blocked: {val_msg}</span>', unsafe_allow_html=True)

        st.code(plan.generated_code, language="python")

        st.download_button(
            "Download test suite (.py)",
            data=plan.generated_code,
            file_name=f"test_{plan.function_name}_edges.py",
            mime="text/x-python",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # Stage 3: Execution
    if run_btn:
        if not plan or not plan.generated_code:
            st.warning("Generate tests first before executing.")
        else:
            with st.spinner("Running tests in temporary subprocess with AST validation..."):
                exec_res = test_runner.run_test_code(plan.generated_code)
                st.session_state["test_execution_result"] = exec_res

    res = st.session_state.get("test_execution_result")
    if res:
        st.markdown(
            '<div class="rs-card">'
            '<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem;">'
            '<span class="rs-step-badge">3</span>'
            '<span style="font-weight:700; color:#18263D; font-size:0.95rem;">Subprocess execution outcome</span>'
            '</div>',
            unsafe_allow_html=True
        )

        status_badge = get_verification_badge_html(res.status)
        st.markdown(f"{status_badge} &nbsp; <strong>Passed:</strong> {res.passed_count} &nbsp;|&nbsp; <strong>Failed:</strong> {res.failed_count} &nbsp;|&nbsp; <strong>Duration:</strong> {res.execution_time_seconds}s", unsafe_allow_html=True)

        tab_out, tab_err = st.tabs(["Subprocess Stdout", "Subprocess Stderr"])
        with tab_out:
            st.code(res.stdout or "(Empty stdout)", language="text")
        with tab_err:
            st.code(res.stderr or "(Empty stderr)", language="text")

        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# PAGE 6: REMEDIATION WORKSPACE
# ==============================================================================
def render_remediation_page():
    report: Optional[ScanReport] = st.session_state.get("scan_report")
    active_repo: Optional[Path] = st.session_state.get("active_repo_path")

    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Verified Remediation Workspace</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Review proposed fixes, apply patches to a temporary sandbox copy, and re-run scanners to verify the issue is genuinely resolved.'
        '</p></div>',
        unsafe_allow_html=True
    )

    if not report or not active_repo:
        render_empty_state("🔧", "No Findings to Remediate", "Run a repository scan first to select findings for remediation.")
        return

    # Finding selection mapping
    finding_options = {}
    for s in report.secret_findings:
        finding_options[f"[Secret] {s.id}: {s.rule} in {s.file}:{s.line}"] = ("secret", s)
    for a in report.dependency_advisories:
        finding_options[f"[Dependency] {a.id}: {a.package} ({a.version})"] = ("dependency", a)

    if not finding_options:
        st.success("✓ No active findings requiring remediation.")
        return

    selected_label = st.selectbox(
        "Select Finding to Remediate",
        list(finding_options.keys()),
    )
    f_type, f_obj = finding_options[selected_label]

    # Target File
    target_rel_path = f_obj.file if f_type == "secret" else (f_obj.source or "requirements.txt")
    target_abs_path = active_repo / target_rel_path

    if not target_abs_path.exists():
        st.warning(f"File `{target_rel_path}` was not found in the scanned workspace.")
        return

    orig_content = target_abs_path.read_text(encoding="utf-8", errors="ignore")

    # Generate proposal
    if f_type == "secret":
        proposal = RemediationEngine.propose_secret_remediation(f_obj, orig_content)
    else:
        proposal = RemediationEngine.propose_dependency_remediation(f_obj, orig_content, target_abs_path.name)

    st.markdown(
        '<div class="rs-card">'
        '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.6rem;">📝 Proposed Change & Unified Diff</div>',
        unsafe_allow_html=True
    )

    st.write(f"**Explanation:** {proposal.explanation}")
    st.write(f"**Target File:** `{proposal.file}`")

    st.code(proposal.diff, language="diff")

    st.caption("Note: Applying the patch copies the repository into a temporary sandbox. Your live files are not modified.")

    if st.button("Apply Patch in Sandbox & Verify Resolution", type="primary"):
        with st.spinner("Testing patch in isolated sandbox copy..."):
            proposed_full_content = orig_content.replace(proposal.original_snippet, proposal.proposed_snippet)
            ver_res = RemediationEngine.verify_patch_in_sandbox(
                repo_root=active_repo,
                relative_file_path=proposal.file,
                proposed_file_content=proposed_full_content,
                finding_id=proposal.finding_id,
                finding_type=proposal.finding_type,
            )
            st.session_state["verification_results"].append(ver_res)
            report.verification_results = st.session_state["verification_results"]

            if ver_res.status == "VERIFIED":
                st.success(f"✓ {ver_res.summary}")
            else:
                st.error(f"✕ {ver_res.summary}")

    st.markdown("</div>", unsafe_allow_html=True)

    # Verification History
    if report.verification_results:
        st.markdown(
            '<div class="rs-card">'
            '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.6rem;">📋 Verification Results Log</div>',
            unsafe_allow_html=True
        )

        for vr in report.verification_results:
            badge = get_verification_badge_html(vr.status)
            st.markdown(f"{badge} &nbsp; <code>{vr.file}</code> ({vr.finding_id}) — {vr.summary}", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# PAGE 7: REPORTS & EXPORTS
# ==============================================================================
def render_reports_page():
    report: Optional[ScanReport] = st.session_state.get("scan_report")

    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Reports & Export Center</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Download audit reports in standard open-source formats for developer reviews, CI pipelines, and GitHub security tabs.'
        '</p></div>',
        unsafe_allow_html=True
    )

    if not report:
        render_empty_state("📊", "No Report Available", "Run a repository scan first to generate exportable audit reports.")
        return

    json_str = export_report_to_json(report)
    md_str = export_report_to_markdown(report)
    sarif_str = export_report_to_sarif(report)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            '<div class="rs-card" style="height:100%;">'
            '<div style="font-weight:700; color:#18263D; font-size:1rem; margin-bottom:0.4rem;">📋 JSON Audit Report</div>'
            '<p style="font-size:0.82rem; color:#64748B;">Machine-readable structured JSON format containing full finding metadata and dependency trees.</p>',
            unsafe_allow_html=True
        )
        st.download_button(
            "Download JSON report",
            data=json_str,
            file_name="reposentinel-report.json",
            mime="application/json",
            use_container_width=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown(
            '<div class="rs-card" style="height:100%;">'
            '<div style="font-weight:700; color:#18263D; font-size:1rem; margin-bottom:0.4rem;">📄 Markdown Summary</div>'
            '<p style="font-size:0.82rem; color:#64748B;">Formatted GitHub-Flavored Markdown report suitable for pull request summaries and documentation.</p>',
            unsafe_allow_html=True
        )
        st.download_button(
            "Download Markdown report",
            data=md_str,
            file_name="reposentinel-report.md",
            mime="text/markdown",
            use_container_width=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        st.markdown(
            '<div class="rs-card" style="height:100%;">'
            '<div style="font-weight:700; color:#18263D; font-size:1rem; margin-bottom:0.4rem;">🛡️ OASIS SARIF v2.1.0</div>'
            '<p style="font-size:0.82rem; color:#64748B;">Standard Static Analysis Results Interchange Format directly ingestible into GitHub Code Scanning.</p>',
            unsafe_allow_html=True
        )
        st.download_button(
            "Download SARIF report",
            data=sarif_str,
            file_name="reposentinel-report.sarif",
            mime="application/json",
            use_container_width=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)

    # Markdown Preview
    st.markdown(
        '<div class="rs-card">'
        '<div style="font-weight:700; color:#18263D; font-size:1rem; margin-bottom:0.5rem;">👁️ Report Preview (Markdown)</div>',
        unsafe_allow_html=True
    )
    st.code(md_str[:1200] + "\n\n... (truncated for preview)", language="markdown")
    st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# PAGE 8: LEARN & ARCHITECTURE
# ==============================================================================
def render_learn_page():
    st.markdown(
        '<div style="margin-bottom:1.25rem;">'
        '<h3 style="font-size:1.5rem; font-weight:700; color:#18263D; margin:0 0 0.25rem 0;">Workflow & Technical Architecture</h3>'
        '<p style="font-size:0.92rem; color:#64748B; margin:0;">'
        'Understand the evidence-backed verification pipeline and defense-in-depth principles.'
        '</p></div>',
        unsafe_allow_html=True
    )

    # Workflow Steps
    st.markdown(
        '<div class="rs-card">'
        '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.6rem;">🔄 The 6-Stage Evidence-Backed Workflow</div>'
        '<div style="font-size:0.88rem; color:#18263D; line-height:1.6;">'
        '<strong>1. Ingestion:</strong> Validates archives against Zip-Slip path traversal and enforces file size boundaries.<br>'
        '<strong>2. Detection:</strong> Deterministic regex rules, Shannon entropy checks, and multi-ecosystem manifest parsing.<br>'
        '<strong>3. Advisory Query:</strong> Real-time lookups to the OSV.dev database with persistent disk caching.<br>'
        '<strong>4. Local AI Triage:</strong> Evidence is quarantined inside <code>&lt;UNTRUSTED_SCANNER_EVIDENCE&gt;</code> tags for local open-weight models.<br>'
        '<strong>5. Edge-Case Testing:</strong> AST validator inspects test code before isolated subprocess execution with a 10s timeout.<br>'
        '<strong>6. Verified Remediation:</strong> Proposed unified diffs are tested in a sandbox copy; fixes are only marked <code>VERIFIED</code> if re-scan passes.'
        '</div></div>',
        unsafe_allow_html=True
    )

    # Synthetic Demo Walkthrough
    st.markdown(
        '<div class="rs-card">'
        '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.6rem;">🎬 Synthetic Demonstration Reference</div>'
        '<p style="font-size:0.85rem; color:#64748B; margin:0 0 0.5rem 0;">Clearly labeled synthetic scenarios illustrating the full lifecycle:</p>'
        '<div style="font-size:0.85rem; color:#18263D; line-height:1.5;">'
        '• <strong>Synthetic Secret:</strong> <code>AWS_ACCESS_KEY_ID = "AKIA..."</code> in <code>src/auth.py</code> &rarr; Redacted & extracted into <code>os.getenv</code>.<br>'
        '• <strong>Matched Advisory:</strong> <code>requests==2.28.1</code> affected by <code>GHSA-72xf-g2v4-qvf3</code> (CVE-2023-32681) &rarr; Patched in <code>2.31.0</code>.<br>'
        '• <strong>Edge-Case Bug:</strong> <code>calculate_percentage(obtained, maximum)</code> &rarr; Subprocess test failed on <code>maximum=0</code>, proving unhandled zero division.'
        '</div></div>',
        unsafe_allow_html=True
    )

    # Threat Model
    st.markdown(
        '<div class="rs-card">'
        '<div style="font-weight:700; color:#18263D; font-size:1.05rem; margin-bottom:0.6rem;">🛡️ Security Guarantees & Honest Boundaries</div>'
        '<div style="font-size:0.85rem; color:#18263D; line-height:1.6;">'
        '• <strong>No Cloud Inference:</strong> Source code is never sent to third-party cloud APIs.<br>'
        '• <strong>Zero Credential Leaks:</strong> Secrets are masked by default in UI, logs, exports, and prompts.<br>'
        '• <strong>Subprocess vs Container:</strong> Test execution uses a Python subprocess with stripped environment variables and AST whitelisting, not an OS kernel container.<br>'
        '• <strong>Heuristic Disclaimers:</strong> Clean scans prove no active patterns matched, not that an application is mathematically invulnerable.'
        '</div></div>',
        unsafe_allow_html=True
    )


# ==============================================================================
# ROUTE TO CURRENT PAGE
# ==============================================================================
page = st.session_state["current_page"]

if page == "Overview":
    render_overview_page()
elif page == "Scan Repository":
    render_scan_page()
elif page == "Findings":
    render_findings_page()
elif page == "AI Analysis":
    render_ai_analysis_page()
elif page == "Test Lab":
    render_test_lab_page()
elif page == "Remediation":
    render_remediation_page()
elif page == "Reports":
    render_reports_page()
elif page == "Learn & Architecture":
    render_learn_page()
else:
    render_overview_page()
