"""
Reusable UI presentation components for RepoSentinel AI.
Bright Modern Security SaaS Design System (1536x1024 Reference Match).
"""

import base64
from pathlib import Path
from typing import Optional, Any, List
import streamlit as st

from reposentinel.core.models import ScanReport, SecretFinding, Advisory


def safe_html(content: str):
    """Safely renders HTML without Markdown pre-processing to prevent code block leaks."""
    if hasattr(st, "html"):
        st.html(content)
    else:
        st.markdown(content, unsafe_allow_html=True)


# ==============================================================================
# TOP APPLICATION BAR (Search + Truthful Model Status)
# ==============================================================================
def render_top_bar(
    ollama_connected: bool,
    available_models: list,
    selected_model: str,
    search_key: str = "global_search",
) -> str:
    """
    Renders the slim horizontal top bar:
    Left: Search input with placeholder 'Search findings, files, or packages...'
    Right: Truthful model status pill
    """
    col_search, col_status = st.columns([2.8, 1.2])

    with col_search:
        search_val = st.text_input(
            "Global Search",
            placeholder="Search findings, files, or packages...",
            label_visibility="collapsed",
            key=search_key,
        )

    with col_status:
        # Determine truthful model status
        if ollama_connected:
            sel_lower = selected_model.strip().lower()
            avail_lower = [m.lower() for m in available_models]
            has_model = (
                sel_lower in avail_lower
                or (":" not in sel_lower and any(m.startswith(f"{sel_lower}:") for m in avail_lower))
                or (sel_lower.endswith(":latest") and sel_lower.split(":", 1)[0] in avail_lower)
            )
            if has_model:
                pill_html = (
                    '<div style="text-align:right;">'
                    '<span class="rs-top-pill rs-pill-online">'
                    '<span class="rs-status-dot rs-dot-online"></span>'
                    f'Ollama Connected ({selected_model})'
                    '</span></div>'
                )
            else:
                pill_html = (
                    '<div style="text-align:right;">'
                    '<span class="rs-top-pill rs-pill-warning">'
                    '<span class="rs-status-dot rs-dot-warning"></span>'
                    'Model Missing (Fallback Active)'
                    '</span></div>'
                )
        else:
            pill_html = (
                '<div style="text-align:right;">'
                '<span class="rs-top-pill rs-pill-warning">'
                '<span class="rs-status-dot rs-dot-warning"></span>'
                'Ollama Offline (Fallback Active)'
                '</span></div>'
            )

        safe_html(pill_html)

    return search_val


# ==============================================================================
# HERO BANNER COMPONENT
# ==============================================================================
def render_hero_banner():
    """
    Renders the large pale-blue gradient hero banner:
    Eyebrow: REPOSITORY SECURITY
    Heading: Your repository. Understood and secured.
    Supporting text: Detect exposed secrets, investigate vulnerable dependencies...
    Buttons: Scan Repository, Load Sample Project
    Right side: Vector security illustration with floating status cards
    """
    # Load and encode SVG to base64 data URI to guarantee 0 raw XML leaks
    asset_path = Path(__file__).resolve().parent.parent.parent / "assets" / "hero_illustration.svg"
    if asset_path.exists():
        svg_content = asset_path.read_text(encoding="utf-8")
        clean_svg = "".join(l.strip() for l in svg_content.splitlines() if l.strip())
        b64 = base64.b64encode(clean_svg.encode("utf-8")).decode("utf-8")
        hero_img_html = f'<img src="data:image/svg+xml;base64,{b64}" alt="Security Architecture" style="width:100%; max-width:440px; height:auto; display:block; margin:0 auto;" />'
    else:
        hero_img_html = '<div style="height:200px; display:flex; align-items:center; justify-content:center; color:#2165F5; font-size:3rem;">🛡️</div>'

    with st.container(border=True):
        hero_cols = st.columns([1.5, 1.1])

        with hero_cols[0]:
            safe_html(
                '<div style="padding:0.25rem 0 0.4rem 0;">'
                '<div class="rs-hero-eyebrow">REPOSITORY SECURITY</div>'
                '<h1 class="rs-hero-title">Your repository. <span class="rs-hero-title-accent">Understood and secured.</span></h1>'
                '<p class="rs-hero-desc">'
                'Detect exposed secrets, investigate vulnerable dependencies, test edge cases and verify proposed fixes — all in one place.'
                '</p>'
                '</div>'
            )

            btn_c1, btn_c2, _ = st.columns([1.3, 1.6, 1.4])
            with btn_c1:
                if st.button("Scan Repository", type="primary", key="hero_btn_scan", use_container_width=True):
                    st.session_state["current_page"] = "Scan Repository"
                    st.rerun()
            with btn_c2:
                if st.button("Load Sample Project", type="secondary", key="hero_btn_sample", use_container_width=True):
                    sample_path = Path(__file__).resolve().parent.parent.parent / "sample_project"
                    if sample_path.exists():
                        from app import execute_scan
                        execute_scan(sample_path, "sample_project (Demo)")
                        st.rerun()

        with hero_cols[1]:
            safe_html(
                f'<div style="display:flex; justify-content:center; align-items:center; height:100%; padding:0.25rem;">{hero_img_html}</div>'
            )


# ==============================================================================
# DASHBOARD METRICS (4 TINTED CARDS)
# ==============================================================================
def render_dashboard_metrics(report: Optional[ScanReport]):
    """Renders the 4 equal-width tinted metric cards."""
    if report:
        crit_count = sum(1 for s in report.secret_findings if s.severity == "Critical") + sum(1 for a in report.dependency_advisories if a.severity == "Critical")
        high_count = sum(1 for s in report.secret_findings if s.severity == "High") + sum(1 for a in report.dependency_advisories if a.severity == "High")
        vuln_count = len(report.dependency_advisories)
        files_count = report.files_scanned
        sub_files = f"{len(report.dependencies_parsed)} dependencies parsed"
    else:
        crit_count = 0
        high_count = 0
        vuln_count = 0
        files_count = 0
        sub_files = "Repository files analyzed"

    m1, m2, m3, m4 = st.columns(4)

    # Card 1: Critical Findings (Red)
    with m1:
        c1_html = (
            '<div class="rs-metric-box critical">'
            '<div>'
            '<div class="rs-metric-header">'
            '<div class="rs-metric-icon-circle">'
            '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
            '</svg>'
            '</div>'
            '<div class="rs-metric-title">Critical Findings</div>'
            '</div>'
            f'<div class="rs-metric-num">{crit_count}</div>'
            '</div>'
            '<div class="rs-metric-caption">Requires immediate attention</div>'
            '</div>'
        )
        safe_html(c1_html)

    # Card 2: High Findings (Amber)
    with m2:
        c2_html = (
            '<div class="rs-metric-box high">'
            '<div>'
            '<div class="rs-metric-header">'
            '<div class="rs-metric-icon-circle">'
            '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
            '</svg>'
            '</div>'
            '<div class="rs-metric-title">High Findings</div>'
            '</div>'
            f'<div class="rs-metric-num">{high_count}</div>'
            '</div>'
            '<div class="rs-metric-caption">High risk security issues</div>'
            '</div>'
        )
        safe_html(c2_html)

    # Card 3: OSV Vulnerabilities (Blue)
    with m3:
        c3_html = (
            '<div class="rs-metric-box osv">'
            '<div>'
            '<div class="rs-metric-header">'
            '<div class="rs-metric-icon-circle">'
            '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="m21.12 6.4-6.05-4.06a4.95 4.95 0 0 0-5.14 0L3.88 6.4a4.8 4.8 0 0 0-2.38 4.12v7.96a4.8 4.8 0 0 0 2.38 4.12l6.05 4.06a4.95 4.95 0 0 0 5.14 0l6.05-4.06a4.8 4.8 0 0 0 2.38-4.12V10.52a4.8 4.8 0 0 0-2.38-4.12Z"/><path d="M12 22V12"/><path d="m3.3 7 8.7 5 8.7-5"/>'
            '</svg>'
            '</div>'
            '<div class="rs-metric-title">OSV Vulnerabilities</div>'
            '</div>'
            f'<div class="rs-metric-num">{vuln_count}</div>'
            '</div>'
            '<div class="rs-metric-caption">Matched public advisories</div>'
            '</div>'
        )
        safe_html(c3_html)

    # Card 4: Files Scanned (Mint)
    with m4:
        c4_html = (
            '<div class="rs-metric-box files">'
            '<div>'
            '<div class="rs-metric-header">'
            '<div class="rs-metric-icon-circle">'
            '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="m9 15 2 2 4-4"/>'
            '</svg>'
            '</div>'
            '<div class="rs-metric-title">Files Scanned</div>'
            '</div>'
            f'<div class="rs-metric-num">{files_count}</div>'
            '</div>'
            f'<div class="rs-metric-caption">{sub_files}</div>'
            '</div>'
        )
        safe_html(c4_html)


# ==============================================================================
# 3-COLUMN MAIN DASHBOARD (Scan Details, Donut Chart, Priority Findings)
# ==============================================================================
def render_donut_chart(secrets_count: int, deps_count: int):
    """Renders the SVG Donut Chart for Findings by Type."""
    total = secrets_count + deps_count
    radius = 50
    stroke = 15
    circumference = 2 * 3.14159265 * radius  # ~ 314.16

    if total == 0:
        chart_svg = (
            f'<svg width="150" height="150" viewBox="0 0 150 150" style="display:block; margin:0 auto;">'
            f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="#E2E8F0" stroke-width="{stroke}" />'
            f'<text x="75" y="73" text-anchor="middle" font-size="22" font-weight="800" fill="#10264B" font-family="-apple-system, sans-serif">0</text>'
            f'<text x="75" y="90" text-anchor="middle" font-size="9.5" font-weight="700" fill="#536B91" letter-spacing="0.08em" font-family="-apple-system, sans-serif">TOTAL</text>'
            f'</svg>'
        )
    else:
        sec_ratio = secrets_count / total
        sec_dash = sec_ratio * circumference
        dep_dash = circumference - sec_dash

        chart_svg = (
            f'<svg width="150" height="150" viewBox="0 0 150 150" style="display:block; margin:0 auto;">'
            f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="#F1F5F9" stroke-width="{stroke}" />'
            f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="#EF4444" stroke-width="{stroke}" '
            f'stroke-dasharray="{sec_dash:.2f} {circumference:.2f}" stroke-dashoffset="0" '
            f'transform="rotate(-90 75 75)" stroke-linecap="round" />'
            f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="#3B82F6" stroke-width="{stroke}" '
            f'stroke-dasharray="{dep_dash:.2f} {circumference:.2f}" stroke-dashoffset="-{sec_dash:.2f}" '
            f'transform="rotate(-90 75 75)" stroke-linecap="round" />'
            f'<text x="75" y="73" text-anchor="middle" font-size="22" font-weight="800" fill="#10264B" font-family="-apple-system, sans-serif">{total}</text>'
            f'<text x="75" y="90" text-anchor="middle" font-size="9.5" font-weight="700" fill="#536B91" letter-spacing="0.08em" font-family="-apple-system, sans-serif">TOTAL</text>'
            f'</svg>'
        )

    safe_html(
        '<div class="rs-card" style="height:100%;">'
        '<div class="rs-card-header">'
        '<div class="rs-card-title">Findings by Type</div>'
        '</div>'
        f'{chart_svg}'
        '<div style="display:flex; justify-content:center; gap:1.25rem; margin-top:0.85rem; font-size:0.83rem;">'
        '<div style="display:flex; align-items:center; gap:0.4rem;">'
        '<span style="display:inline-block; width:9px; height:9px; border-radius:50%; background:#EF4444;"></span>'
        f'<span style="color:#536B91; font-weight:500;">Secrets:</span> <strong style="color:#10264B;">{secrets_count}</strong>'
        '</div>'
        '<div style="display:flex; align-items:center; gap:0.4rem;">'
        '<span style="display:inline-block; width:9px; height:9px; border-radius:50%; background:#3B82F6;"></span>'
        f'<span style="color:#536B91; font-weight:500;">Dependencies:</span> <strong style="color:#10264B;">{deps_count}</strong>'
        '</div>'
        '</div>'
        '</div>'
    )


def render_recent_scan_panel(report: Optional[ScanReport]):
    """Renders the Left Column: Recent Scan Details with alternating rows."""
    if report:
        target_name = report.project_name
        timestamp = report.timestamp or "Just now"
        status_pill = '<span class="rs-pill rs-pill-online" style="padding:0.15rem 0.55rem; font-size:0.75rem;">Completed</span>'
        files_scanned = str(report.files_scanned)
        secrets_found = str(len(report.secret_findings))
        advisories = str(len(report.dependency_advisories))
    else:
        target_name = "None"
        timestamp = "—"
        status_pill = '<span class="rs-pill rs-pill-warning" style="padding:0.15rem 0.55rem; font-size:0.75rem;">Awaiting Scan</span>'
        files_scanned = "—"
        secrets_found = "—"
        advisories = "—"

    table_html = (
        '<div class="rs-card" style="height:100%;">'
        '<div class="rs-card-header">'
        '<div class="rs-card-title">Recent Scan Details</div>'
        f'{status_pill}'
        '</div>'
        '<div style="margin-bottom:1rem;">'
        '<div class="rs-table-row">'
        '<span class="rs-table-label">Target:</span>'
        f'<span class="rs-table-val"><code>{target_name}</code></span>'
        '</div>'
        '<div class="rs-table-row">'
        '<span class="rs-table-label">Scanned At:</span>'
        f'<span class="rs-table-val">{timestamp}</span>'
        '</div>'
        '<div class="rs-table-row">'
        '<span class="rs-table-label">Files Scanned:</span>'
        f'<span class="rs-table-val">{files_scanned}</span>'
        '</div>'
        '<div class="rs-table-row">'
        '<span class="rs-table-label">Secrets Found:</span>'
        f'<span class="rs-table-val">{secrets_found}</span>'
        '</div>'
        '<div class="rs-table-row">'
        '<span class="rs-table-label">OSV Advisories:</span>'
        f'<span class="rs-table-val">{advisories}</span>'
        '</div>'
        '</div>'
        '</div>'
    )
    safe_html(table_html)

    if st.button("View All Findings →", key="btn_view_all_findings_scan", use_container_width=True, type="secondary"):
        st.session_state["current_page"] = "Findings"
        st.rerun()


def render_priority_findings_panel(report: Optional[ScanReport]):
    """Renders the Right Column: Priority Findings with severity badges, location, explanation, chevron."""
    priority_items = []
    if report:
        for s in report.secret_findings:
            if s.severity in ("Critical", "High"):
                priority_items.append(("secret", s))
        for a in report.dependency_advisories:
            if a.severity in ("Critical", "High"):
                priority_items.append(("dependency", a))

    rows_html = ""
    if not priority_items:
        rows_html = (
            '<div style="padding:1.5rem 0.5rem; text-align:center; color:#536B91; font-size:0.88rem;">'
            '<span style="font-size:1.2rem; display:block; margin-bottom:0.35rem;">✓</span>'
            'No critical or high-severity findings detected.'
            '</div>'
        )
    else:
        for p_type, item in priority_items[:3]:
            sev_badge = get_severity_badge_html(item.severity)
            type_badge = get_type_badge_html("Secret" if p_type == "secret" else "Dependency")
            title = item.rule if p_type == "secret" else f"{item.package} ({item.version}) — {item.id}"
            loc = f"{item.file}:{item.line}" if p_type == "secret" else (item.source or "package.json")
            explanation = "Evidence detected in source code" if p_type == "secret" else (item.summary[:65] + "..." if len(item.summary) > 65 else item.summary)

            row_html = (
                '<div class="rs-priority-row">'
                '<div style="min-width:0; flex:1; margin-right:0.65rem;">'
                f'<div style="display:flex; align-items:center; gap:0.45rem; margin-bottom:0.25rem;">'
                f'{sev_badge} {type_badge}'
                f'<span style="font-weight:700; color:#10264B; font-size:0.86rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{title}</span>'
                f'</div>'
                f'<div style="font-size:0.78rem; color:#536B91; font-family:monospace; margin-bottom:0.2rem;">{loc}</div>'
                f'<div style="font-size:0.77rem; color:#536B91; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{explanation}</div>'
                '</div>'
                '<div style="font-size:1.15rem; color:#8FA3C7; font-weight:700;">›</div>'
                '</div>'
            )
            rows_html += row_html

    card_html = (
        '<div class="rs-card" style="height:100%;">'
        '<div class="rs-card-header">'
        '<div class="rs-card-title">Priority Findings</div>'
        '</div>'
        f'{rows_html}'
        '</div>'
    )
    safe_html(card_html)

    if st.button("Inspect All Findings in Detail →", key="btn_inspect_detail_panel", use_container_width=True, type="secondary"):
        st.session_state["current_page"] = "Findings"
        st.rerun()


# ==============================================================================
# QUICK ACTIONS BAR
# ==============================================================================
def render_quick_actions():
    """Renders the 4 horizontally aligned interactive action cards at the bottom."""
    safe_html(
        '<div class="rs-card" style="margin-top:0.5rem; margin-bottom:0.5rem;">'
        '<div class="rs-card-header" style="margin-bottom:0.85rem;">'
        '<div class="rs-card-title">Quick Actions</div>'
        '</div>'
        '</div>'
    )

    q1, q2, q3, q4 = st.columns(4)

    # 1. Scan Repository (Blue)
    with q1:
        safe_html(
            '<div class="rs-quick-card">'
            '<div>'
            '<div class="rs-quick-header">'
            '<div class="rs-quick-icon-circle" style="background:#EFF6FF; color:#2165F5;">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3"/><path d="m14.5 15.5 2.5 2.5"/>'
            '</svg>'
            '</div>'
            '<div class="rs-quick-title">Scan Repository</div>'
            '</div>'
            '<div class="rs-quick-desc">Upload a ZIP or select a local directory to scan</div>'
            '</div>'
            '</div>'
        )
        if st.button("Launch Scan", key="quick_act_scan", use_container_width=True, type="secondary"):
            st.session_state["current_page"] = "Scan Repository"
            st.rerun()

    # 2. AI Analysis (Purple)
    with q2:
        safe_html(
            '<div class="rs-quick-card">'
            '<div>'
            '<div class="rs-quick-header">'
            '<div class="rs-quick-icon-circle" style="background:#F5F3FF; color:#8B5CF6;">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 2v4"/><path d="M12 18v4"/><path d="m4.93 4.93 2.83 2.83"/><path d="m16.24 16.24 2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="m4.93 19.07 2.83-2.83"/><path d="m16.24 7.76 2.83-2.83"/><circle cx="12" cy="12" r="4"/>'
            '</svg>'
            '</div>'
            '<div class="rs-quick-title">AI Analysis</div>'
            '</div>'
            '<div class="rs-quick-desc">Get AI explanations and remediation guidance</div>'
            '</div>'
            '</div>'
        )
        if st.button("Start Triage", key="quick_act_ai", use_container_width=True, type="secondary"):
            st.session_state["current_page"] = "AI Analysis"
            st.rerun()

    # 3. Test Lab (Green)
    with q3:
        safe_html(
            '<div class="rs-quick-card">'
            '<div>'
            '<div class="rs-quick-header">'
            '<div class="rs-quick-icon-circle" style="background:#F0FDF4; color:#10B981;">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/>'
            '</svg>'
            '</div>'
            '<div class="rs-quick-title">Test Lab</div>'
            '</div>'
            '<div class="rs-quick-desc">Generate and run edge-case tests for Python code</div>'
            '</div>'
            '</div>'
        )
        if st.button("Open Lab", key="quick_act_lab", use_container_width=True, type="secondary"):
            st.session_state["current_page"] = "Test Lab"
            st.rerun()

    # 4. Export Reports (Amber)
    with q4:
        safe_html(
            '<div class="rs-quick-card">'
            '<div>'
            '<div class="rs-quick-header">'
            '<div class="rs-quick-icon-circle" style="background:#FFFBEB; color:#F59E0B;">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>'
            '</svg>'
            '</div>'
            '<div class="rs-quick-title">Export Reports</div>'
            '</div>'
            '<div class="rs-quick-desc">Download JSON, Markdown or SARIF reports</div>'
            '</div>'
            '</div>'
        )
        if st.button("Export Center", key="quick_act_reports", use_container_width=True, type="secondary"):
            st.session_state["current_page"] = "Reports"
            st.rerun()


# ==============================================================================
# BADGE & HELPER FUNCTIONS
# ==============================================================================
def get_severity_badge_html(severity: str) -> str:
    """Returns HTML for a standardized severity badge."""
    s = severity.lower()
    if s == "critical":
        css_class = "rs-badge-critical"
    elif s == "high":
        css_class = "rs-badge-high"
    elif s == "medium":
        css_class = "rs-badge-medium"
    elif s == "low":
        css_class = "rs-badge-low"
    else:
        css_class = "rs-badge-type"
    return f'<span class="rs-badge {css_class}">{severity}</span>'


def get_type_badge_html(finding_type: str) -> str:
    """Returns HTML for finding type badge (Secret vs Dependency)."""
    return f'<span class="rs-badge rs-badge-type">{finding_type}</span>'


def get_verification_badge_html(status: str) -> str:
    """Returns HTML for remediation verification status badge."""
    s = status.upper()
    if s == "VERIFIED":
        return '<span class="rs-badge" style="background:#DCFCE7; color:#15803D; border:1px solid #BBF7D0;">✓ Verified</span>'
    elif s == "FAILED":
        return '<span class="rs-badge rs-badge-critical">✕ Failed</span>'
    elif s == "PROPOSED":
        return '<span class="rs-badge rs-badge-medium">Proposed</span>'
    else:
        return f'<span class="rs-badge rs-badge-low">{status}</span>'


def render_metric_card(
    label: str,
    value: Any,
    subtext: Optional[str] = None,
    variant: str = "default",
):
    """Legacy compatibility helper."""
    card_html = (
        '<div class="rs-card">'
        f'<div style="font-size:0.75rem; font-weight:700; color:#536B91; text-transform:uppercase;">{label}</div>'
        f'<div style="font-size:1.85rem; font-weight:800; color:#10264B; margin:0.25rem 0;">{value}</div>'
        f'<div style="font-size:0.8rem; color:#536B91;">{subtext or ""}</div>'
        '</div>'
    )
    safe_html(card_html)


def render_empty_state(
    icon: str,
    title: str,
    description: str,
):
    """Renders a centered empty state placeholder."""
    html = (
        '<div class="rs-empty-box">'
        f'<div class="rs-empty-icon">{icon}</div>'
        f'<div class="rs-empty-title">{title}</div>'
        f'<div class="rs-empty-desc">{description}</div>'
        '</div>'
    )
    safe_html(html)


def render_header(
    ollama_connected: bool,
    available_models: list,
    selected_model: str,
    version: str = "1.0.0",
):
    """Backwards-compatibility alias for top bar."""
    return render_top_bar(
        ollama_connected=ollama_connected,
        available_models=available_models,
        selected_model=selected_model,
    )
