"""Reusable UI presentation components for RepoSentinel AI (Bright SaaS Theme)."""

from typing import Optional, Any
import streamlit as st


def render_header(
    ollama_connected: bool,
    available_models: list,
    selected_model: str,
    version: str = "1.0.0",
):
    """Renders the top application header bar with title, subtitle, and status pill."""
    col_left, col_right = st.columns([3, 1.3])

    with col_left:
        header_title_html = (
            '<div style="display:flex; align-items:center; gap:0.65rem;">'
            '<span style="font-size:1.6rem; line-height:1;">🛡️</span>'
            '<h2 style="margin:0; font-size:1.45rem; font-weight:700; color:#18263D; display:inline-block; white-space:nowrap; letter-spacing:-0.01em;">'
            f'RepoSentinel AI <span style="font-size:0.75rem; font-weight:600; padding:0.15rem 0.45rem; background:#EFF6FF; color:#2563EB; border:1px solid #BFDBFE; border-radius:4px; font-family:monospace; vertical-align:middle;">v{version}</span>'
            '</h2>'
            '</div>'
            '<p style="margin:0.25rem 0 0 0; font-size:0.88rem; color:#64748B;">Evidence-first repository security & edge-case testing</p>'
        )
        st.markdown(header_title_html, unsafe_allow_html=True)

    with col_right:
        if ollama_connected:
            sel_lower = selected_model.strip().lower()
            avail_lower = [m.lower() for m in available_models]
            has_model = (
                sel_lower in avail_lower
                or (":" not in sel_lower and any(m.startswith(f"{sel_lower}:") for m in avail_lower))
                or (sel_lower.endswith(":latest") and sel_lower.split(":", 1)[0] in avail_lower)
            )
            if has_model:
                pill_html = f'<div style="text-align:right; margin-top:0.4rem;"><span class="rs-pill rs-pill-success">● Ollama Online ({selected_model})</span></div>'
            else:
                pill_html = '<div style="text-align:right; margin-top:0.4rem;"><span class="rs-pill rs-pill-warning">● Model Missing (Fallback Active)</span></div>'
        else:
            pill_html = '<div style="text-align:right; margin-top:0.4rem;"><span class="rs-pill rs-pill-warning">○ Local AI Offline (Fallback Active)</span></div>'

        st.markdown(pill_html, unsafe_allow_html=True)

    st.markdown("<div style='margin-bottom:1.25rem; border-bottom:1px solid #E2E8F0; padding-bottom:0.75rem;'></div>", unsafe_allow_html=True)


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
    """Renders a single metric card with high-contrast text."""
    var_class = f" {variant}" if variant in ("critical", "warning", "info") else ""
    subtext_html = f'<div class="rs-metric-sub">{subtext}</div>' if subtext else ""
    card_html = (
        '<div class="rs-card">'
        f'<div class="rs-metric-label">{label}</div>'
        f'<div class="rs-metric-val{var_class}">{value}</div>'
        f'{subtext_html}'
        '</div>'
    )
    st.markdown(card_html, unsafe_allow_html=True)


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
    st.markdown(html, unsafe_allow_html=True)
