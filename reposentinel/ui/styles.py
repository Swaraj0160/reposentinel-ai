"""Bright, modern cybersecurity SaaS theme and design system for RepoSentinel AI."""

import textwrap

RAW_CSS = """
<style>
/* ==========================================================================
   RepoSentinel AI - Bright Modern Security SaaS Design System
   Palette:
     Main BG:       #F4F7FB (Soft cool white)
     Card Surface:  #FFFFFF (Pure white)
     Sidebar BG:    #101C35 (Deep dark navy for contrast)
     Primary Text:  #18263D (Dark slate navy)
     Secondary:     #64748B (Muted slate gray)
     Borders:       #E2E8F0 (Subtle cool border)
     Primary Blue:  #2563EB
     Success Green: #15803D / #DCFCE7
     Warning Amber: #B45309 / #FEF3C7
     Critical Red:  #B91C1C / #FEE2E2
   ========================================================================== */

/* Main Page Container Bounds */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 3rem !important;
    max-width: 1380px !important;
    color: #18263D !important;
}

/* Sidebar Custom Styling (Deep Navy) */
[data-testid="stSidebar"] {
    background-color: #101C35 !important;
    border-right: 1px solid #1E2D4A !important;
}

[data-testid="stSidebar"] * {
    color: #CBD5E1 !important;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] strong,
[data-testid="stSidebar"] .st-emotion-cache-10trblm {
    color: #FFFFFF !important;
}

/* Sidebar Navigation Items */
[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 0.5rem 0.75rem !important;
    border-radius: 6px !important;
    margin-bottom: 0.25rem !important;
    background-color: transparent !important;
    transition: all 0.15s ease !important;
    cursor: pointer !important;
}

[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background-color: #1B2B4E !important;
}

[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background-color: #1E3A6B !important;
    border-left: 3px solid #3B82F6 !important;
}

[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] span,
[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) span {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

/* Top Bar Banner / Header */
.rs-top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 0.85rem 1.25rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}

.rs-top-bar-left {
    display: flex;
    align-items: center;
    gap: 0.85rem;
    min-width: 0;
}

.rs-app-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: #18263D;
    margin: 0;
    line-height: 1.2;
    white-space: nowrap;
}

.rs-app-sub {
    font-size: 0.85rem;
    color: #64748B;
    margin: 0.15rem 0 0 0;
    white-space: nowrap;
}

/* Status Badges & Pills */
.rs-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    font-weight: 600;
    padding: 0.3rem 0.75rem;
    border-radius: 9999px;
    white-space: nowrap;
}

.rs-pill-success {
    background-color: #DCFCE7;
    color: #15803D;
    border: 1px solid #BBF7D0;
}

.rs-pill-warning {
    background-color: #FEF3C7;
    color: #B45309;
    border: 1px solid #FDE68A;
}

.rs-pill-danger {
    background-color: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FECACA;
}

.rs-pill-info {
    background-color: #DBEAFE;
    color: #1D4ED8;
    border: 1px solid #BFDBFE;
}

/* Severity Badges */
.rs-badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    font-family: ui-monospace, SFMono-Regular, monospace;
}

.rs-badge-critical {
    background: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FECACA;
}

.rs-badge-high {
    background: #FEF3C7;
    color: #B45309;
    border: 1px solid #FDE68A;
}

.rs-badge-medium {
    background: #DBEAFE;
    color: #1D4ED8;
    border: 1px solid #BFDBFE;
}

.rs-badge-low {
    background: #F1F5F9;
    color: #475569;
    border: 1px solid #E2E8F0;
}

.rs-badge-type {
    background: #F8FAFC;
    color: #475569;
    border: 1px solid #E2E8F0;
    font-size: 0.72rem;
}

/* SaaS Metric Cards */
.rs-card {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 1.15rem 1.25rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    margin-bottom: 1rem;
}

.rs-metric-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #64748B;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 0.35rem;
}

.rs-metric-val {
    font-size: 1.85rem;
    font-weight: 700;
    color: #18263D;
    line-height: 1.1;
    font-family: ui-monospace, SFMono-Regular, monospace;
}

.rs-metric-val.critical {
    color: #B91C1C;
}

.rs-metric-val.warning {
    color: #B45309;
}

.rs-metric-val.info {
    color: #2563EB;
}

.rs-metric-sub {
    font-size: 0.8rem;
    color: #64748B;
    margin-top: 0.35rem;
}

/* Unified Finding Compact Row */
.rs-row {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.rs-row:hover {
    border-color: #CBD5E1;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
}

/* Clean Empty State */
.rs-empty-box {
    text-align: center;
    padding: 2.75rem 1.5rem;
    background: #FFFFFF;
    border: 1px dashed #CBD5E1;
    border-radius: 8px;
    margin: 1.25rem 0;
}

.rs-empty-icon {
    font-size: 2.4rem;
    margin-bottom: 0.5rem;
}

.rs-empty-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #18263D;
    margin-bottom: 0.35rem;
}

.rs-empty-desc {
    font-size: 0.88rem;
    color: #64748B;
    max-width: 520px;
    margin: 0 auto 1.25rem auto;
    line-height: 1.5;
}

/* Stepper on Scan Page */
.rs-step-badge {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: #EFF6FF;
    color: #2563EB;
    font-size: 0.8rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid #BFDBFE;
}

/* Streamlit Button Tweaks (Bright Blue & Clean White) */
button[kind="primary"] {
    background-color: #2563EB !important;
    border-color: #2563EB !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
    padding: 0.45rem 1.15rem !important;
}

button[kind="primary"]:hover {
    background-color: #1D4ED8 !important;
    border-color: #1D4ED8 !important;
}

button[kind="secondary"] {
    background-color: #FFFFFF !important;
    border-color: #CBD5E1 !important;
    color: #18263D !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
    padding: 0.45rem 1.15rem !important;
}

button[kind="secondary"]:hover {
    background-color: #F8FAFC !important;
    border-color: #94A3B8 !important;
}

/* Form Inputs & Select Boxes */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div {
    background-color: #FFFFFF !important;
    color: #18263D !important;
    border-color: #CBD5E1 !important;
    border-radius: 6px !important;
}

.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #2563EB !important;
    box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.15) !important;
}

/* Code & Diff Containers */
pre, code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
}

.rs-diff-box {
    background: #0F172A;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 0.85rem;
    font-size: 0.85rem;
    line-height: 1.45;
    overflow-x: auto;
}
</style>
"""

# Dedent to ensure CommonMark never treats CSS lines as indented code blocks!
CUSTOM_CSS = textwrap.dedent(RAW_CSS).strip()
