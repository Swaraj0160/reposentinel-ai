"""
RepoSentinel AI - Design System & Modern Bright Security SaaS CSS.
Theme Tokens:
  Canvas:       #F4F7FC (Very light cool blue-white)
  Card Surface: #FFFFFF (Pure white)
  Sidebar BG:   Linear Gradient #0E1B35 to #14284A (Deep dark navy)
  Primary Text: #10264B (Deep slate navy)
  Secondary:    #536B91 (Muted blue-gray)
  Borders:      #DFE7F2 (Subtle cool gray-blue)
  Accent Blue:  #2165F5 (Vivid security blue)
  Critical Red: #DC2626 / #FEF2F2
  Amber High:   #D97706 / #FFFBEB
  OSV Info:     #2563EB / #EFF6FF
  Mint Green:   #16A34A / #F0FDF4
  AI Purple:    #8B5CF6 / #F5F3FF
"""

# SVG Data URIs for Sidebar Icons (Clean Line Icons)
ICON_OVERVIEW = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Crect%20x%3D%223%22%20y%3D%223%22%20width%3D%227%22%20height%3D%229%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2214%22%20y%3D%223%22%20width%3D%227%22%20height%3D%225%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2214%22%20y%3D%2212%22%20width%3D%227%22%20height%3D%229%22%20rx%3D%221%22/%3E%3Crect%20x%3D%223%22%20y%3D%2216%22%20width%3D%227%22%20height%3D%225%22%20rx%3D%221%22/%3E%3C/svg%3E"
ICON_SCAN = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%22/%3E%3Ccircle%20cx%3D%2212%22%20cy%3D%2213%22%20r%3D%223%22/%3E%3Cpath%20d%3D%22m14.5%2015.5%202.5%202.5%22/%3E%3C/svg%3E"
ICON_FINDINGS = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M12%2022s8-4%208-10V5l-8-3-8%203v7c0%206%208%2010%208%2010z%22/%3E%3Cline%20x1%3D%2212%22%20y1%3D%228%22%20x2%3D%2212%22%20y2%3D%2212%22/%3E%3Cline%20x1%3D%2212%22%20y1%3D%2216%22%20x2%3D%2212.01%22%20y2%3D%2216%22/%3E%3C/svg%3E"
ICON_AI = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M12%202v4%22/%3E%3Cpath%20d%3D%22M12%2018v4%22/%3E%3Cpath%20d%3D%22m4.93%204.93%202.83%202.83%22/%3E%3Cpath%20d%3D%22m16.24%2016.24%202.83%202.83%22/%3E%3Cpath%20d%3D%22M2%2012h4%22/%3E%3Cpath%20d%3D%22M18%2012h4%22/%3E%3Cpath%20d%3D%22m4.93%2019.07%202.83-2.83%22/%3E%3Cpath%20d%3D%22m16.24%207.76%202.83-2.83%22/%3E%3Ccircle%20cx%3D%2212%22%20cy%3D%2212%22%20r%3D%224%22/%3E%3C/svg%3E"
ICON_LAB = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M10%202v7.527a2%202%200%200%201-.211.896L4.72%2020.55a1%201%200%200%200%20.9%201.45h12.76a1%201%200%200%200%20.9-1.45l-5.069-10.127A2%202%200%200%201%2014%209.527V2%22/%3E%3Cpath%20d%3D%22M8.5%202h7%22/%3E%3Cpath%20d%3D%22M7%2016h10%22/%3E%3C/svg%3E"
ICON_REMEDIATION = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M14.7%206.3a1%201%200%200%200%200%201.4l1.6%201.6a1%201%200%200%200%201.4%200l3.77-3.77a6%206%200%200%201-7.94%207.94l-6.91%206.91a2.12%202.12%200%200%201-3-3l6.91-6.91a6%206%200%200%201%207.94-7.94l-3.76%203.76z%22/%3E%3C/svg%3E"
ICON_REPORTS = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8z%22/%3E%3Cpolyline%20points%3D%2214%202%2014%208%2020%208%22/%3E%3Cline%20x1%3D%2216%22%20y1%3D%2213%22%20x2%3D%228%22%20y2%3D%2213%22/%3E%3Cline%20x1%3D%2216%22%20y1%3D%2217%22%20x2%3D%228%22%20y2%3D%2217%22/%3E%3C/svg%3E"
ICON_LEARN = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%2220%22%20height%3D%2220%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238FA3C7%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M2%203h6a4%204%200%200%201%204%204v14a3%203%200%200%200-3-3H2z%22/%3E%3Cpath%20d%3D%22M22%203h-6a4%204%200%200%200-4%204v14a3%203%200%200%201%203-3h7z%22/%3E%3C/svg%3E"

CUSTOM_CSS = f"""
<style>
/* ==========================================================================
   RepoSentinel AI - Master Security SaaS Theme & Strict Layout Bounds
   ========================================================================== */

/* Universal Canvas Reset & Strict Horizontal Overflow Containment */
html, body {{
    background-color: #F4F7FC !important;
    color: #10264B !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    overflow-x: hidden !important;
    max-width: 100vw !important;
    box-sizing: border-box !important;
}}

[data-testid="stAppViewContainer"], .stApp {{
    background-color: #F4F7FC !important;
    color: #10264B !important;
    overflow-x: hidden !important;
    max-width: 100% !important;
}}

[data-testid="stMain"] {{
    overflow-x: hidden !important;
    max-width: 100% !important;
}}

/* Main Block Bounds - Responsive, Centered, No Horizontal Scrollbars */
.block-container {{
    padding-top: 1rem !important;
    padding-bottom: 3.5rem !important;
    max-width: 1380px !important;
    width: 100% !important;
    margin-left: auto !important;
    margin-right: auto !important;
    box-sizing: border-box !important;
    overflow-x: hidden !important;
}}

/* Header Toolbar Transparency */
[data-testid="stHeader"] {{
    background-color: transparent !important;
    z-index: 10 !important;
}}

/* Image and SVG Universal Overflow Guard */
img, svg {{
    max-width: 100% !important;
    box-sizing: border-box !important;
}}

/* ==========================================================================
   Deep Navy Gradient Sidebar
   ========================================================================== */
[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, #0E1B35 0%, #14284A 100%) !important;
    border-right: 1px solid #1E2D4A !important;
    box-shadow: 2px 0 10px rgba(0, 0, 0, 0.12) !important;
    overflow-x: hidden !important;
}}

[data-testid="stSidebar"] * {{
    color: #CBD5E1 !important;
}}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] strong {{
    color: #FFFFFF !important;
}}

/* Hide native circular radio bullets completely */
[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child {{
    display: none !important;
}}

[data-testid="stSidebar"] div[role="radiogroup"] {{
    gap: 0.25rem !important;
}}

/* Custom Navigation Menu Items */
[data-testid="stSidebar"] div[role="radiogroup"] > label {{
    padding: 0.6rem 0.9rem !important;
    border-radius: 8px !important;
    margin: 0 !important;
    background-color: transparent !important;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1) !important;
    cursor: pointer !important;
    display: flex !important;
    align-items: center !important;
    border: 1px solid transparent !important;
    width: 100% !important;
}}

[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {{
    background-color: rgba(255, 255, 255, 0.08) !important;
}}

[data-testid="stSidebar"] div[role="radiogroup"] > label:hover p,
[data-testid="stSidebar"] div[role="radiogroup"] > label:hover span {{
    color: #FFFFFF !important;
}}

/* Active Navigation Item: Bright Blue Rounded Rectangle with White Text */
[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked),
[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] {{
    background-color: #2165F5 !important;
    box-shadow: 0 2px 10px rgba(33, 101, 245, 0.4) !important;
    border-color: rgba(255, 255, 255, 0.15) !important;
}}

[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p,
[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) span,
[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p,
[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] span {{
    color: #FFFFFF !important;
    font-weight: 600 !important;
}}

/* Navigation Icons using CSS ::before */
[data-testid="stSidebar"] div[role="radiogroup"] > label p::before {{
    content: "";
    display: inline-block;
    width: 18px;
    height: 18px;
    margin-right: 11px;
    vertical-align: -3px;
    background-size: contain;
    background-repeat: no-repeat;
    opacity: 0.85;
    transition: all 0.15s ease;
}}

[data-testid="stSidebar"] div[role="radiogroup"] > label:hover p::before,
[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p::before,
[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p::before {{
    opacity: 1;
    filter: brightness(0) invert(1);
}}

/* Bind exact icon to each nav row */
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(1) p::before {{ background-image: url("{ICON_OVERVIEW}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(2) p::before {{ background-image: url("{ICON_SCAN}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(3) p::before {{ background-image: url("{ICON_FINDINGS}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(4) p::before {{ background-image: url("{ICON_AI}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(5) p::before {{ background-image: url("{ICON_LAB}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(6) p::before {{ background-image: url("{ICON_REMEDIATION}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(7) p::before {{ background-image: url("{ICON_REPORTS}"); }}
[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-of-type(8) p::before {{ background-image: url("{ICON_LEARN}"); }}

/* Sidebar Translucent Cards */
.rs-sidebar-card {{
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: 9px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.85rem;
}}

/* ==========================================================================
   Top Application Bar (Search + Model Status Pill)
   ========================================================================== */
.rs-top-bar-container {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1.25rem;
    background: #FFFFFF;
    border: 1px solid #DFE7F2;
    border-radius: 10px;
    padding: 0.65rem 1.15rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 1px 3px rgba(16, 38, 75, 0.03);
}}

.rs-top-pill {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    font-weight: 600;
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    white-space: nowrap;
}}

.rs-pill-online {{
    background-color: #DCFCE7;
    color: #15803D;
    border: 1px solid #BBF7D0;
}}

.rs-pill-warning {{
    background-color: #FEF3C7;
    color: #B45309;
    border: 1px solid #FDE68A;
}}

.rs-pill-offline {{
    background-color: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FECACA;
}}

.rs-status-dot {{
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
}}

.rs-dot-online {{
    background-color: #16A34A;
    box-shadow: 0 0 0 2px rgba(22, 163, 74, 0.25);
}}

.rs-dot-warning {{
    background-color: #D97706;
    box-shadow: 0 0 0 2px rgba(217, 119, 6, 0.25);
}}

.rs-dot-offline {{
    background-color: #DC2626;
    box-shadow: 0 0 0 2px rgba(220, 38, 38, 0.25);
}}

/* ==========================================================================
   Hero Banner Styling (Container Border Wrapper Match)
   ========================================================================== */
div[data-testid="stVerticalBlockBorderWrapper"]:has(.rs-hero-eyebrow) {{
    background: linear-gradient(135deg, #EBF3FE 0%, #F0F6FF 100%) !important;
    border: 1px solid #D0E1FD !important;
    border-radius: 12px !important;
    padding: 1.25rem 1.6rem !important;
    box-shadow: 0 2px 8px rgba(33, 101, 245, 0.04) !important;
    margin-bottom: 1.15rem !important;
    overflow: hidden !important;
}}

.rs-hero-eyebrow {{
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.09em;
    color: #2165F5;
    text-transform: uppercase;
    margin-bottom: 0.35rem;
}}

.rs-hero-title {{
    font-size: 1.85rem;
    font-weight: 800;
    color: #10264B;
    margin: 0 0 0.55rem 0;
    line-height: 1.22;
    letter-spacing: -0.025em;
}}

.rs-hero-title-accent {{
    color: #2165F5;
}}

.rs-hero-desc {{
    font-size: 0.92rem;
    color: #536B91;
    margin: 0 0 1rem 0;
    line-height: 1.55;
    max-width: 620px;
}}

/* ==========================================================================
   Dashboard Metrics (4 Tinted Cards)
   ========================================================================== */
.rs-metric-box {{
    border-radius: 10px;
    padding: 1.15rem 1.25rem;
    border: 1px solid;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
    box-sizing: border-box;
}}

.rs-metric-box:hover {{
    transform: translateY(-1px);
    box-shadow: 0 3px 8px rgba(16, 38, 75, 0.05);
}}

.rs-metric-header {{
    display: flex;
    align-items: center;
    gap: 0.65rem;
    margin-bottom: 0.5rem;
}}

.rs-metric-icon-circle {{
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}}

.rs-metric-title {{
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}}

.rs-metric-num {{
    font-size: 2.15rem;
    font-weight: 800;
    line-height: 1.1;
    margin: 0.2rem 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}}

.rs-metric-caption {{
    font-size: 0.8rem;
    font-weight: 500;
}}

/* Critical Card Variant */
.rs-metric-box.critical {{
    background-color: #FEF2F2;
    border-color: #FEE2E2;
}}
.rs-metric-box.critical .rs-metric-icon-circle {{ background-color: #FEE2E2; color: #DC2626; }}
.rs-metric-box.critical .rs-metric-title {{ color: #991B1B; }}
.rs-metric-box.critical .rs-metric-num {{ color: #DC2626; }}
.rs-metric-box.critical .rs-metric-caption {{ color: #991B1B; opacity: 0.9; }}

/* High Card Variant */
.rs-metric-box.high {{
    background-color: #FFFBEB;
    border-color: #FEF3C7;
}}
.rs-metric-box.high .rs-metric-icon-circle {{ background-color: #FEF3C7; color: #D97706; }}
.rs-metric-box.high .rs-metric-title {{ color: #92400E; }}
.rs-metric-box.high .rs-metric-num {{ color: #D97706; }}
.rs-metric-box.high .rs-metric-caption {{ color: #92400E; opacity: 0.9; }}

/* OSV Info Variant */
.rs-metric-box.osv {{
    background-color: #EFF6FF;
    border-color: #DBEAFE;
}}
.rs-metric-box.osv .rs-metric-icon-circle {{ background-color: #DBEAFE; color: #2563EB; }}
.rs-metric-box.osv .rs-metric-title {{ color: #1E40AF; }}
.rs-metric-box.osv .rs-metric-num {{ color: #2563EB; }}
.rs-metric-box.osv .rs-metric-caption {{ color: #1E40AF; opacity: 0.9; }}

/* Mint Green Variant */
.rs-metric-box.files {{
    background-color: #F0FDF4;
    border-color: #DCFCE7;
}}
.rs-metric-box.files .rs-metric-icon-circle {{ background-color: #DCFCE7; color: #16A34A; }}
.rs-metric-box.files .rs-metric-title {{ color: #166534; }}
.rs-metric-box.files .rs-metric-num {{ color: #16A34A; }}
.rs-metric-box.files .rs-metric-caption {{ color: #166534; opacity: 0.9; }}

/* ==========================================================================
   Universal Card Containers & Alternating Table Rows
   ========================================================================== */
.rs-card {{
    background: #FFFFFF;
    border: 1px solid #DFE7F2;
    border-radius: 10px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 1px 3px rgba(16, 38, 75, 0.03);
    margin-bottom: 1.15rem;
    box-sizing: border-box;
}}

.rs-card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}}

.rs-card-title {{
    font-size: 1.05rem;
    font-weight: 700;
    color: #10264B;
    margin: 0;
}}

/* Table Rows with Alternating Backgrounds */
.rs-table-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.55rem 0.75rem;
    border-radius: 6px;
    font-size: 0.86rem;
}}

.rs-table-row:nth-child(odd) {{
    background-color: #F8FAFC;
}}

.rs-table-row:nth-child(even) {{
    background-color: #FFFFFF;
}}

.rs-table-label {{
    color: #536B91;
    font-weight: 500;
}}

.rs-table-val {{
    color: #10264B;
    font-weight: 600;
    text-align: right;
}}

/* Priority Finding Row */
.rs-priority-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 0.85rem;
    border: 1px solid #EDF2F7;
    border-radius: 8px;
    margin-bottom: 0.55rem;
    background: #FFFFFF;
    transition: all 0.15s ease;
    box-sizing: border-box;
}}

.rs-priority-row:hover {{
    border-color: #CBD5E1;
    background-color: #F8FAFC;
    box-shadow: 0 2px 5px rgba(16, 38, 75, 0.04);
}}

/* ==========================================================================
   Quick Actions Bar
   ========================================================================== */
.rs-quick-card {{
    background: #FFFFFF;
    border: 1px solid #DFE7F2;
    border-radius: 10px;
    padding: 1.15rem 1.25rem;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1);
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    box-sizing: border-box;
    margin-bottom: 0.5rem;
}}

.rs-quick-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(16, 38, 75, 0.06);
    border-color: #CBD5E1;
}}

.rs-quick-header {{
    display: flex;
    align-items: center;
    gap: 0.65rem;
    margin-bottom: 0.5rem;
}}

.rs-quick-icon-circle {{
    width: 34px;
    height: 34px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}}

.rs-quick-title {{
    font-size: 0.95rem;
    font-weight: 700;
    color: #10264B;
}}

.rs-quick-desc {{
    font-size: 0.82rem;
    color: #536B91;
    line-height: 1.45;
    margin-bottom: 0.85rem;
}}

/* Badges */
.rs-badge {{
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-family: ui-monospace, SFMono-Regular, monospace;
}}

.rs-badge-critical {{
    background: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FECACA;
}}

.rs-badge-high {{
    background: #FEF3C7;
    color: #B45309;
    border: 1px solid #FDE68A;
}}

.rs-badge-medium {{
    background: #DBEAFE;
    color: #1D4ED8;
    border: 1px solid #BFDBFE;
}}

.rs-badge-low {{
    background: #F1F5F9;
    color: #475569;
    border: 1px solid #E2E8F0;
}}

.rs-badge-type {{
    background: #F8FAFC;
    color: #475569;
    border: 1px solid #E2E8F0;
}}

/* Empty Box */
.rs-empty-box {{
    text-align: center;
    padding: 3rem 1.5rem;
    background: #FFFFFF;
    border: 1px dashed #DFE7F2;
    border-radius: 10px;
    margin: 1.5rem 0;
}}

.rs-empty-icon {{
    font-size: 2.25rem;
    margin-bottom: 0.65rem;
}}

.rs-empty-title {{
    font-size: 1.15rem;
    font-weight: 700;
    color: #10264B;
    margin-bottom: 0.35rem;
}}

.rs-empty-desc {{
    font-size: 0.88rem;
    color: #536B91;
    max-width: 500px;
    margin: 0 auto;
    line-height: 1.5;
}}

/* Button Overrides */
div.stButton > button[kind="primary"] {{
    background-color: #2165F5 !important;
    color: #FFFFFF !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    border: none !important;
    box-shadow: 0 1px 3px rgba(33, 101, 245, 0.25) !important;
    transition: all 0.15s ease !important;
}}

div.stButton > button[kind="primary"]:hover {{
    background-color: #1A54D6 !important;
    box-shadow: 0 3px 8px rgba(33, 101, 245, 0.35) !important;
}}

div.stButton > button[kind="secondary"] {{
    background-color: #FFFFFF !important;
    color: #10264B !important;
    border: 1px solid #DFE7F2 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    transition: all 0.15s ease !important;
}}

div.stButton > button[kind="secondary"]:hover {{
    background-color: #F8FAFC !important;
    border-color: #CBD5E1 !important;
    color: #2165F5 !important;
}}
</style>
"""
