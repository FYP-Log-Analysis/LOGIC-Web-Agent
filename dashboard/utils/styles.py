"""
Shared theme constants and HTML helper functions for the LOGIC Web Agent dashboard.
Import from here instead of duplicating magic values across components.
"""

from __future__ import annotations

# ── Palette ────────────────────────────────────────────────────────────────────
BG_DEEP    = "#080808"
BG_CARD    = "#0d0d0d"
BG_RAISED  = "#111111"
BORDER     = "#1e1e1e"
BORDER_DIM = "#1a1a1a"

TEXT_PRIMARY   = "#e0e0e0"
TEXT_SECONDARY = "#c0c0c0"
TEXT_MUTED     = "#555555"
TEXT_DIM       = "#333333"

ACCENT_ADMIN   = "#6b46c1"
ACCENT_ANALYST = "#1d4ed8"
ACCENT_AI      = "#4c1d95"

STATUS_OK    = "#2E8B57"
STATUS_WARN  = "#cc8800"
STATUS_ERROR = "#cc4444"


# ── HTML helpers ───────────────────────────────────────────────────────────────

def section_header(text: str) -> str:
    """Uppercase letter-spaced section label (pass to st.markdown unsafe_allow_html=True)."""
    return (
        f'<div style="font-size:11px; letter-spacing:2px; color:{TEXT_MUTED}; '
        f'text-transform:uppercase; margin:28px 0 12px 0;">{text}</div>'
    )


def hr() -> str:
    """Styled horizontal rule."""
    return '<hr style="border:none; border-top:1px solid #181818; margin:24px 0;">'


def status_dot(active: bool) -> str:
    """
    Small CSS circle in green (active) or red (inactive).
    Replaces 🟢/🔴 emoji for consistent cross-platform rendering.
    Returns an inline HTML span — use inside unsafe_allow_html=True markdown.
    """
    color = STATUS_OK if active else STATUS_ERROR
    return (
        f'<span style="display:inline-block; width:7px; height:7px; '
        f'border-radius:50%; background:{color}; margin-right:6px; '
        f'vertical-align:middle;"></span>'
    )


def api_status_line(healthy: bool) -> str:
    """
    One-line "API · ONLINE/OFFLINE" indicator with a CSS dot.
    Replaces inline emoji status checks in overview and pipeline components.
    """
    dot   = status_dot(healthy)
    label = "ONLINE" if healthy else "OFFLINE"
    return (
        f'<div style="font-size:11px; letter-spacing:1px; color:#444; margin-bottom:20px;">'
        f'API &nbsp; {dot} &nbsp; {label}</div>'
    )
