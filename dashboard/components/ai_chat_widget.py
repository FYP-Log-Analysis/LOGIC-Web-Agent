"""
ai_chat_widget.py — Hawkins · Personal Analyst

A reusable contextual AI chat widget that renders in the sidebar.

HOW TO USE
──────────
Call render_hawkins_sidebar() at the END of any page render function, after
data has been loaded so data_summary can be populated:

    from components.ai_chat_widget import render_hawkins_sidebar

    def render_my_page():
        data = load_data()
        # ... existing render code ...

        render_hawkins_sidebar(
            title         = "My Page",
            description   = "Shows X and Y.",
            data_summary  = {"rows": len(data), "top_ip": data[0]["ip"]},
            component_key = "my_page",
            help_guide    = "Click a row to drill down ...",
        )

The Hawkins panel appears at the bottom of the sidebar, collapsed by default.
Each component has its own independent chat history stored in session state.
The GROQ_API_KEY never leaves the API container — all inference is routed
through POST /api/analysis/chat which streams tokens back via chunked HTTP.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import streamlit as st

from utils.analysis_client import stream_chat_message

# ── CSS ───────────────────────────────────────────────────────────────────────

_HAWKINS_CSS = """
<style>
/* ── Chat message bubbles ──────────────────────────────────────────────── */
[data-testid="stChatMessage"] {
    background: transparent !important;
    border-radius: 6px !important;
    margin: 4px 0 !important;
}
[data-testid="stChatMessage"][data-testid*="user"] div[data-testid="stMarkdownContainer"] {
    background: rgba(109, 40, 217, 0.09) !important;
    border-left: 3px solid #7c3aed !important;
    padding: 8px 12px !important;
    border-radius: 0 4px 4px 0 !important;
}
[data-testid="stChatMessage"][data-testid*="assistant"] div[data-testid="stMarkdownContainer"] {
    background: #0d0d0d !important;
    border-left: 3px solid #2a2a2a !important;
    padding: 8px 12px !important;
    border-radius: 0 4px 4px 0 !important;
}

/* ── Chat input ────────────────────────────────────────────────────────── */
[data-testid="stChatInput"] textarea {
    background: #0d0d0d !important;
    border: 1px solid #2d1b69 !important;
    border-radius: 4px !important;
    color: #c0c0c0 !important;
    font-family: 'SF Mono','Fira Code','Consolas',monospace !important;
    font-size: 12px !important;
}
[data-testid="stChatInput"] textarea:focus {
    border-color: #7c3aed !important;
    box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.2) !important;
}
[data-testid="stChatInput"] button {
    background: #4c1d95 !important;
    border-color: #7c3aed !important;
    color: #c4b5fd !important;
    border-radius: 4px !important;
}

/* ── Floating chat button (bottom-right) ───────────────────────────────── */
/* Target the specific button by its Streamlit key via aria-label */
[data-testid="stBottom"] { display: none; }

.hawkins-float-wrapper {
    position: fixed !important;
    bottom: 24px !important;
    right: 24px !important;
    z-index: 99999 !important;
    display: flex !important;
    flex-direction: column !important;
    align-items: flex-end !important;
    gap: 10px !important;
}

.hawkins-float-panel {
    background: #080808 !important;
    border: 1px solid #2d1b69 !important;
    border-radius: 10px !important;
    box-shadow: 0 8px 40px rgba(109,40,217,0.30), 0 2px 12px rgba(0,0,0,0.85) !important;
    width: 400px !important;
    max-height: 540px !important;
    overflow-y: auto !important;
    padding: 16px 14px 10px 14px !important;
    display: flex !important;
    flex-direction: column !important;
}

.hawkins-float-btn {
    width: 52px !important;
    height: 52px !important;
    border-radius: 50% !important;
    background: #4c1d95 !important;
    border: 2px solid #7c3aed !important;
    color: #e9d5ff !important;
    font-size: 22px !important;
    cursor: pointer !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    box-shadow: 0 4px 20px rgba(109,40,217,0.45) !important;
    transition: background 0.2s !important;
    flex-shrink: 0 !important;
}
.hawkins-float-btn:hover {
    background: #6d28d9 !important;
}
</style>
"""


def _inject_css() -> None:
    """Inject Hawkins CSS exactly once per browser session."""
    if not st.session_state.get("_hawkins_css_injected"):
        st.markdown(_HAWKINS_CSS, unsafe_allow_html=True)
        st.session_state["_hawkins_css_injected"] = True


# ── Context builder ────────────────────────────────────────────────────────────

def _build_context(
    title:        str,
    description:  str,
    data_summary: Optional[Dict[str, Any]],
    help_guide:   str,
) -> str:
    """
    Assemble the rich context block sent to the API with every message.
    Includes the component metadata, data snapshot, active global filters,
    and an optional how-to guide the model can cite when explaining the UI.
    """
    lines = [
        f"COMPONENT: {title}",
        f"DESCRIPTION: {description}",
    ]

    # Active dashboard-level filters from session_state
    global_filters: Dict[str, Any] = {}
    for key in ("page", "time_start", "time_end", "active_filter", "log_filter"):
        val = st.session_state.get(key)
        if val is not None:
            global_filters[key] = str(val)
    if global_filters:
        lines.append(f"ACTIVE_FILTERS: {json.dumps(global_filters)}")

    # Compact JSON snapshot of the component's data
    if data_summary:
        try:
            # Truncate large lists so context stays within token budget
            def _trim(obj: Any, depth: int = 0) -> Any:
                if isinstance(obj, list):
                    trimmed = obj[:25]  # show at most 25 items
                    return [_trim(i, depth + 1) for i in trimmed]
                if isinstance(obj, dict):
                    return {k: _trim(v, depth + 1) for k, v in obj.items()}
                return obj

            lines.append(f"DATA_SUMMARY:\n{json.dumps(_trim(data_summary), indent=2, default=str)}")
        except Exception:
            lines.append(f"DATA_SUMMARY: {str(data_summary)[:2000]}")

    if help_guide:
        lines.append(f"HOW_TO_USE:\n{help_guide}")

    return "\n\n".join(lines)


# ── Inner chat UI ──────────────────────────────────────────────────────────────

def _render_chat_ui(
    title:        str,
    description:  str,
    data_summary: Optional[Dict[str, Any]],
    component_key: str,
    help_guide:   str,
) -> None:
    """Render the full Hawkins chat panel."""

    session_key = f"hawkins_{component_key}"
    if session_key not in st.session_state:
        st.session_state[session_key] = []

    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="display:flex; align-items:center; gap:10px; margin-bottom:14px;
            padding-bottom:10px; border-bottom:1px solid #2d1b69;">
          <span style="background:rgba(109,40,217,0.15); border:1px solid #4c1d95;
            color:#a78bfa; font-size:10px; letter-spacing:2px; padding:3px 9px;
            border-radius:12px; font-family:monospace;">HAWKINS</span>
          <span style="color:#e0e0e0; font-size:13px; font-weight:300;
            letter-spacing:1px; font-family:monospace;">{title}</span>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Conversation history ─────────────────────────────────────────────────
    history = st.session_state[session_key]

    # Render existing turns
    for msg in history:
        with st.chat_message(msg["role"], avatar="assistant" if msg["role"] == "assistant" else "user"):
            st.markdown(msg["content"])

    # "Clear" button — only show when there is history
    if history:
        if st.button(
            "Clear conversation",
            key=f"hawkins_clear_{component_key}",
            help="Erase the chat history for this component",
        ):
            st.session_state[session_key] = []
            st.rerun()

    # ── Chat input ───────────────────────────────────────────────────────────
    # Suggest some starter questions based on the component type
    placeholder = "Ask about this data, patterns, threats, or how to use this view…"
    user_input = st.chat_input(placeholder, key=f"hawkins_input_{component_key}")

    if user_input:
        # Append user message to history and display immediately
        history.append({"role": "user", "content": user_input})
        with st.chat_message("user", avatar="user"):
            st.markdown(user_input)

        # Build context once per submission
        context = _build_context(title, description, data_summary, help_guide)

        # Stream the assistant response
        with st.chat_message("assistant", avatar="assistant"):
            placeholder_el = st.empty()
            full_response   = ""

            with st.spinner(""):
                for chunk in stream_chat_message(context, history):
                    # Check for error JSON from the API
                    if chunk.startswith('{"error"'):
                        try:
                            err = json.loads(chunk)
                            full_response = f"**Error:** {err.get('error', chunk)}"
                        except Exception:
                            full_response = chunk
                        break
                    full_response += chunk
                    placeholder_el.markdown(full_response)

            # Final render without cursor
            placeholder_el.markdown(full_response)

        # Persist assistant turn
        history.append({"role": "assistant", "content": full_response})
        st.session_state[session_key] = history


# ── Public entry point ─────────────────────────────────────────────────────────

def render_hawkins_sidebar(
    title:         str,
    description:   str            = "",
    data_summary:  Optional[Dict] = None,
    component_key: str            = "default",
    help_guide:    str            = "",
) -> None:
    """
    Render the Hawkins AI chat panel as a floating widget anchored to the
    bottom-right corner of the screen, like a typical website chat button.

    Call this at the END of any page render function after data has been
    loaded, so that data_summary reflects the current page state.

    The panel is collapsed by default.  Clicking the circular button in the
    bottom-right corner toggles it open/closed.
    Each component has its own independent chat history in session state.
    """
    _inject_css()

    _collapsed_key = f"hawkins_collapsed_{component_key}"
    if _collapsed_key not in st.session_state:
        st.session_state[_collapsed_key] = True  # collapsed by default

    is_collapsed = st.session_state[_collapsed_key]

    # ── Floating toggle button (always visible, bottom-right) ───────────────
    # We inject a pure-HTML button that submits a hidden Streamlit form so the
    # click is handled server-side without requiring a JS eval library.
    # The actual Streamlit button is rendered off-screen and triggered via CSS.

    # Streamlit button for server-side click handling (hidden visually,
    # positioned via the wrapper div injected below)
    if st.button(
        "AI",
        key=f"hawkins_toggle_{component_key}",
        help="Open / close Hawkins AI assistant",
        type="secondary",
    ):
        st.session_state[_collapsed_key] = not is_collapsed
        st.rerun()

    # CSS to grab that specific button (identified by its aria-label / key)
    # and pin it fixed to the bottom-right corner.
    float_btn_css = f"""
<style>
/* Floating toggle button */
[data-testid="stBaseButton-secondary"][kind="secondary"] {{
    /* Reset — we only want to float the Hawkins toggle, not every secondary btn */
}}
/* Target by the exact key Streamlit assigns as aria-label */
button[aria-label="Open / close Hawkins AI assistant"] {{
    position: fixed !important;
    bottom: 24px !important;
    right: 24px !important;
    z-index: 99999 !important;
    width: 52px !important;
    height: 52px !important;
    border-radius: 50% !important;
    background: #4c1d95 !important;
    border: 2px solid #7c3aed !important;
    color: #e9d5ff !important;
    font-size: 13px !important;
    font-family: 'SF Mono','Fira Code','Consolas',monospace !important;
    letter-spacing: 0.5px !important;
    cursor: pointer !important;
    box-shadow: 0 4px 20px rgba(109,40,217,0.50) !important;
    padding: 0 !important;
    transition: background 0.2s !important;
}}
button[aria-label="Open / close Hawkins AI assistant"]:hover {{
    background: #6d28d9 !important;
}}
/* Hide the default Streamlit label span inside the button */
button[aria-label="Open / close Hawkins AI assistant"] p {{
    margin: 0 !important;
    font-size: 13px !important;
    color: #e9d5ff !important;
}}
</style>
"""
    st.markdown(float_btn_css, unsafe_allow_html=True)

    # ── Floating chat panel (shown when open) ───────────────────────────────
    if not is_collapsed:
        # Wrap the chat panel in a fixed-position div via raw HTML + st.container
        st.markdown(
            """
<div id="hawkins-panel-anchor" style="
    position: fixed;
    bottom: 88px;
    right: 24px;
    width: 400px;
    max-height: 540px;
    z-index: 99998;
    background: #080808;
    border: 1px solid #2d1b69;
    border-radius: 10px;
    box-shadow: 0 8px 40px rgba(109,40,217,0.30), 0 2px 12px rgba(0,0,0,0.85);
    overflow: hidden;
    display: flex;
    flex-direction: column;
"></div>
<style>
/* Move the next Streamlit container into the fixed panel via CSS transform trick */
div[data-testid="stVerticalBlock"]:has(> div > [data-testid="stVerticalBlock"] #hawkins-chat-inner) {{
    position: fixed !important;
    bottom: 88px !important;
    right: 24px !important;
    width: 400px !important;
    max-height: 540px !important;
    z-index: 99998 !important;
    background: #080808 !important;
    border: 1px solid #2d1b69 !important;
    border-radius: 10px !important;
    box-shadow: 0 8px 40px rgba(109,40,217,0.30), 0 2px 12px rgba(0,0,0,0.85) !important;
    overflow-y: auto !important;
    padding: 16px 14px 10px 14px !important;
}}
</style>
""",
            unsafe_allow_html=True,
        )

        # Marker so the CSS selector above can find this container
        st.markdown(
            '<div id="hawkins-chat-inner"></div>',
            unsafe_allow_html=True,
        )

        with st.container():
            _render_chat_ui(
                title         = title,
                description   = description,
                data_summary  = data_summary,
                component_key = component_key,
                help_guide    = help_guide,
            )


def hawkins_button(
    title:         str,
    description:   str            = "",
    data_summary:  Optional[Dict] = None,
    component_key: str            = "default",
    help_guide:    str            = "",
) -> None:
    """Deprecated alias for render_hawkins_sidebar(). Use render_hawkins_sidebar() instead."""
    render_hawkins_sidebar(
        title         = title,
        description   = description,
        data_summary  = data_summary,
        component_key = component_key,
        help_guide    = help_guide,
    )
