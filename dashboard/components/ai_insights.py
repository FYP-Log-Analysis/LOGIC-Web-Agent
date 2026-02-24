import os
import streamlit as st

from utils.api_client import get_threat_insights, get_insights_status


def _badge(label: str, color: str, bg: str = "transparent") -> str:
    return (
        f'<span style="display:inline-block; padding:2px 10px; '
        f'border-radius:2px; border:1px solid {color}; color:{color}; '
        f'background:{bg}; font-size:10px; letter-spacing:1.2px; '
        f'text-transform:uppercase; font-weight:500;">{label}</span>'
    )


def render_ai_insights() -> None:
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        AI INSIGHTS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Groq Cloud LLM analysis of detection results — powered by llama-3.3-70b-versatile.
        </p>""",
        unsafe_allow_html=True,
    )

    # ── Status badges ──────────────────────────────────────────────────────────
    groq_key_set = bool(os.getenv("GROQ_API_KEY"))
    status_data  = get_insights_status()
    has_data     = status_data.get("status") == "available"

    badge_groq = _badge(
        "Groq API Key Set" if groq_key_set else "Groq API Key Missing",
        "#4caf50" if groq_key_set else "#ff4444",
    )
    badge_data = _badge(
        f"Detection Data Ready — {status_data.get('total_matches', 0):,} matches"
        if has_data else "No Detection Data",
        "#4caf50" if has_data else "#888888",
    )

    st.markdown(
        f"""<div style="margin-bottom:24px; display:flex; gap:10px; flex-wrap:wrap;">
        {badge_groq}&nbsp;&nbsp;{badge_data}
        </div>""",
        unsafe_allow_html=True,
    )

    if not groq_key_set:
        st.markdown(
            """<div style="background:#1a1010; border:1px solid #3a1010; border-radius:4px; padding:16px 20px; color:#cc8888; font-size:13px; margin-bottom:16px;">
            Set the <code>GROQ_API_KEY</code> environment variable to enable AI threat analysis.
            </div>""",
            unsafe_allow_html=True,
        )

    if not has_data:
        st.markdown(
            """<div style="background:#111; border:1px solid #1e1e1e; border-radius:4px; padding:16px 20px; color:#666; font-size:13px; margin-bottom:16px;">
            No detection results available. Upload logs and run Analysis first.
            </div>""",
            unsafe_allow_html=True,
        )

    col1, col2 = st.columns([3, 1])
    with col2:
        generate = st.button(
            "Generate AI Threat Insights",
            use_container_width=True,
            disabled=not (groq_key_set and has_data),
        )

    if not generate:
        if "last_ai_insights" in st.session_state:
            _render_insights(st.session_state["last_ai_insights"])
        return

    with st.spinner("Calling Groq API…"):
        result = get_threat_insights()

    if result.get("error"):
        st.error(f"API error: {result['error']}")
        return
    if result.get("status") == "error":
        st.error(f"LLM error: {result.get('error_message')}")
        return

    st.session_state["last_ai_insights"] = result
    _render_insights(result)


def _render_insights(result: dict) -> None:
    analysis = result.get("analysis") or ""
    model    = result.get("model",   "llama-3.3-70b-versatile")
    backend  = result.get("backend", "groq")
    det_sum  = result.get("detection_summary", {})

    # Meta bar
    st.markdown(
        f"""<div style="background:#0a0a0a; border:1px solid #1a1a1a; border-radius:4px; padding:10px 16px; margin-bottom:16px; display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
        <span style="color:#444; font-size:11px; letter-spacing:1px; text-transform:uppercase;">Model</span>
        <span style="color:#888; font-size:12px;">{model}</span>
        <span style="color:#222;">|</span>
        <span style="color:#444; font-size:11px; letter-spacing:1px; text-transform:uppercase;">Backend</span>
        <span style="color:#888; font-size:12px;">{backend.upper()}</span>
        <span style="color:#222;">|</span>
        <span style="color:#444; font-size:11px; letter-spacing:1px; text-transform:uppercase;">Matches Analysed</span>
        <span style="color:#888; font-size:12px;">{det_sum.get('total_matches', '—'):,}</span>
        </div>""",
        unsafe_allow_html=True,
    )

    # Analysis output
    st.markdown(
        f"""<div style="background:#0d0d0d; border:1px solid #1a1a1a; border-radius:4px; padding:24px 28px; color:#b0b0b0; font-size:14px; line-height:1.8; font-family:monospace; white-space:pre-wrap; overflow-x:auto;">
{analysis}
        </div>""",
        unsafe_allow_html=True,
    )
