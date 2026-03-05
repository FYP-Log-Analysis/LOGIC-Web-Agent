import streamlit as st
from utils.api_client import api_health
from utils.pipeline_client import get_pipeline_steps, run_pipeline, run_pipeline_step
from utils.styles import api_status_line

STEP_LABELS = {
    "ingestion":     "1 · Log Ingestion",
    "processing":    "2 · Log Processing",
    "rule_analysis": "3 · CRS Rule-Based Detection",
}

_STATUS_COLORS = {
    "success":  ("#0a0f0a", "#2E8B57", "SUCCESS"),
    "complete": ("#0a0f0a", "#2E8B57", "COMPLETE"),
    "failed":   ("#1a0a0a", "#cc4444", "FAILED"),
    "error":    ("#1a0a0a", "#cc4444", "ERROR"),
    "timeout":  ("#1a0a0a", "#cc8800", "TIMEOUT"),
}


def _status_badge(status: str) -> str:
    bg, col, label = _STATUS_COLORS.get(status.lower(), ("#111", "#555", status.upper()))
    return (
        f'<span style="background:{bg}; border:1px solid {col}33; color:{col}; '
        f'padding:2px 10px; border-radius:2px; font-size:10px; letter-spacing:1px;">{label}</span>'
    )


def render_pipeline_control():
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        PIPELINE</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Trigger ingestion, normalisation, rule detection, and ML analysis steps.
        </p>""",
        unsafe_allow_html=True,
    )

    healthy = api_health()
    st.markdown(api_status_line(healthy), unsafe_allow_html=True)

    if not healthy:
        st.warning("Cannot reach the API — check that the API container is running.")
        return

    # ── Full pipeline ──────────────────────────────────────────────────────────
    col_btn, col_cap = st.columns([2, 5])
    with col_btn:
        run_all = st.button("Run Full Pipeline", width='stretch')
    with col_cap:
        st.caption("Runs all pipeline stages in sequence: ingest → process → CRS rule detection")

    if run_all:
        with st.spinner("Running full pipeline — this may take several minutes …"):
            result = run_pipeline()

        st.markdown(
            f"Overall: {_status_badge(result.get('status', 'unknown'))}",
            unsafe_allow_html=True,
        )
        for step_result in result.get("results", []):
            label = step_result.get("step_name") or step_result.get("step_id", "?")
            with st.expander(label):
                st.markdown(
                    f"Status: {_status_badge(step_result.get('status', ''))}",
                    unsafe_allow_html=True,
                )
                if step_result.get("output"):
                    st.code(step_result["output"], language="text")
                if step_result.get("error"):
                    st.error(step_result["error"])

    st.divider()

    # ── Individual steps ───────────────────────────────────────────────────────
    st.markdown(
        '<div style="color:#444; font-size:11px; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:12px;">Individual Steps</div>',
        unsafe_allow_html=True,
    )

    steps_info = get_pipeline_steps().get("steps", {})
    step_ids   = sorted(steps_info.keys(), key=lambda x: steps_info[x].get("order", 99))

    for step_id in step_ids:
        meta  = steps_info[step_id]
        label = STEP_LABELS.get(step_id, meta.get("name", step_id))
        desc  = meta.get("description", "")
        col1, col2 = st.columns([5, 1])
        col1.markdown(
            f'<div style="padding:12px 0;">'
            f'<div style="color:#c0c0c0; font-size:12px; letter-spacing:0.5px;">{label}</div>'
            f'<div style="color:#444; font-size:11px; margin-top:2px;">{desc}</div></div>',
            unsafe_allow_html=True,
        )
        if col2.button("Run", key=f"step_{step_id}", width='stretch'):
            with st.spinner(f"Running {label} …"):
                res = run_pipeline_step(step_id)
            st.markdown(
                f"Result: {_status_badge(res.get('status', 'unknown'))}",
                unsafe_allow_html=True,
            )
            if res.get("output"):
                st.code(res["output"], language="text")
            if res.get("error"):
                st.error(res["error"])
