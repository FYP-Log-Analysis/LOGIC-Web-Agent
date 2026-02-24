import streamlit as st
from utils.api_client import get_pipeline_steps, run_pipeline, run_pipeline_step, api_health

STEP_LABELS = {
    "ingestion":     "1 · Log Ingestion",
    "parsing":       "2 · Log Parsing",
    "ml_analysis":   "3 · ML Anomaly Detection",
    "normalization": "4 · Normalization",
    "rule_analysis": "5 · Rule Detection",
}


def _status_badge(status: str) -> str:
    color = {"success": "#27AE60", "failed": "#C0392B", "error": "#C0392B",
             "timeout": "#E67E22"}.get(status, "#7F8C8D")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:10px;font-size:0.8em;">{status.upper()}</span>'


def render_pipeline_control():
    st.header("Pipeline Control")
    st.caption("Trigger individual pipeline steps or run the full pipeline end-to-end.")

    # API health
    healthy = api_health()
    st.markdown(f"**API:** {'🟢 Online' if healthy else '🔴 Offline — check API container'}")

    if not healthy:
        st.warning("Cannot run pipeline — API is unreachable.")
        return

    st.divider()

    # Full pipeline button
    if st.button("▶ Run Full Pipeline", type="primary", use_container_width=True):
        with st.spinner("Running full pipeline … this may take a few minutes."):
            result = run_pipeline()

        st.subheader("Pipeline Results")
        status = result.get("status", "unknown")
        st.markdown(f"Overall status: {_status_badge(status)}", unsafe_allow_html=True)

        for step_result in result.get("results", []):
            with st.expander(f"{step_result.get('step_name', step_result.get('step_id'))}"):
                st.markdown(
                    f"Status: {_status_badge(step_result.get('status', ''))}",
                    unsafe_allow_html=True,
                )
                if step_result.get("output"):
                    st.code(step_result["output"], language="text")
                if step_result.get("error"):
                    st.error(step_result["error"])

    st.divider()

    # Individual steps
    st.subheader("Run Individual Steps")
    steps_info = get_pipeline_steps().get("steps", {})
    step_ids   = sorted(steps_info.keys(),
                        key=lambda x: steps_info[x].get("order", 99))

    for step_id in step_ids:
        meta = steps_info[step_id]
        label = STEP_LABELS.get(step_id, meta.get("name", step_id))
        col1, col2 = st.columns([3, 1])
        col1.markdown(f"**{label}**  \n_{meta.get('description', '')}_")
        if col2.button("Run", key=f"step_{step_id}"):
            with st.spinner(f"Running {label} …"):
                res = run_pipeline_step(step_id)
            st.markdown(
                f"Result: {_status_badge(res.get('status', ''))}",
                unsafe_allow_html=True,
            )
            if res.get("output"):
                st.code(res["output"], language="text")
            if res.get("error"):
                st.error(res["error"])
