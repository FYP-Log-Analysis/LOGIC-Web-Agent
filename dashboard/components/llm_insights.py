"""
LLM Insights Page — LOGIC Web Agent Dashboard
Local LM Studio integration for natural language threat analysis,
mitigation recommendations, and combined rule + anomaly insights.
"""

import streamlit as st
from utils.api_client import (
    get_lm_studio_status,
    get_lm_studio_insights,
    get_lm_studio_anomaly_insights,
    get_lm_studio_rule_insights,
)


# ── Status badge helper ───────────────────────────────────────────────────────

def _status_badge(ok: bool, yes_label: str, no_label: str) -> str:
    if ok:
        return f'<span style="background:#2E8B57;color:white;padding:2px 10px;border-radius:8px;">{yes_label}</span>'
    return f'<span style="background:#8B0000;color:white;padding:2px 10px;border-radius:8px;">{no_label}</span>'


# ── Main renderer ─────────────────────────────────────────────────────────────

def render_llm_insights():
    st.header("🤖 LM Studio — Local LLM Insights")
    st.caption(
        "Sends detection results to a locally running LM Studio instance "
        "(OpenAI-compatible API) for natural language threat analysis and mitigation guidance."
    )

    # ── Connection status ─────────────────────────────────────────────────────
    with st.spinner("Checking LM Studio connection …"):
        status = get_lm_studio_status()

    col1, col2, col3, col4 = st.columns(4)

    reachable    = status.get("reachable", False)
    has_rules    = status.get("rule_data", False)
    has_anomalies = status.get("anomaly_data", False)
    base_url     = status.get("base_url", "http://localhost:1234/v1")
    model        = status.get("model", "local-model")

    col1.markdown(
        f"**LM Studio**<br>{_status_badge(reachable, '● Online', '● Offline')}",
        unsafe_allow_html=True,
    )
    col2.markdown(
        f"**Rule Data**<br>{_status_badge(has_rules, '● Ready', '● Missing')}",
        unsafe_allow_html=True,
    )
    col3.markdown(
        f"**Anomaly Data**<br>{_status_badge(has_anomalies, '● Ready', '● Missing')}",
        unsafe_allow_html=True,
    )
    col4.markdown(
        f"**Model**<br><code>{model}</code>",
        unsafe_allow_html=True,
    )

    if not reachable:
        st.warning(
            f"LM Studio is not reachable at **{base_url}**. "
            "Start LM Studio, load a model, and enable the local server "
            "(Server → Start Server in the LM Studio app). "
            "You can override the URL with the `LM_STUDIO_BASE_URL` environment variable."
        )
        st.stop()

    st.divider()

    # ── Analysis mode tabs ────────────────────────────────────────────────────
    tab_combined, tab_rules, tab_anomalies = st.tabs([
        "🔍 Combined Insights",
        "📋 Rule-Based Analysis",
        "📊 Anomaly Explanation",
    ])

    # ── Combined ──────────────────────────────────────────────────────────────
    with tab_combined:
        st.subheader("Combined Threat Insights + Mitigations")
        st.markdown(
            "Analyses both **rule-based detections** and **ML anomaly scores** together "
            "to produce an executive summary, threat insights, risk rating, and mitigation plan."
        )

        if not has_rules:
            st.info("No rule-match data available. Run the rule analysis pipeline step first.")
        else:
            if not has_anomalies:
                st.info(
                    "Anomaly data not found — only rule matches will be sent. "
                    "Run the ML pipeline step to include anomaly context."
                )

            if st.button("Generate Combined Insights", key="btn_combined", type="primary"):
                with st.spinner("LM Studio is analysing detections… this may take 30–90 s"):
                    result = get_lm_studio_insights()

                if result.get("error"):
                    st.error(f"Request failed: {result['error']}")
                elif result.get("status") == "error":
                    st.error(f"LLM error: {result.get('error_message') or result.get('detail')}")
                else:
                    _render_analysis_result(result)

    # ── Rules only ────────────────────────────────────────────────────────────
    with tab_rules:
        st.subheader("Rule-Based Threat Analysis")
        st.markdown(
            "Focuses exclusively on **YAML rule matches** — attack patterns, severity breakdown, "
            "top offending IPs, and targeted firewall / WAF recommendations."
        )

        if not has_rules:
            st.info("No rule-match data. Run the rule analysis pipeline step first.")
        else:
            if st.button("Analyse Rule Detections", key="btn_rules", type="primary"):
                with st.spinner("LM Studio is analysing rule matches…"):
                    result = get_lm_studio_rule_insights()

                if result.get("error"):
                    st.error(f"Request failed: {result['error']}")
                elif result.get("status") == "error":
                    st.error(f"LLM error: {result.get('error_message') or result.get('detail')}")
                else:
                    _render_analysis_result(result)

    # ── Anomalies only ────────────────────────────────────────────────────────
    with tab_anomalies:
        st.subheader("Anomaly Detection — Natural Language Explanation")
        st.markdown(
            "Takes the **Isolation Forest anomaly scores** and asks the LLM to explain "
            "in plain English what the anomalous requests represent, likely threat types, "
            "and recommended responses."
        )

        if not has_anomalies:
            st.info("No anomaly data. Run the ML (Isolation Forest) pipeline step first.")
        else:
            if st.button("Explain Anomalies", key="btn_anomalies", type="primary"):
                with st.spinner("LM Studio is interpreting anomaly scores…"):
                    result = get_lm_studio_anomaly_insights()

                if result.get("error"):
                    st.error(f"Request failed: {result['error']}")
                elif result.get("status") == "error":
                    st.error(f"LLM error: {result.get('error_message') or result.get('detail')}")
                else:
                    # Show anomaly counts
                    c1, c2 = st.columns(2)
                    c1.metric("Total Entries",  result.get("total_entries", "–"))
                    c2.metric("Anomalies Found", result.get("total_anomalies", "–"))
                    st.divider()
                    _render_analysis_result(result)

    # ── Configuration help ────────────────────────────────────────────────────
    with st.expander("⚙️ LM Studio Configuration", expanded=False):
        st.markdown(f"""
**Current settings**

| Setting | Value |
|---------|-------|
| Base URL | `{base_url}` |
| Model | `{model}` |

**Override with environment variables** before starting the API server:

```bash
export LM_STUDIO_BASE_URL=http://localhost:1234/v1
export LM_STUDIO_MODEL=your-model-name
```

**LM Studio setup steps:**
1. Download and install [LM Studio](https://lmstudio.ai)
2. Load a model (e.g. *Llama 3*, *Mistral*, *Phi-3*)
3. Navigate to the **Local Server** tab and click **Start Server**
4. The server starts on `http://localhost:1234` by default
5. Restart the LOGIC API server so it picks up any changed env vars
        """)


# ── Shared result renderer ────────────────────────────────────────────────────

def _render_analysis_result(result: dict):
    """Render LLM output with metadata footer."""
    analysis = result.get("analysis", "")
    if not analysis:
        st.warning("LLM returned an empty response.")
        return

    # Detection summary chips (present in combined / rule analyses)
    summary = result.get("detection_summary")
    if summary:
        c1, c2, c3 = st.columns(3)
        c1.metric("Rule Matches",    summary.get("total_rule_matches", "–"))
        c2.metric("Unique Rules",    summary.get("unique_rules", "–"))
        c3.metric("Anomalies",       summary.get("total_anomalies", "–"))
        st.divider()

    st.markdown(analysis)

    # Footer
    st.divider()
    st.caption(
        f"Generated by **{result.get('model', 'local-model')}** "
        f"via LM Studio · Backend: `{result.get('backend', 'lm_studio')}`"
    )
