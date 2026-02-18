"""
Rule-Based Detection Page — LOGIC Web Agent Dashboard
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_rule_matches
from utils.api_client import get_threat_insights, get_insights_status


SEVERITY_ORDER  = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_COLORS = {
    "critical": "#8B0000",
    "high":     "#CC5500",
    "medium":   "#DAA520",
    "low":      "#2E8B57",
    "unknown":  "#708090",
}


def render_rule_based_detection():
    st.header("Rule-Based Detection")
    st.caption("YAML detection rules matched against normalised web server logs.")

    data    = get_rule_matches()
    matches = data.get("matches", [])

    if not matches:
        st.info("No rule matches found. Run the rule analysis pipeline step first.")
        return

    df = pd.DataFrame(matches)

    # Summary metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Matches",  data.get("total_matches", 0))
    c2.metric("Unique Rules",   len(data.get("matched_rules", [])))
    c3.metric("Unique IPs",     df["client_ip"].nunique() if "client_ip" in df.columns else 0)

    st.divider()

    # Severity filter
    severities = [s for s in SEVERITY_ORDER if s in df.get("severity", pd.Series()).unique().tolist()]
    selected_sev = st.multiselect("Filter by Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    filtered = df[df["severity"].isin(selected_sev)] if "severity" in df.columns else df

    # Severity bar chart
    if "severity" in filtered.columns:
        sev_counts = filtered["severity"].value_counts().reindex(SEVERITY_ORDER).dropna()
        fig = px.bar(
            sev_counts, title="Matches by Severity",
            color=sev_counts.index,
            color_discrete_map=SEVERITY_COLORS,
            labels={"value": "Count", "index": "Severity"},
        )
        st.plotly_chart(fig, use_container_width=True)

    # Top rules
    if "rule_title" in filtered.columns:
        top_rules = filtered["rule_title"].value_counts().head(10)
        fig2 = px.bar(top_rules, title="Top 10 Triggered Rules",
                      labels={"value": "Count", "index": "Rule"})
        st.plotly_chart(fig2, use_container_width=True)

    # Top IPs
    if "client_ip" in filtered.columns:
        top_ips = filtered["client_ip"].value_counts().head(10)
        fig3 = px.bar(top_ips, title="Top 10 Offending IPs",
                      labels={"value": "Matches", "index": "IP"}, color_discrete_sequence=["#9B59B6"])
        st.plotly_chart(fig3, use_container_width=True)

    st.divider()

    # Detailed table
    st.subheader("Match Details")
    display_cols = [c for c in ["rule_title", "severity", "client_ip", "method",
                                 "path", "status_code", "timestamp"] if c in filtered.columns]
    st.dataframe(filtered[display_cols].head(200), use_container_width=True)

    st.divider()

    # LLM Threat Insights
    st.subheader("🤖 AI Threat Insights (Groq LLM)")
    status_info = get_insights_status()
    st.caption(f"Detection results: {status_info.get('total_matches', 0)} matches available")

    if st.button("Generate Threat Insights"):
        with st.spinner("Analysing with LLM …"):
            result = get_threat_insights()
        if result.get("status") == "success":
            st.markdown(result.get("analysis", ""))
        else:
            st.error(f"LLM error: {result.get('detail') or result.get('error')}")
