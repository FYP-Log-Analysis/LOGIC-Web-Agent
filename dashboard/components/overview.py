import streamlit as st
from services.data_service import get_rule_matches, get_anomaly_scores, get_normalized_logs
from utils.api_client import api_health


def render_overview():
    st.header("Overview")

    # API status
    healthy = api_health()
    status_color = "🟢" if healthy else "🔴"
    st.markdown(f"**API Status:** {status_color} {'Online' if healthy else 'Offline'}")

    st.divider()

    rule_data    = get_rule_matches()
    anomaly_data = get_anomaly_scores()
    norm_logs    = get_normalized_logs()

    total_events  = len(norm_logs)
    total_matches = rule_data.get("total_matches", 0)
    unique_rules  = len(rule_data.get("matched_rules", []))
    anomaly_count = sum(1 for e in anomaly_data if e.get("is_anomaly"))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Log Entries", f"{total_events:,}")
    c2.metric("Rule Matches",      f"{total_matches:,}")
    c3.metric("Unique Rules Hit",  unique_rules)
    c4.metric("ML Anomalies",      f"{anomaly_count:,}")

    st.divider()

    # Recent high/critical matches
    matches = rule_data.get("matches", [])
    high_matches = [m for m in matches if m.get("severity", "").lower() in {"critical", "high"}]

    if high_matches:
        st.subheader(f"⚠️ High / Critical Alerts  ({len(high_matches)})")
        for match in high_matches[:10]:
            sev = match.get("severity", "").upper()
            color = "#8B0000" if sev == "CRITICAL" else "#CC5500"
            st.markdown(
                f"""<div style="background:{color};color:white;padding:8px 12px;
                border-radius:5px;margin:4px 0;font-size:0.9em;">
                <b>[{sev}]</b> {match.get('rule_title')} &nbsp;|&nbsp;
                IP: {match.get('client_ip', 'N/A')} &nbsp;|&nbsp;
                {match.get('method', '')} {match.get('path', '')} &nbsp;|&nbsp;
                {match.get('timestamp', '')}
                </div>""",
                unsafe_allow_html=True,
            )
    else:
        st.info("No high or critical alerts detected. Run the pipeline to analyse logs.")
