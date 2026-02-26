import streamlit as st
from services.data_service import get_rule_matches, get_anomaly_scores, get_normalized_logs
from utils.api_client import api_health
from utils.styles import api_status_line
from components.ai_chat_widget import hawkins_button


def render_overview():
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        OVERVIEW</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Security posture at a glance — latest detection results across all analysis engines.
        </p>""",
        unsafe_allow_html=True,
    )

    # ── API status ─────────────────────────────────────────────────────────────
    healthy = api_health()
    st.markdown(api_status_line(healthy), unsafe_allow_html=True)

    # ── Summary metrics ────────────────────────────────────────────────────────
    rule_data    = get_rule_matches()
    anomaly_data = get_anomaly_scores()
    norm_logs    = get_normalized_logs()

    total_events  = len(norm_logs)
    total_matches = rule_data.get("total_matches", 0)
    unique_rules  = len(rule_data.get("matched_rules", []))
    anomaly_count = sum(1 for e in anomaly_data if e.get("is_anomaly"))
    matches       = rule_data.get("matches", [])
    top_ips_raw   = {}
    if matches:
        import pandas as _pd
        _df = _pd.DataFrame(matches)
        if "client_ip" in _df.columns:
            top_ips_raw = _df["client_ip"].value_counts().head(8).to_dict()

    hawkins_button(
        title         = "Security Overview",
        description   = "High-level security posture dashboard — rule matches, ML anomalies, and high/critical alert feed from the last analysis run.",
        data_summary  = {
            "total_log_entries":        total_events,
            "total_rule_matches":        total_matches,
            "unique_rules_triggered":    unique_rules,
            "ml_anomaly_count":          anomaly_count,
            "high_critical_alert_count": len([m for m in matches if m.get("severity", "").lower() in {"critical", "high"}]),
            "top_offending_ips":         top_ips_raw,
            "recent_high_critical":      [{"rule": m.get("rule_title"), "ip": m.get("client_ip"), "severity": m.get("severity"), "ts": m.get("timestamp")} for m in matches if m.get("severity", "").lower() in {"critical", "high"}][:10],
        },
        component_key = "overview",
        help_guide    = (
            "The Security Overview is your starting point. "
            "The four KPI cards show total log entries ingested, total rule matches, number of unique rules triggered, and ML anomaly count. "
            "The alert feed below highlights only HIGH and CRITICAL severity matches — these require immediate attention. "
            "The two charts show severity breakdown and top offending IPs. "
            "Navigate to Detections for full rule/anomaly tables, Behavioral Analysis for traffic-pattern threats, or AI Insights for Groq LLM threat summaries."
        ),
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Log Entries",   f"{total_events:,}")
    c2.metric("Rule Matches",  f"{total_matches:,}")
    c3.metric("Unique Rules",  unique_rules)
    c4.metric("ML Anomalies",  f"{anomaly_count:,}")

    st.divider()

    # ── High / Critical alert feed ─────────────────────────────────────────────
    matches      = rule_data.get("matches", [])
    high_matches = [m for m in matches if m.get("severity", "").lower() in {"critical", "high"}]

    if high_matches:
        st.markdown(
            '<div style="color:#cc4444; font-size:11px; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:12px;">'
            f'HIGH / CRITICAL ALERTS  ({len(high_matches)})</div>',
            unsafe_allow_html=True,
        )
        for match in high_matches[:15]:
            sev   = match.get("severity", "").upper()
            color = "#8B0000" if sev == "CRITICAL" else "#7a3300"
            bd    = "#cc0000" if sev == "CRITICAL" else "#cc5500"
            st.markdown(
                f"""<div style="background:{color}22; border:1px solid {bd}44;
                border-left: 3px solid {bd}; color:#ccc; padding:8px 14px;
                border-radius:2px; margin:4px 0; font-size:12px; font-family:monospace;">
                <span style="color:{bd}; font-size:10px; letter-spacing:1px;">[{sev}]</span>
                &nbsp; {match.get('rule_title', '—')}
                &nbsp;&nbsp;<span style="color:#555;">IP:</span> {match.get('client_ip', '—')}
                &nbsp;&nbsp;<span style="color:#555;">{match.get('method', '')} {match.get('path', '')}</span>
                &nbsp;&nbsp;<span style="color:#444; font-size:10px;">{match.get('timestamp', '')}</span>
                </div>""",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="background:#0a0f0a; border:1px solid #1a3a1a; border-radius:4px; '
            'padding:16px 20px; color:#2E8B57; font-size:13px; letter-spacing:0.5px;">'
            'No high or critical alerts detected in the last analysis run.</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # ── Severity breakdown ─────────────────────────────────────────────────────
    if matches:
        import pandas as pd
        import plotly.express as px

        df = pd.DataFrame(matches)
        if "severity" in df.columns:
            sev_map = {"critical": "#ff4444", "high": "#ff8800", "medium": "#f0c040",
                       "low": "#4488ff", "unknown": "#555555"}
            sev_counts = df["severity"].str.lower().fillna("unknown").value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]

            col_chart, col_top = st.columns(2)
            with col_chart:
                fig = px.bar(
                    sev_counts, x="Severity", y="Count",
                    title="Matches by Severity",
                    color="Severity",
                    color_discrete_map=sev_map,
                    template="plotly_dark",
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#888",
                    font_family="monospace",
                    margin=dict(l=16, r=16, t=32, b=16),
                    showlegend=False,
                )
                st.plotly_chart(fig, width='stretch')

            with col_top:
                if "client_ip" in df.columns:
                    top_ips = df["client_ip"].value_counts().head(8).reset_index()
                    top_ips.columns = ["IP", "Hits"]
                    fig2 = px.bar(
                        top_ips, x="Hits", y="IP", orientation="h",
                        title="Top 8 Offending IPs",
                        color_discrete_sequence=["#3a3a6a"],
                        template="plotly_dark",
                    )
                    fig2.update_layout(
                        yaxis=dict(autorange="reversed"),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#888",
                        font_family="monospace",
                        margin=dict(l=16, r=16, t=32, b=16),
                    )
                    st.plotly_chart(fig2, width='stretch')
