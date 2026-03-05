import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from components.ai_chat_widget import hawkins_button

from services.data_service import (
    get_rule_matches,
    get_normalized_logs,
    get_data_sizes,
    get_anomaly_scores,
    get_crs_matches,   # CRS INTEGRATION
    get_crs_stats,     # CRS INTEGRATION
)
from components.rule_based_detection import render_rule_detections_tab, render_crs_detections_tab

_DARK_TEMPLATE = "plotly_dark"
_BG   = "rgba(0,0,0,0)"
_GRID = "#1a1a1a"
_TEXT = "#888888"

_SEV_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#f0c040",
    "low":      "#4488ff",
    "unknown":  "#555555",
}


def _make_fig(fig: go.Figure) -> go.Figure:
    fig.update_layout(
        template=_DARK_TEMPLATE,
        paper_bgcolor=_BG,
        plot_bgcolor=_BG,
        font_color=_TEXT,
        font_family="monospace",
        margin=dict(l=16, r=16, t=32, b=16),
        xaxis=dict(gridcolor=_GRID, zerolinecolor=_GRID),
        yaxis=dict(gridcolor=_GRID, zerolinecolor=_GRID),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font_color=_TEXT,
        ),
    )
    return fig


def _render_charts() -> None:
    rule_data    = get_rule_matches()
    log_data     = get_normalized_logs()
    crs_stats    = get_crs_stats()  # CRS INTEGRATION

    matches  = rule_data.get("matches", [])
    total    = rule_data.get("total_matches", 0)
    rules    = rule_data.get("matched_rules", [])

    # ── Summary metrics ────────────────────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rule Matches",  total)
    c2.metric("Unique Rules",  len(rules))
    c3.metric("Logs Loaded",   len(log_data))
    c4.metric("CRS Matches",   crs_stats.get("total_crs_matches", 0))

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row 1: Severity + Top Rules ────────────────────────────────────
    if matches:
        df_det = pd.DataFrame(matches)
        col_a, col_b = st.columns(2)

        with col_a:
            sev_counts = (
                df_det["severity"].fillna("unknown").str.lower().value_counts().reset_index()
            )
            sev_counts.columns = ["Severity", "Count"]
            colors = [_SEV_COLORS.get(s, "#555") for s in sev_counts["Severity"]]
            fig = px.bar(
                sev_counts, x="Severity", y="Count",
                title="Detections by Severity",
                color="Severity",
                color_discrete_map=_SEV_COLORS,
            )
            st.plotly_chart(_make_fig(fig), width='stretch')

        with col_b:
            top_rules = (
                df_det["rule_title"].fillna("Unknown").value_counts().head(10).reset_index()
            )
            top_rules.columns = ["Rule", "Matches"]
            fig2 = px.bar(
                top_rules, x="Matches", y="Rule", orientation="h",
                title="Top 10 Triggered Rules",
                color_discrete_sequence=["#4a4a4a"],
            )
            fig2.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(_make_fig(fig2), width='stretch')

        # ── Top IPs ────────────────────────────────────────────────────────────
        col_c, col_d = st.columns(2)
        with col_c:
            top_ips = (
                df_det["client_ip"].fillna("unknown").value_counts().head(10).reset_index()
            )
            top_ips.columns = ["IP", "Matches"]
            fig3 = px.bar(
                top_ips, x="Matches", y="IP", orientation="h",
                title="Top 10 Offending IPs",
                color_discrete_sequence=["#3a3a3a"],
            )
            fig3.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(_make_fig(fig3), width='stretch')


    # ── HTTP methods + status codes ────────────────────────────────────────────
    if log_data:
        df_logs = pd.DataFrame(log_data)
        col_g, col_h = st.columns(2)

        if "http_method" in df_logs.columns:
            with col_g:
                method_counts = df_logs["http_method"].value_counts().reset_index()
                method_counts.columns = ["Method", "Count"]
                fig5 = px.pie(
                    method_counts, names="Method", values="Count",
                    title="HTTP Methods",
                    color_discrete_sequence=px.colors.sequential.gray,
                    hole=0.4,
                )
                fig5.update_traces(textfont_color="#888")
                st.plotly_chart(_make_fig(fig5), width='stretch')

        if "status_class" in df_logs.columns:
            with col_h:
                sc_counts = df_logs["status_class"].value_counts().reset_index()
                sc_counts.columns = ["Status Class", "Count"]
                status_colors = {
                    "2xx": "#4a8a4a", "3xx": "#4a4a8a",
                    "4xx": "#8a6a4a", "5xx": "#8a4a4a",
                }
                fig6 = px.pie(
                    sc_counts, names="Status Class", values="Count",
                    title="HTTP Status Classes",
                    color="Status Class",
                    color_discrete_map=status_colors,
                    hole=0.4,
                )
                fig6.update_traces(textfont_color="#888")
                st.plotly_chart(_make_fig(fig6), width='stretch')

        col_i, col_j = st.columns(2)
        if "request_path" in df_logs.columns:
            with col_i:
                top_paths = (
                    df_logs["request_path"].fillna("/").value_counts().head(15).reset_index()
                )
                top_paths.columns = ["Path", "Count"]
                fig7 = px.bar(
                    top_paths, x="Count", y="Path", orientation="h",
                    title="Top 15 Requested Paths",
                    color_discrete_sequence=["#3a3a3a"],
                )
                fig7.update_layout(yaxis=dict(autorange="reversed"))
                st.plotly_chart(_make_fig(fig7), width='stretch')

        if "is_bot" in df_logs.columns:
            with col_j:
                bot_counts = df_logs["is_bot"].map(lambda x: "Bot" if x else "Human").value_counts().reset_index()
                bot_counts.columns = ["Type", "Count"]
                fig8 = px.pie(
                    bot_counts, names="Type", values="Count",
                    title="Bot vs Human Traffic",
                    color_discrete_map={"Bot": "#555", "Human": "#aaa"},
                    hole=0.4,
                )
                fig8.update_traces(textfont_color="#888")
                st.plotly_chart(_make_fig(fig8), width='stretch')

    # ── CRS INTEGRATION: CRS Anomaly Score over Time ───────────────────────────
    crs_rows = get_crs_matches(limit=5000)
    if crs_rows:
        df_crs = pd.DataFrame(crs_rows)
        if "timestamp" in df_crs.columns and "anomaly_score" in df_crs.columns:
            df_crs["timestamp"] = pd.to_datetime(df_crs["timestamp"], errors="coerce")
            df_crs = df_crs.dropna(subset=["timestamp"]).sort_values("timestamp")

            # Colour each point by anomaly score severity
            def _crs_point_colour(score):
                if score >= 5:
                    return "High (≥5)"
                if score >= 2:
                    return "Medium (≥2)"
                return "Low (<2)"

            df_crs["Risk Level"] = df_crs["anomaly_score"].apply(_crs_point_colour)

            fig_crs_time = px.scatter(
                df_crs,
                x="timestamp",
                y="anomaly_score",
                color="Risk Level",
                color_discrete_map={
                    "High (≥5)":   "#ff4b4b",
                    "Medium (≥2)": "#ffa500",
                    "Low (<2)":    "#00cc96",
                },
                hover_data=["client_ip", "rule_id", "uri"] if "uri" in df_crs.columns else ["client_ip", "rule_id"],
                title="CRS Anomaly Score over Time",
                labels={"timestamp": "Time", "anomaly_score": "Anomaly Score"},
            )
            st.plotly_chart(_make_fig(fig_crs_time), width='stretch')

    # ── File sizes ─────────────────────────────────────────────────────────────
    st.markdown(
        """<div style="color:#333; font-size:11px; letter-spacing:1px; text-transform:uppercase; margin:24px 0 8px;">
        DATA FILE SIZES</div>""",
        unsafe_allow_html=True,
    )
    sizes = get_data_sizes()
    df_s = pd.DataFrame([s for s in sizes if s["bytes"] > 0])
    if not df_s.empty:
        fig9 = px.bar(
            df_s.sort_values("bytes", ascending=True),
            x="bytes", y="File", orientation="h",
            title="",
            color_discrete_sequence=["#2a2a2a"],
        )
        fig9.update_xaxes(title="Bytes")
        st.plotly_chart(_make_fig(fig9), width='stretch')

    if sizes:
        df_show = pd.DataFrame([{"File": s["File"], "Size": s["Size"]} for s in sizes])
        st.dataframe(df_show, width='stretch', hide_index=True)


def render_detections_charts() -> None:
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        DETECTIONS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Visualisations and detailed data tables from the last analysis run.
        </p>""",
        unsafe_allow_html=True,
    )

    # ── Hawkins AI button (data loaded inline for context) ────────────────────
    _quick_rule = get_rule_matches()
    _quick_anom = get_anomaly_scores()
    hawkins_button(
        title         = "Detections",
        description   = "Charts and data tables from the last analysis run — rule matches (CRS + YAML), ML anomaly scores, and CRS audit detail.",
        data_summary  = {
            "total_rule_matches":     _quick_rule.get("total_matches", 0),
            "unique_rules_triggered": len(_quick_rule.get("matched_rules", [])),
            "ml_anomaly_count":       sum(1 for e in _quick_anom if e.get("is_anomaly")),
            "severity_breakdown":     pd.DataFrame(_quick_rule.get("matches", []))["severity"].value_counts().to_dict() if _quick_rule.get("matches") else {},
            "top_triggered_rules":    sorted(
                {m.get("rule_title", "?"): 0 for m in _quick_rule.get("matches", [])}.keys()
            )[:10] if _quick_rule.get("matches") else [],
        },
        component_key = "detections",
        help_guide    = (
            "The Detections page has four tabs. "
            "'Overview Charts' shows severity distribution and method breakdown charts. "
            "'Rule Detections' is a searchable table of every OWASP CRS and custom YAML rule match — use the Severity and Method dropdowns to filter. "
            "'Anomaly Scores' shows the Isolation Forest anomaly scores per request — toggle 'Show anomalies only' to focus on flagged entries. "
            "'CRS Detail' shows raw ModSecurity audit log entries with paranoia-level filtering. "
            "Tip: sort the Rule Detections table by Severity to prioritise CRITICAL findings first."
        ),
    )

    tab_charts, tab_rules, tab_crs = st.tabs([
        "Overview Charts",
        "Rule Detections",
        "CRS Detail",
    ])

    with tab_charts:
        _render_charts()

    with tab_rules:
        render_rule_detections_tab()

    with tab_crs:
        render_crs_detections_tab()
