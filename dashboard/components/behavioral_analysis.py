"""
Behavioral Traffic Analysis Dashboard Component
================================================
Detects:
  1. Request-rate spikes       — high req/min from a single IP (DDoS, brute-force)
  2. URL enumeration/scanning  — many distinct paths hit by one IP in a short window
  3. Status-code spikes        — windows where 4xx/5xx dominate traffic
  4. Visitor-rate anomalies    — unusual low/high unique-visitor counts per hour (slow attacks)
"""
from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Any

from utils.api_client import run_behavioral_analysis, get_behavioral_results, api_health
from components.ai_chat_widget import hawkins_button


# ── Helpers ────────────────────────────────────────────────────────────────────

def _dark_chart(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#888",
        font_family="monospace",
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=16, r=16, t=36, b=16),
    )
    fig.update_xaxes(gridcolor="#1a1a1a", zeroline=False)
    fig.update_yaxes(gridcolor="#1a1a1a", zeroline=False)
    return fig


def _search_filter(df: pd.DataFrame, key: str, label: str = "Search table") -> pd.DataFrame:
    """Add a free-text search input that filters any string-matching rows."""
    query = st.text_input(label, value="", key=key)
    if query.strip():
        mask = df.apply(
            lambda row: query.strip().lower() in " ".join(row.astype(str).values).lower(),
            axis=1,
        )
        return df[mask]
    return df


def _col_filter(df: pd.DataFrame, col: str, label: str, key: str, all_label: str = "All") -> pd.DataFrame:
    """Selectbox filter for a categorical column."""
    if col not in df.columns:
        return df
    opts = [all_label] + sorted(df[col].dropna().unique().tolist())
    sel = st.selectbox(label, opts, key=key)
    if sel != all_label:
        return df[df[col] == sel]
    return df


# ── Tab renderers ─────────────────────────────────────────────────────────────

def _render_rate_spikes(data: dict) -> None:
    rows = data.get("request_rate_spikes", [])
    thresholds = data.get("thresholds", {})

    if not rows:
        st.info(
            "No request-rate spikes detected with current thresholds. "
            f"Threshold: **{thresholds.get('rate_threshold', 60)} req / "
            f"{thresholds.get('rate_window_minutes', 1)} min**."
        )
        return

    df = pd.DataFrame(rows)

    c1, c2, c3 = st.columns(3)
    c1.metric("Spike Windows",    len(df))
    c2.metric("Unique IPs",       df["client_ip"].nunique())
    c3.metric("Max Req / Window", int(df["request_count"].max()))

    st.divider()

    # Top offending IPs bar chart
    top_ips = df.groupby("client_ip")["request_count"].max().sort_values(ascending=False).head(15)
    fig = px.bar(
        top_ips, title="Top IPs by Peak Request Count",
        labels={"value": "Peak req/window", "index": "IP"},
        color=top_ips.values,
        color_continuous_scale="Reds",
        template="plotly_dark",
    )
    fig.update_layout(coloraxis_showscale=False)
    st.plotly_chart(_dark_chart(fig), width='stretch')

    # Timeline scatter: all spike windows coloured by IP
    df["window_dt"] = pd.to_datetime(df["window_start"], errors="coerce")
    if df["window_dt"].notna().any():
        fig2 = px.scatter(
            df, x="window_dt", y="request_count", color="client_ip",
            title="Request-Rate Spike Timeline",
            labels={"window_dt": "Window Start", "request_count": "Requests"},
            template="plotly_dark",
            size="request_count",
            size_max=20,
        )
        st.plotly_chart(_dark_chart(fig2), width='stretch')

    st.divider()
    st.subheader("Spike Details")

    filt_df = _search_filter(df.drop(columns=["window_dt"], errors="ignore"), key="rate_search")
    display_cols = [c for c in ["client_ip", "window_start", "request_count", "window_minutes", "threshold_used"] if c in filt_df.columns]
    st.dataframe(filt_df[display_cols].sort_values("request_count", ascending=False), width='stretch', hide_index=True)


def _render_url_enumeration(data: dict) -> None:
    rows = data.get("url_enumeration", [])
    thresholds = data.get("thresholds", {})

    if not rows:
        st.info(
            "No URL enumeration detected. "
            f"Threshold: **{thresholds.get('enum_threshold', 50)} distinct paths / "
            f"{thresholds.get('enum_window_hours', 1)} hour**."
        )
        return

    df = pd.DataFrame(rows)

    c1, c2, c3 = st.columns(3)
    c1.metric("Enumeration Alerts",  len(df))
    c2.metric("Unique Scanning IPs", df["client_ip"].nunique())
    c3.metric("Max Distinct Paths",  int(df["distinct_paths"].max()))

    st.divider()

    # Top scanners
    top = df.groupby("client_ip")["distinct_paths"].max().sort_values(ascending=False).head(15)
    fig = px.bar(
        top, title="Top IPs by Distinct Paths Scanned",
        labels={"value": "Max distinct paths", "index": "IP"},
        color=top.values,
        color_continuous_scale="Oranges",
        template="plotly_dark",
    )
    fig.update_layout(coloraxis_showscale=False)
    st.plotly_chart(_dark_chart(fig), width='stretch')

    st.divider()
    st.subheader("Enumeration Details")

    filt_df = df.copy()

    # Expand sample_paths to a readable string
    if "sample_paths" in filt_df.columns:
        filt_df["sample_paths"] = filt_df["sample_paths"].apply(
            lambda x: " | ".join(x) if isinstance(x, list) else str(x)
        )

    filt_df = _search_filter(filt_df, key="enum_search")
    display_cols = [c for c in ["client_ip", "window_start", "distinct_paths", "total_requests", "sample_paths", "threshold_used"] if c in filt_df.columns]
    st.dataframe(filt_df[display_cols].sort_values("distinct_paths", ascending=False), width='stretch', hide_index=True)


def _render_status_spikes(data: dict) -> None:
    rows = data.get("status_code_spikes", [])
    thresholds = data.get("thresholds", {})

    if not rows:
        st.info(
            "No status-code spike windows detected. "
            f"Threshold: **{int(thresholds.get('status_error_ratio', 0.5)*100)}% error ratio** over "
            f"{thresholds.get('status_window_minutes', 5)}-minute windows."
        )
        return

    df = pd.DataFrame(rows)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Spike Windows",       len(df))
    c2.metric("Total Error Reqs",    int(df["error_count"].sum()))
    c3.metric("Max Error Ratio",     f"{df['error_ratio'].max()*100:.1f}%")
    c4.metric("Max Requests/Window", int(df["total_requests"].max()))

    st.divider()

    # Timeline: error ratio over time
    df["window_dt"] = pd.to_datetime(df["window_start"], errors="coerce")
    if df["window_dt"].notna().any():
        fig = px.area(
            df.sort_values("window_dt"), x="window_dt", y="error_ratio",
            title="Error Ratio Over Time (spike windows only)",
            labels={"window_dt": "Window Start", "error_ratio": "Error Ratio"},
            template="plotly_dark",
            color_discrete_sequence=["#e05050"],
        )
        fig.add_hline(
            y=thresholds.get("status_error_ratio", 0.5),
            line_dash="dot", line_color="#aaa",
            annotation_text=f"Threshold {thresholds.get('status_error_ratio', 0.5):.0%}",
        )
        st.plotly_chart(_dark_chart(fig), width='stretch')

    st.divider()
    st.subheader("Status-Spike Details")

    display_df = df.drop(columns=["window_dt"], errors="ignore").copy()
    if "top_status_codes" in display_df.columns:
        display_df["top_status_codes"] = display_df["top_status_codes"].apply(
            lambda x: ", ".join(f"{k}:{v}" for k, v in x.items()) if isinstance(x, dict) else str(x)
        )
    display_df["error_ratio"] = (display_df["error_ratio"] * 100).round(1).astype(str) + "%"

    filt_df = _search_filter(display_df, key="status_search")
    display_cols = [c for c in ["window_start", "total_requests", "error_count", "error_ratio", "top_status_codes", "window_minutes"] if c in filt_df.columns]
    st.dataframe(filt_df[display_cols].sort_values("error_count", ascending=False), width='stretch', hide_index=True)


def _render_visitor_rates(data: dict) -> None:
    rows = data.get("visitor_rates", [])
    thresholds = data.get("thresholds", {})

    if not rows:
        st.info("No visitor-rate data. Run behavioral analysis after uploading log files.")
        return

    df = pd.DataFrame(rows)
    df["hour_dt"] = pd.to_datetime(df["hour"], errors="coerce")

    flagged    = df[df["flag"].isin(["high_visitor_rate", "low_visitor_rate"])]
    normal     = df[df["flag"] == "normal"]

    c1, c2, c3 = st.columns(3)
    c1.metric("Hours Analysed",      len(df))
    c2.metric("Anomalous Hours",     len(flagged))
    c3.metric("Z-Score Threshold",   f"±{thresholds.get('visitor_zscore', 2.0)}")

    st.divider()

    # Visitor rate timeline with anomalies highlighted
    if df["hour_dt"].notna().any():
        mean_v = df["mean_visitors"].dropna().iloc[0] if "mean_visitors" in df.columns and df["mean_visitors"].notna().any() else None
        std_v  = df["std_visitors"].dropna().iloc[0]  if "std_visitors"  in df.columns and df["std_visitors"].notna().any()  else None

        fig = go.Figure()
        # Normal hours
        norm_df = df[df["flag"] == "normal"]
        if not norm_df.empty:
            fig.add_trace(go.Scatter(
                x=norm_df["hour_dt"], y=norm_df["unique_visitors"],
                mode="lines+markers", name="Normal",
                line=dict(color="#4caf50", width=1),
                marker=dict(size=5),
            ))
        # Flagged hours
        if not flagged.empty:
            fig.add_trace(go.Scatter(
                x=flagged["hour_dt"], y=flagged["unique_visitors"],
                mode="markers", name="Anomalous",
                marker=dict(color="#ff4444", size=10, symbol="x"),
            ))
        # Mean line
        if mean_v is not None:
            fig.add_hline(y=mean_v, line_dash="dash", line_color="#aaa",
                          annotation_text=f"Mean: {mean_v:.0f}")
        if mean_v is not None and std_v is not None:
            z = thresholds.get("visitor_zscore", 2.0)
            fig.add_hrect(
                y0=mean_v - z * std_v, y1=mean_v + z * std_v,
                fillcolor="rgba(100,100,255,0.05)", line_width=0,
                annotation_text="Normal band",
            )
        fig.update_layout(
            title="Unique Visitors per Hour",
            xaxis_title="Hour", yaxis_title="Unique Visitors",
            template="plotly_dark",
        )
        st.plotly_chart(_dark_chart(fig), width='stretch')

    st.divider()
    st.subheader("Visitor Rate Details")

    display_df = df.drop(columns=["hour_dt"], errors="ignore").copy()
    if "z_score" in display_df.columns:
        display_df["z_score"] = display_df["z_score"].apply(
            lambda v: f"{v:+.3f}" if v is not None else "—"
        )

    # Flag filter
    col_f1, col_f2 = st.columns([2, 3])
    with col_f1:
        flag_opts = ["All"] + sorted(display_df["flag"].dropna().unique().tolist())
        flag_sel  = st.selectbox("Filter by Flag", flag_opts, key="visitor_flag_filter")
        if flag_sel != "All":
            display_df = display_df[display_df["flag"] == flag_sel]

    with col_f2:
        filt_df = _search_filter(display_df, key="visitor_search")

    display_cols = [c for c in ["hour", "unique_visitors", "total_requests", "mean_visitors", "std_visitors", "z_score", "flag"] if c in filt_df.columns]
    st.dataframe(filt_df[display_cols], width='stretch', hide_index=True)


# ── Settings panel ─────────────────────────────────────────────────────────────

def _render_settings() -> dict:
    """Render threshold configuration expander and return the selected values."""
    with st.expander("Threshold Configuration", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            rate_window = st.number_input("Rate window (minutes)", min_value=1, max_value=60, value=1, step=1, key="beh_rate_win")
            rate_thresh = st.number_input("Rate threshold (req/window)", min_value=1, max_value=10000, value=60, step=10, key="beh_rate_thr")
            enum_window = st.number_input("Enum window (hours)", min_value=1, max_value=24, value=1, step=1, key="beh_enum_win")
            enum_thresh = st.number_input("Enum threshold (distinct paths)", min_value=1, max_value=5000, value=50, step=10, key="beh_enum_thr")
        with c2:
            status_window = st.number_input("Status window (minutes)", min_value=1, max_value=60, value=5, step=1, key="beh_stat_win")
            status_ratio  = st.slider("Status error ratio threshold", min_value=0.1, max_value=1.0, value=0.5, step=0.05, key="beh_stat_ratio")
            visitor_z     = st.slider("Visitor z-score threshold", min_value=1.0, max_value=5.0, value=2.0, step=0.5, key="beh_vis_z")
    return {
        "rate_window_minutes":   int(rate_window),
        "rate_threshold":        int(rate_thresh),
        "enum_window_hours":     int(enum_window),
        "enum_threshold":        int(enum_thresh),
        "status_window_minutes": int(status_window),
        "status_error_ratio":    float(status_ratio),
        "visitor_zscore":        float(visitor_z),
    }


# ── Main entry point ──────────────────────────────────────────────────────────

def render_behavioral_analysis() -> None:
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        BEHAVIORAL ANALYSIS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Detects high request-rate spikes, URL enumeration/scanning, status-code anomalies, and
        unusual visitor volumes — effective against slow &amp; low-volume attacks.
        </p>""",
        unsafe_allow_html=True,
    )

    if not api_health():
        st.warning("API is offline — cannot run behavioral analysis.")
        return

    # ── Configure thresholds + run button ──────────────────────────────────────
    settings = _render_settings()

    col_run, col_status = st.columns([2, 5])
    with col_run:
        run_btn = st.button("Run Behavioral Analysis", width='stretch')

    if run_btn:
        with st.spinner("Analysing traffic patterns …"):
            resp = run_behavioral_analysis(**settings)
        if resp.get("status") == "complete":
            summary = resp.get("summary", {})
            st.success(
                f"Complete — "
                f"{summary.get('total_rate_spike_windows', 0)} rate spikes · "
                f"{summary.get('total_enumeration_alerts', 0)} enum alerts · "
                f"{summary.get('total_status_spike_windows', 0)} status spikes · "
                f"{summary.get('total_visitor_anomaly_hours', 0)} visitor anomalies"
            )
            st.session_state["behavioral_data"] = get_behavioral_results()
        else:
            st.error(f"Error: {resp.get('detail') or resp.get('error', 'Unknown error')}")

    # ── Load cached / last results ─────────────────────────────────────────────
    if "behavioral_data" not in st.session_state:
        data = get_behavioral_results()
        if not data or "error" in data:
            st.info(
                "No behavioral analysis results yet. "
                "Configure thresholds above and click **Run Behavioral Analysis**."
            )
            return
        st.session_state["behavioral_data"] = data

    data: dict[str, Any] = st.session_state["behavioral_data"]

    generated_at = data.get("generated_at", "unknown")
    st.caption(f"Results generated: {generated_at}")

    # ── Summary metrics across all detections ──────────────────────────────────
    summary = data.get("summary", {})

    # ── Hawkins AI button ──────────────────────────────────────────────────────
    _top_spikes = sorted(
        data.get("request_rate_spikes", []),
        key=lambda r: r.get("request_count", 0), reverse=True
    )[:5]
    hawkins_button(
        title         = "Behavioral Traffic Analysis",
        description   = "Detects request-rate spikes, URL enumeration/scanning, status-code anomalies, and unusual visitor-volume patterns.",
        data_summary  = {
            "generated_at":              generated_at,
            "rate_spike_windows":         summary.get("total_rate_spike_windows", 0),
            "url_enumeration_alerts":     summary.get("total_enumeration_alerts", 0),
            "status_spike_windows":       summary.get("total_status_spike_windows", 0),
            "visitor_anomaly_hours":      summary.get("total_visitor_anomaly_hours", 0),
            "top_rate_spike_ips":         [{"ip": r.get("client_ip"), "reqs": r.get("request_count"), "window": r.get("window_start")} for r in _top_spikes],
            "thresholds":                 data.get("thresholds", {}),
        },
        component_key = "behavioral",
        help_guide    = (
            "Behavioral Analysis has four tabs. "
            "'Request Rate Spikes' flags IPs that exceed the req/min threshold — typical indicators of brute-force, credential stuffing, or DDoS. "
            "'URL Enumeration' flags IPs scanning large numbers of distinct paths in a short window — indicators of directory traversal or recon. "
            "'Status Code Spikes' highlights time windows with abnormally high 4xx/5xx ratios — may indicate scanning, fuzzing, or broken attack automation. "
            "'Visitor Rate Anomalies' uses z-score analysis to flag hours with statistically unusual unique-visitor counts — useful for detecting slow or low-volume attacks. "
            "Adjust thresholds using the settings expander at the top before clicking Run."
        ),
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Rate Spike Windows",    summary.get("total_rate_spike_windows", 0),    help="Windows where a single IP exceeded the request-rate threshold")
    m2.metric("URL Enum Alerts",       summary.get("total_enumeration_alerts", 0),    help="IP+hour combos where distinct path count exceeded the enumeration threshold")
    m3.metric("Status Spike Windows",  summary.get("total_status_spike_windows", 0),  help="Time windows where error ratio exceeded the status threshold")
    m4.metric("Visitor Anomaly Hours", summary.get("total_visitor_anomaly_hours", 0), help="Hours with statistically unusual unique visitor counts (z-score based)")

    st.divider()

    # ── Four tabs ──────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "Request Rate Spikes",
        "URL Enumeration",
        "Status Code Spikes",
        "Visitor Rate Anomalies",
    ])

    with tab1:
        _render_rate_spikes(data)
    with tab2:
        _render_url_enumeration(data)
    with tab3:
        _render_status_spikes(data)
    with tab4:
        _render_visitor_rates(data)
