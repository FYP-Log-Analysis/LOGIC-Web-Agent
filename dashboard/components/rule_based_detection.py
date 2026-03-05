import json

import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_rule_matches, get_crs_matches, get_crs_stats
from utils.analysis_client import get_threat_insights, get_insights_status
from components.ai_chat_widget import hawkins_button


SEVERITY_ORDER  = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_COLORS = {
    "critical": "#8B0000",
    "high":     "#CC5500",
    "medium":   "#DAA520",
    "low":      "#2E8B57",
    "unknown":  "#708090",
}

# CRS INTEGRATION: Anomaly score colour thresholds
_CRS_RED    = "#ff4b4b"   # score >= 5
_CRS_ORANGE = "#ffa500"   # score >= 2
_CRS_GREEN  = "#00cc96"   # score < 2


def _score_colour(score: float) -> str:
    if score >= 5:
        return _CRS_RED
    if score >= 2:
        return _CRS_ORANGE
    return _CRS_GREEN


def _render_custom_rules() -> None:
    st.caption(
        "Detections from the OWASP ModSecurity CRS engine "
        "(CRS rules prefixed with **[CRS]**) and supplementary custom YAML rules."
    )

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
        st.plotly_chart(fig, width='stretch')

    # Top rules
    if "rule_title" in filtered.columns:
        top_rules = filtered["rule_title"].value_counts().head(10)
        fig2 = px.bar(top_rules, title="Top 10 Triggered Rules",
                      labels={"value": "Count", "index": "Rule"})
        st.plotly_chart(fig2, width='stretch')

    # Top IPs
    if "client_ip" in filtered.columns:
        top_ips = filtered["client_ip"].value_counts().head(10)
        fig3 = px.bar(top_ips, title="Top 10 Offending IPs",
                      labels={"value": "Matches", "index": "IP"},
                      color_discrete_sequence=["#9B59B6"])
        st.plotly_chart(fig3, width='stretch')

    st.divider()

    # Detailed table
    st.subheader("Match Details")
    display_cols = [c for c in ["rule_title", "severity", "client_ip", "method",
                                 "path", "status_code", "timestamp"] if c in filtered.columns]
    tbl_df = filtered[display_cols].copy()

    # ── Table search & column filters ─────────────────────────────────────────
    sf_col1, sf_col2, sf_col3 = st.columns([3, 2, 2])
    with sf_col1:
        tbl_search = st.text_input("Search table", key="rule_tbl_search", placeholder="IP, path, rule…")
    with sf_col2:
        if "severity" in tbl_df.columns:
            sev_opts = ["All"] + sorted(tbl_df["severity"].dropna().unique().tolist())
            sev_sel  = st.selectbox("Severity", sev_opts, key="rule_tbl_sev")
            if sev_sel != "All":
                tbl_df = tbl_df[tbl_df["severity"] == sev_sel]
    with sf_col3:
        if "method" in tbl_df.columns:
            meth_opts = ["All"] + sorted(tbl_df["method"].dropna().unique().tolist())
            meth_sel  = st.selectbox("Method", meth_opts, key="rule_tbl_method")
            if meth_sel != "All":
                tbl_df = tbl_df[tbl_df["method"] == meth_sel]
    if tbl_search.strip():
        q = tbl_search.strip().lower()
        tbl_df = tbl_df[tbl_df.apply(lambda row: q in " ".join(row.astype(str).values).lower(), axis=1)]

    st.caption(f"Showing {len(tbl_df):,} of {len(filtered):,} matches")
    st.dataframe(tbl_df.head(500), width='stretch', hide_index=True)

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


def _render_crs_detections() -> None:
    st.caption(
        "Raw CRS match details from the SQLite **crs_matches** table — "
        "rule ID, anomaly score, tags, and paranoia level for every CRS hit."
    )

    stats = get_crs_stats()
    total = stats.get("total_crs_matches", 0)

    if total == 0:
        st.info(
            "No CRS matches found yet. Run the pipeline with the crs-detector service "
            "running (`docker compose up crs-detector`) to populate this tab."
        )
        return

    # ── Summary metrics ────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CRS Matches",      total)
    c2.metric("Unique Rules",     stats.get("unique_crs_rules", 0))
    c3.metric("Unique IPs",       stats.get("unique_crs_ips", 0))
    c4.metric("Max Anomaly Score", f"{stats.get('max_anomaly_score', 0):.1f}")

    st.divider()

    # ── Load data ──────────────────────────────────────────────────────────────
    rows = get_crs_matches(limit=5000)
    df   = pd.DataFrame(rows)
    if df.empty:
        st.warning("CRS match data unavailable.")
        return

    # ── Filters ────────────────────────────────────────────────────────────────
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        ip_filter = st.text_input("Filter by IP", value="", key="crs_ip_filter")
    with col_f2:
        min_score = st.slider(
            "Minimum Anomaly Score",
            min_value=0.0,
            max_value=float(df["anomaly_score"].max()) if "anomaly_score" in df.columns else 10.0,
            value=0.0,
            step=0.5,
            key="crs_score_filter",
        )

    df_f = df.copy()
    if ip_filter:
        df_f = df_f[df_f["client_ip"].str.contains(ip_filter, na=False)]
    if "anomaly_score" in df_f.columns:
        df_f = df_f[df_f["anomaly_score"] >= min_score]

    # ── Charts ─────────────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        if "anomaly_score" in df_f.columns:
            fig_hist = px.histogram(
                df_f, x="anomaly_score",
                title="CRS Anomaly Score Distribution",
                nbins=30,
                color_discrete_sequence=["#e05050"],
                template="plotly_dark",
            )
            fig_hist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#888",
                font_family="monospace",
                margin=dict(l=16, r=16, t=32, b=16),
            )
            st.plotly_chart(fig_hist, width='stretch')

    with col_b:
        if "rule_id" in df_f.columns:
            top_rules = df_f["rule_id"].value_counts().head(10).reset_index()
            top_rules.columns = ["Rule ID", "Matches"]
            fig_rules = px.bar(
                top_rules, x="Matches", y="Rule ID", orientation="h",
                title="Top 10 CRS Rules Triggered",
                color_discrete_sequence=["#4a4a8a"],
                template="plotly_dark",
            )
            fig_rules.update_layout(
                yaxis=dict(autorange="reversed"),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#888",
                font_family="monospace",
                margin=dict(l=16, r=16, t=32, b=16),
            )
            st.plotly_chart(fig_rules, width='stretch')

    st.divider()

    # ── Colour-coded detail table ──────────────────────────────────────────────
    st.subheader(f"CRS Match Details ({len(df_f):,} rows)")

    display_cols = [c for c in [
        "timestamp", "client_ip", "method", "uri",
        "rule_id", "message", "anomaly_score", "tags", "paranoia_level",
    ] if c in df_f.columns]

    df_display = df_f[display_cols].copy()

    # Decode tags from JSON string to a readable list
    if "tags" in df_display.columns:
        def _fmt_tags(t):
            try:
                lst = json.loads(t) if isinstance(t, str) else (t or [])
                return ", ".join(lst) if isinstance(lst, list) else str(lst)
            except Exception:
                return str(t)
        df_display["tags"] = df_display["tags"].apply(_fmt_tags)

    # ── Table search & column filters ─────────────────────────────────────────
    crs_s1, crs_s2, crs_s3 = st.columns([3, 2, 2])
    with crs_s1:
        crs_search = st.text_input("Search CRS table", key="crs_tbl_search", placeholder="IP, rule ID, message…")
    with crs_s2:
        if "method" in df_display.columns:
            cm_opts = ["All"] + sorted(df_display["method"].dropna().unique().tolist())
            cm_sel  = st.selectbox("Method", cm_opts, key="crs_method_filter")
            if cm_sel != "All":
                df_display = df_display[df_display["method"] == cm_sel]
    with crs_s3:
        if "paranoia_level" in df_display.columns:
            pl_opts = ["All"] + sorted(df_display["paranoia_level"].dropna().astype(str).unique().tolist())
            pl_sel  = st.selectbox("Paranoia Level", pl_opts, key="crs_pl_filter")
            if pl_sel != "All":
                df_display = df_display[df_display["paranoia_level"].astype(str) == pl_sel]
    if crs_search.strip():
        q = crs_search.strip().lower()
        df_display = df_display[df_display.apply(lambda row: q in " ".join(row.astype(str).values).lower(), axis=1)]

    st.caption(f"Showing {len(df_display):,} of {len(df_f):,} CRS matches")

    # Colour-code rows using Pandas Styler based on anomaly_score
    def _row_style(row):
        if "anomaly_score" not in row.index:
            return [""] * len(row)
        score = row["anomaly_score"]
        colour = _score_colour(float(score) if score is not None else 0)
        return [f"color: {colour}"] * len(row)

    styled = df_display.head(500).style.apply(_row_style, axis=1)
    st.dataframe(styled, width='stretch', hide_index=True)

    st.caption(
        "High: anomaly score ≥ 5   "
        "Medium: score ≥ 2   "
        "Low: score < 2"
    )


def render_rule_based_detection():
    st.header("Rule-Based Detection")

    # CRS INTEGRATION: split into two tabs — all detections (CRS+YAML merged) and CRS detail
    tab_yaml, tab_crs = st.tabs(["Rule Detections (CRS + YAML)", "CRS Detail"])

    with tab_yaml:
        _render_custom_rules()

    with tab_crs:
        _render_crs_detections()


# ── Public thin wrappers used when embedding inside another page's tabs ────────

def render_rule_detections_tab():
    """Render only the custom-rules detection panel (no surrounding tabs)."""
    _rq = get_rule_matches()
    _rm = _rq.get("matches", [])
    _sev = {}
    if _rm:
        import pandas as _pd
        _sev = _pd.DataFrame(_rm)["severity"].str.lower().value_counts().to_dict() if "severity" in _pd.DataFrame(_rm).columns else {}
    hawkins_button(
        title         = "Rule-Based Detections",
        description   = "Table of OWASP CRS and custom YAML rule matches from the last analysis run.",
        data_summary  = {
            "total_matches":    _rq.get("total_matches", 0),
            "unique_rules":     len(_rq.get("matched_rules", [])),
            "severity_counts":  _sev,
            "sample_matches":   [{"rule": m.get("rule_title"), "ip": m.get("client_ip"), "severity": m.get("severity"), "method": m.get("method"), "path": m.get("path")} for m in _rm[:10]],
        },
        component_key = "rule_detections",
        help_guide    = (
            "This table shows every rule match from the OWASP CRS and custom YAML rules. "
            "Use the free-text search to filter by IP, rule title, or path. "
            "The Severity dropdown narrows to CRITICAL/HIGH/MEDIUM/LOW. "
            "The Method dropdown filters by HTTP verb. "
            "Rules prefixed with [CRS] are ModSecurity Core Rule Set matches; others are custom YAML rules. "
            "For a deeper dive into a specific rule ID, ask Hawkins to explain what it detects and how attackers typically trigger it."
        ),
    )
    _render_custom_rules()


def render_crs_detections_tab():
    """Render only the CRS detail panel (no surrounding tabs)."""
    _render_crs_detections()
