import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_normalized_logs, get_data_sizes
from utils.styles import section_header
from components.ai_chat_widget import hawkins_button


def render_log_statistics():
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        LOG STATISTICS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Aggregate statistics across all normalised web server log entries.
        </p>""",
        unsafe_allow_html=True,
    )

    # ── Hawkins AI button (quick data pre-load for context) ───────────────────
    _logs_quick = get_normalized_logs()
    if _logs_quick:
        _ldf  = pd.DataFrame(_logs_quick)
        _summary_data = {
            "total_log_entries": len(_ldf),
            "unique_ips":    int(_ldf["client_ip"].nunique())    if "client_ip"    in _ldf.columns else 0,
            "unique_paths":  int(_ldf["request_path"].nunique()) if "request_path" in _ldf.columns else 0,
            "top_15_paths":  _ldf["request_path"].value_counts().head(15).to_dict() if "request_path" in _ldf.columns else {},
            "top_15_ips":    _ldf["client_ip"].value_counts().head(15).to_dict()    if "client_ip"    in _ldf.columns else {},
            "method_counts": _ldf["http_method"].value_counts().to_dict()           if "http_method"   in _ldf.columns else {},
            "status_counts": _ldf["status_class"].value_counts().to_dict()          if "status_class"  in _ldf.columns else {},
            "bot_vs_human":  _ldf["is_bot"].value_counts().rename({True: "bot", False: "human"}).to_dict() if "is_bot" in _ldf.columns else {},
        }
    else:
        _summary_data = {"total_log_entries": 0}
    hawkins_button(
        title         = "Log Statistics",
        description   = "Aggregate statistics across all normalised web server log entries — method/status distributions, top paths, top IPs, bot vs human ratio.",
        data_summary  = _summary_data,
        component_key = "log_statistics",
        help_guide    = (
            "Log Statistics shows aggregate metrics across all normalised log entries. "
            "The HTTP Methods pie shows the verb distribution (GET/POST/etc). "
            "The Status Classes pie shows 2xx/3xx/4xx/5xx breakdown. "
            "The Top 15 Requested Paths bar chart reveals the most-targeted endpoints. "
            "The Top 15 Client IPs bar chart shows the most active source IPs — high counts may indicate scanning or automation. "
            "Use the search boxes under each chart to filter the corresponding table. "
            "A high 4xx percentage often correlates with active scanning or brute-force attempts."
        ),
    )

    # ── Data File Sizes ───────────────────────────────────────────────────────
    st.markdown(section_header("Data File Sizes"), unsafe_allow_html=True)
    size_rows = get_data_sizes()
    if size_rows:
        size_df = pd.DataFrame(size_rows)

        # Summary chips — raw log vs total pipeline output
        raw_bytes   = next((r["bytes"] for r in size_rows if "access.log" in r["Path"]), 0)
        total_bytes = sum(r["bytes"] for r in size_rows)

        def _fmt(b):
            if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
            if b >= 1_048_576:     return f"{b/1_048_576:.1f} MB"
            if b >= 1_024:         return f"{b/1_024:.1f} KB"
            return f"{b} B"

        s1, s2, s3 = st.columns(3)
        s1.metric("Raw Log Size",          _fmt(raw_bytes))
        s2.metric("Total Pipeline Data",   _fmt(total_bytes))
        s3.metric("Files Tracked",         len([r for r in size_rows if r["bytes"] > 0]))

        # Bar chart of file sizes (MB)
        chart_df = size_df[size_df["bytes"] > 0].copy()
        chart_df["MB"] = chart_df["bytes"] / 1_048_576
        fig_sz = px.bar(
            chart_df, x="File", y="MB",
            title="Data File Sizes (MB)",
            labels={"MB": "Size (MB)", "File": ""},
            color="MB",
            color_continuous_scale="Purples",
            text=chart_df["Size"],
        )
        fig_sz.update_traces(textposition="outside")
        fig_sz.update_layout(coloraxis_showscale=False, xaxis_tickangle=-20)
        st.plotly_chart(fig_sz, width='stretch')

        # Table
        st.dataframe(
            size_df[["File", "Path", "Size"]],
            width='stretch',
            hide_index=True,
        )
    else:
        st.info("No data files found yet. Run the pipeline first.")

    st.divider()

    # ── Log Entry Statistics ──────────────────────────────────────────────────
    logs = get_normalized_logs()
    if not logs:
        st.warning("No normalised logs found. Run the full pipeline first.")
        return

    df = pd.DataFrame(logs)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Entries",    f"{len(df):,}")
    c2.metric("Unique IPs",       df["client_ip"].nunique()    if "client_ip"    in df.columns else 0)
    c3.metric("Unique Paths",     df["request_path"].nunique() if "request_path" in df.columns else 0)
    c4.metric("Unique UAs",       df["user_agent"].nunique()   if "user_agent"   in df.columns else 0)

    st.divider()

    col_a, col_b = st.columns(2)

    # HTTP Method distribution
    if "http_method" in df.columns:
        with col_a:
            method_counts = df["http_method"].value_counts()
            fig = px.pie(values=method_counts.values, names=method_counts.index,
                         title="HTTP Methods", color_discrete_sequence=px.colors.qualitative.Pastel)
            st.plotly_chart(fig, width='stretch')

    # Status code distribution
    if "status_class" in df.columns:
        with col_b:
            status_counts = df["status_class"].value_counts()
            fig2 = px.pie(values=status_counts.values, names=status_counts.index,
                          title="HTTP Status Classes",
                          color_discrete_map={
                              "2xx": "#2E8B57", "3xx": "#4169E1",
                              "4xx": "#DAA520", "5xx": "#8B0000",
                          })
            st.plotly_chart(fig2, width='stretch')

    # Top requested paths
    if "request_path" in df.columns:
        top_paths = df["request_path"].value_counts().head(15)
        fig3 = px.bar(top_paths, title="Top 15 Requested Paths",
                      labels={"value": "Requests", "index": "Path"},
                      color_discrete_sequence=["#9B59B6"])
        fig3.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig3, width='stretch')

        # Searchable top-paths table
        paths_df = top_paths.reset_index()
        paths_df.columns = ["Path", "Requests"]
        p_search = st.text_input("Search paths", key="logstat_path_search", placeholder="Filter by path…")
        if p_search.strip():
            paths_df = paths_df[paths_df["Path"].str.contains(p_search.strip(), case=False, na=False)]
        st.dataframe(paths_df, width='stretch', hide_index=True)

    # Top IPs
    if "client_ip" in df.columns:
        top_ips = df["client_ip"].value_counts().head(15)
        fig4 = px.bar(top_ips, title="Top 15 Client IPs",
                      labels={"value": "Requests", "index": "IP"},
                      color_discrete_sequence=["#3498DB"])
        st.plotly_chart(fig4, width='stretch')

        # Searchable top-IPs table
        ips_df = top_ips.reset_index()
        ips_df.columns = ["IP", "Requests"]
        ip_search = st.text_input("Search IPs", key="logstat_ip_search", placeholder="Filter by IP…")
        if ip_search.strip():
            ips_df = ips_df[ips_df["IP"].str.contains(ip_search.strip(), case=False, na=False)]
        st.dataframe(ips_df, width='stretch', hide_index=True)

    # Bot vs Human
    if "is_bot" in df.columns:
        bot_counts = df["is_bot"].value_counts().rename({True: "Bot", False: "Human"})
        fig5 = px.pie(values=bot_counts.values, names=bot_counts.index,
                      title="Bot vs Human Traffic",
                      color_discrete_map={"Bot": "#E74C3C", "Human": "#27AE60"})
        st.plotly_chart(fig5, width='stretch')
