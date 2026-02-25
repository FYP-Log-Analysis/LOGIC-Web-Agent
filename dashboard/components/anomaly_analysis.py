import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_anomaly_scores


def _render_anomaly_body() -> None:
    """Core anomaly analysis content — no page header."""
    scored = get_anomaly_scores()
    if not scored:
        st.warning("No anomaly scores found. Run the ML analysis pipeline step first.")
        return

    df = pd.DataFrame(scored)
    required = {"anomaly_score", "is_anomaly"}
    if not required.issubset(df.columns):
        st.error("Anomaly score data is missing expected columns.")
        return

    anomalies = df[df["is_anomaly"] == True]
    normal    = df[df["is_anomaly"] == False]

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Entries",  f"{len(df):,}")
    c2.metric("Anomalies",      f"{len(anomalies):,}")
    c3.metric("Normal",         f"{len(normal):,}")

    st.divider()

    # Score distribution
    fig = px.histogram(
        df, x="anomaly_score", color="is_anomaly",
        nbins=50, title="Anomaly Score Distribution",
        color_discrete_map={True: "#8E44AD", False: "#3498DB"},
        labels={"anomaly_score": "Anomaly Score (0 = normal, 1 = most anomalous)", "is_anomaly": "Anomaly"},
    )
    st.plotly_chart(fig, use_container_width=True)

    # Top anomalies table
    if not anomalies.empty:
        st.subheader("Top Anomalous Requests")
        display_cols = [c for c in ["timestamp", "client_ip", "http_method", "request_path",
                                     "status_code", "anomaly_score"] if c in anomalies.columns]
        tbl_df = anomalies[display_cols].sort_values("anomaly_score", ascending=False).copy()

        # ── Search & column filters ────────────────────────────────────────────
        a_col1, a_col2, a_col3 = st.columns([3, 2, 2])
        with a_col1:
            a_search = st.text_input("🔍 Search table", key="ano_tbl_search", placeholder="IP, path, status…")
        with a_col2:
            if "http_method" in tbl_df.columns:
                m_opts = ["All"] + sorted(tbl_df["http_method"].dropna().unique().tolist())
                m_sel  = st.selectbox("Method", m_opts, key="ano_method_filter")
                if m_sel != "All":
                    tbl_df = tbl_df[tbl_df["http_method"] == m_sel]
        with a_col3:
            if "status_code" in tbl_df.columns:
                sc_opts = ["All"] + sorted(tbl_df["status_code"].dropna().astype(str).unique().tolist())
                sc_sel  = st.selectbox("Status Code", sc_opts, key="ano_sc_filter")
                if sc_sel != "All":
                    tbl_df = tbl_df[tbl_df["status_code"].astype(str) == sc_sel]
        if a_search.strip():
            q = a_search.strip().lower()
            tbl_df = tbl_df[tbl_df.apply(lambda row: q in " ".join(row.astype(str).values).lower(), axis=1)]

        st.caption(f"Showing {len(tbl_df):,} of {len(anomalies):,} anomalous requests")
        st.dataframe(tbl_df.head(500), use_container_width=True, hide_index=True)


def render_anomaly_analysis():
    """Standalone page render — includes page heading."""
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        ANOMALY ANALYSIS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        ML-based anomaly detection using Isolation Forest on normalised log features.
        </p>""",
        unsafe_allow_html=True,
    )
    _render_anomaly_body()


def render_anomaly_tab():
    """Thin wrapper for embedding inside another page's tab (no page heading)."""
    st.caption("ML-based anomaly detection using Isolation Forest on normalised log features.")
    _render_anomaly_body()
