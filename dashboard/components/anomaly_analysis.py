"""
Anomaly Analysis Page — LOGIC Web Agent Dashboard
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_anomaly_scores


def render_anomaly_analysis():
    st.header("Anomaly Analysis")
    st.caption("ML-based anomaly detection using Isolation Forest on normalised log features.")

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
        st.subheader(f"Top Anomalous Requests  (showing up to 50)")
        display_cols = [c for c in ["timestamp", "client_ip", "http_method", "request_path",
                                     "status_code", "anomaly_score"] if c in anomalies.columns]
        st.dataframe(
            anomalies[display_cols].sort_values("anomaly_score", ascending=False).head(50),
            use_container_width=True,
        )
