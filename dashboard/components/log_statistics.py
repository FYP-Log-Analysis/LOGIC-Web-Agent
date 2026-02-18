"""
Log Statistics Page — LOGIC Web Agent Dashboard
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from services.data_service import get_normalized_logs


def render_log_statistics():
    st.header("Log Statistics")
    st.caption("Aggregate statistics across all normalised web server log entries.")

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
            st.plotly_chart(fig, use_container_width=True)

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
            st.plotly_chart(fig2, use_container_width=True)

    # Top requested paths
    if "request_path" in df.columns:
        top_paths = df["request_path"].value_counts().head(15)
        fig3 = px.bar(top_paths, title="Top 15 Requested Paths",
                      labels={"value": "Requests", "index": "Path"},
                      color_discrete_sequence=["#9B59B6"])
        fig3.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig3, use_container_width=True)

    # Top IPs
    if "client_ip" in df.columns:
        top_ips = df["client_ip"].value_counts().head(15)
        fig4 = px.bar(top_ips, title="Top 15 Client IPs",
                      labels={"value": "Requests", "index": "IP"},
                      color_discrete_sequence=["#3498DB"])
        st.plotly_chart(fig4, use_container_width=True)

    # Bot vs Human
    if "is_bot" in df.columns:
        bot_counts = df["is_bot"].value_counts().rename({True: "Bot", False: "Human"})
        fig5 = px.pie(values=bot_counts.values, names=bot_counts.index,
                      title="Bot vs Human Traffic",
                      color_discrete_map={"Bot": "#E74C3C", "Human": "#27AE60"})
        st.plotly_chart(fig5, use_container_width=True)
