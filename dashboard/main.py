"""
LOGIC Web Agent Dashboard — Main Entry Point
"""

import streamlit as st
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from components.overview            import render_overview
from components.anomaly_analysis    import render_anomaly_analysis
from components.rule_based_detection import render_rule_based_detection
from components.log_statistics      import render_log_statistics
from components.pipeline_control    import render_pipeline_control
from components.llm_insights        import render_llm_insights

st.set_page_config(
    page_title="LOGIC Web Agent",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.main-header { font-size:2.2rem; color:#9B59B6; text-align:center; margin-bottom:0.5rem; }
.stButton > button {
    background-color:#9B59B6; color:white; border:1px solid #8E44AD;
}
.stButton > button:hover { background-color:#8E44AD; }
</style>
""", unsafe_allow_html=True)

NAV_OPTIONS = [
    "Overview",
    "Anomaly Analysis",
    "Rule Based Detection",
    "Log Statistics",
    "Pipeline Control",
    "LLM Insights",
]

st.markdown('<h1 class="main-header">🌐 LOGIC Web Agent</h1>', unsafe_allow_html=True)
st.markdown(
    '<p style="text-align:center;color:#666;margin-bottom:1.5rem;">'
    'Web Server Log Analysis &amp; Threat Detection</p>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Navigation")
    if "page" not in st.session_state:
        st.session_state.page = "Overview"
    for opt in NAV_OPTIONS:
        if st.button(opt, key=f"nav_{opt}", use_container_width=True):
            st.session_state.page = opt

page = st.session_state.get("page", "Overview")

if page == "Overview":
    render_overview()
elif page == "Anomaly Analysis":
    render_anomaly_analysis()
elif page == "Rule Based Detection":
    render_rule_based_detection()
elif page == "Log Statistics":
    render_log_statistics()
elif page == "Pipeline Control":
    render_pipeline_control()
elif page == "LLM Insights":
    render_llm_insights()
