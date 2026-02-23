"""
LOGIC Web Agent Dashboard
Modern black/white metallic design - 4-page navigation
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from components.upload            import render_upload
from components.analysis          import render_analysis
from components.detections_charts import render_detections_charts
from components.ai_insights       import render_ai_insights

st.set_page_config(
    page_title="LOGIC Web Agent",
    page_icon="*",
    layout="wide",
    initial_sidebar_state="expanded",
)

_CSS = """
<style>
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080808 !important;
    color: #c0c0c0;
    font-family: 'SF Mono','Fira Code','Consolas',monospace;
}
[data-testid="stMain"] { background-color: #080808 !important; }
[data-testid="stSidebar"] {
    background-color: #0d0d0d !important;
    border-right: 1px solid #1e1e1e !important;
}
[data-testid="stSidebar"] * {
    font-family: 'SF Mono','Fira Code','Consolas',monospace !important;
}
[data-testid="stButton"] > button {
    background: #111 !important;
    border: 1px solid #404040 !important;
    color: #c0c0c0 !important;
    border-radius: 2px !important;
    font-size: 11px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    padding: 8px 16px !important;
    font-family: 'SF Mono','Fira Code','Consolas',monospace !important;
    transition: all 0.15s ease !important;
}
[data-testid="stButton"] > button:hover {
    border-color: #c0c0c0 !important;
    color: #ffffff !important;
    background: #1a1a1a !important;
}
[data-testid="stMetric"] {
    background: #111 !important;
    border: 1px solid #1e1e1e !important;
    border-radius: 4px !important;
    padding: 16px !important;
}
[data-testid="stMetricValue"] {
    color: #e8e8e8 !important;
    font-size: 28px !important;
    font-weight: 300 !important;
}
[data-testid="stMetricLabel"] {
    color: #555 !important;
    font-size: 10px !important;
    letter-spacing: 1.2px !important;
    text-transform: uppercase !important;
}
[data-testid="stDataFrame"] {
    border: 1px solid #1e1e1e !important;
    border-radius: 4px !important;
}
[data-testid="stFileUploader"] {
    background: #0d0d0d !important;
    border: 1px dashed #2a2a2a !important;
    border-radius: 4px !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    background: transparent !important;
    border-bottom: 1px solid #1a1a1a !important;
    color: #555 !important;
    font-size: 11px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
}
[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
    border-bottom: 2px solid #808080 !important;
    color: #e0e0e0 !important;
}
[data-testid="stRadio"] label { color: #888 !important; font-size: 12px !important; }
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #0d0d0d; }
::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: #404040; }
#MainMenu { visibility: hidden; }
footer    { visibility: hidden; }
header    { visibility: hidden; }
</style>
"""

st.markdown(_CSS, unsafe_allow_html=True)

# ── Session state
if "page" not in st.session_state:
    st.session_state["page"] = "Upload"

NAV = [
    ("Upload",              "Upload"),
    ("Analysis",            "Analysis"),
    ("Detections & Charts", "Detections & Charts"),
    ("AI Insights",         "AI Insights"),
]

# ── Sidebar
with st.sidebar:
    st.markdown(
        '<div style="padding:20px 12px 28px 12px; border-bottom:1px solid #1a1a1a; margin-bottom:20px;">'
        '<div style="font-size:15px; letter-spacing:4px; color:#e0e0e0; font-weight:300;">LOGIC</div>'
        '<div style="font-size:9px; letter-spacing:3px; color:#333; margin-top:4px; text-transform:uppercase;">'
        'Web Agent &middot; Security Analysis</div></div>',
        unsafe_allow_html=True,
    )
    for key, label in NAV:
        if st.button(label, key="nav_" + key, use_container_width=True):
            st.session_state["page"] = key
            st.rerun()
    st.markdown(
        '<div style="padding-top:40px;"><div style="border-top:1px solid #141414; padding-top:12px;">'
        '<div style="font-size:9px; letter-spacing:2px; color:#222; text-transform:uppercase;">Version 2.0</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )

# ── Page dispatch
page = st.session_state.get("page", "Upload")

if   page == "Upload":              render_upload()
elif page == "Analysis":            render_analysis()
elif page == "Detections & Charts": render_detections_charts()
elif page == "AI Insights":         render_ai_insights()
