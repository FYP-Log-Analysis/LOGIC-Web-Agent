import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from components.upload             import render_upload
from components.overview           import render_overview
from components.analysis           import render_analysis
from components.detections_charts  import render_detections_charts
from components.ai_insights        import render_ai_insights
from components.behavioral_analysis import render_behavioral_analysis
from components.log_statistics     import render_log_statistics
from components.pipeline_control   import render_pipeline_control
from components.login              import render_login
from components.projects           import render_projects
from components.admin              import render_admin

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

# ── Auth gate ────────────────────────────────────────────────────────────────
if not st.session_state.get("authenticated"):
    render_login()
    st.stop()


# Set the landing page based on role (only on first load after login)
if "page" not in st.session_state:
    _initial_role = st.session_state.get("role", "analyst")
    st.session_state["page"] = "Admin" if _initial_role == "admin" else "Overview"

NAV = [
    ("Overview",             "Overview"),
    ("Upload",               "Upload"),
    ("Projects",             "Projects"),
    ("Analysis",             "Analysis"),
    ("Detections",           "Detections"),
    ("Behavioral Analysis",  "Behavioral Analysis"),
    ("Log Statistics",       "Log Statistics"),
    ("AI Insights",          "AI Insights"),
    ("Pipeline",             "Pipeline"),
    ("Admin",                "Admin"),
]

# Pages only visible to analysts (and legacy 'user' role)
_NAV_ANALYST_ONLY = {
    "Overview", "Upload", "Projects", "Analysis", "Detections",
    "Behavioral Analysis", "Log Statistics", "AI Insights", "Pipeline",
}
# Pages only visible to admins
_NAV_ADMIN_ONLY   = {"Admin"}


with st.sidebar:
    # ── Branding ──────────────────────────────────────────────────────────
    st.markdown(
        '<div style="padding:20px 12px 28px 12px; border-bottom:1px solid #1a1a1a; margin-bottom:20px;">'
        '<div style="font-size:15px; letter-spacing:4px; color:#e0e0e0; font-weight:300;">LOGIC</div>'
        '<div style="font-size:9px; letter-spacing:3px; color:#333; margin-top:4px; text-transform:uppercase;">'
        'Web Agent &middot; Security Analysis</div></div>',
        unsafe_allow_html=True,
    )

    # ── User badge ────────────────────────────────────────────────────────
    _uname  = st.session_state.get("username", "user")
    _role   = st.session_state.get("role", "analyst")
    _aproj  = st.session_state.get("active_project_name", "")
    # admin=purple, analyst=blue, legacy user=slate
    _role_color = (
        "#6b46c1" if _role == "admin"
        else "#1d4ed8" if _role == "analyst"
        else "#334155"
    )
    st.markdown(
        f'<div style="background:#111; border:1px solid #1e1e1e; border-radius:4px; '
        f'padding:10px 14px; margin-bottom:16px;">'
        f'<div style="font-size:12px; color:#c0c0c0; letter-spacing:0.5px;">{_uname}</div>'
        f'<div style="margin-top:3px;"><span style="background:{_role_color}; color:#fff; '
        f'font-size:8px; letter-spacing:2px; text-transform:uppercase; border-radius:2px; '
        f'padding:1px 6px;">{_role}</span></div>'
        + (f'<div style="font-size:10px; color:#444; margin-top:5px; letter-spacing:0.5px;">'
           f'▸ {_aproj}</div>' if _aproj else '')
        + '</div>',
        unsafe_allow_html=True,
    )

    # ── Nav links ─────────────────────────────────────────────────────────
    for key, label in NAV:
        # Admins see ONLY the Admin page; all analyst pages are hidden from them
        if key in _NAV_ANALYST_ONLY and _role == "admin":
            continue
        # Non-admins never see the Admin page
        if key in _NAV_ADMIN_ONLY and _role != "admin":
            continue
        # Separator before "Pipeline"
        if key == "Pipeline":
            st.markdown(
                '<div style="border-top:1px solid #141414; margin:12px 0 10px 0;'
                'font-size:9px; letter-spacing:2px; color:#222; text-transform:uppercase; padding-top:10px;">'
                'CONTROL</div>',
                unsafe_allow_html=True,
            )
        if st.button(label, key="nav_" + key, width='stretch'):
            st.session_state["page"] = key
            st.rerun()

    # ── Logout ────────────────────────────────────────────────────────────
    st.markdown('<div style="border-top:1px solid #141414; margin-top:16px; padding-top:14px;"></div>',
                unsafe_allow_html=True)
    if st.button("Sign Out", key="nav_logout", width='stretch'):
        for _k in ["authenticated", "token", "username", "role", "user_id", "email",
                   "active_project_id", "active_project_name", "page"]:
            st.session_state.pop(_k, None)
        st.rerun()

    st.markdown(
        '<div style="padding-top:20px;">'
        '<div style="font-size:9px; letter-spacing:2px; color:#222; text-transform:uppercase;">Version 2.0</div>'
        '</div>',
        unsafe_allow_html=True,
    )


page = st.session_state.get("page", "Overview")

# ── Routing-layer role guard (second line of defence) ──────────────────────────────
_current_role = st.session_state.get("role", "analyst")
_ANALYST_PAGES = {
    "Overview", "Upload", "Projects", "Analysis", "Detections",
    "Behavioral Analysis", "Log Statistics", "AI Insights", "Pipeline",
}

if page in _ANALYST_PAGES and _current_role == "admin":
    st.error("Admin accounts cannot access forensics pages. Use the Admin panel.")
    st.stop()
elif page == "Admin" and _current_role not in ("admin",):
    st.error("This page requires admin access.")
    st.stop()

if   page == "Overview":             render_overview()
elif page == "Upload":               render_upload()
elif page == "Projects":             render_projects()
elif page == "Analysis":             render_analysis()
elif page == "Detections":           render_detections_charts()
elif page == "Behavioral Analysis":  render_behavioral_analysis()
elif page == "Log Statistics":       render_log_statistics()
elif page == "AI Insights":          render_ai_insights()
elif page == "Pipeline":             render_pipeline_control()
elif page == "Admin":                render_admin()
