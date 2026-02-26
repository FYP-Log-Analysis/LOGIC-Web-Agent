"""
admin.py — Admin panel (admin role only).

Features:
- Stats: total users + total projects
- Create analyst account (username + password)
- List all accounts with activate / deactivate / delete actions
"""
import streamlit as st
from utils.api_client import (
    admin_list_users,
    admin_set_user_active,
    admin_delete_user,
    admin_create_analyst,
    admin_stats,
)
from utils.styles import section_header, hr, status_dot


def _render_stats() -> None:
    stats = admin_stats()
    if "error" in stats:
        st.error(f"Could not load stats: {stats['error']}")
        return
    c1, c2 = st.columns(2)
    c1.metric("Total Users",    stats.get("total_users",    "—"))
    c2.metric("Total Projects", stats.get("total_projects", "—"))


def _render_create_analyst() -> None:
    st.markdown(section_header("Create Analyst Account"), unsafe_allow_html=True)
    with st.form("form_create_analyst", clear_on_submit=True):
        new_username = st.text_input("Username", placeholder="analyst_username", key="ca_user")
        new_password = st.text_input("Password", type="password", placeholder="min 8 chars", key="ca_pass")
        submitted = st.form_submit_button("Create Account", width='stretch')
        if submitted:
            if not new_username or not new_password:
                st.warning("Both fields are required.")
            elif len(new_password) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                result = admin_create_analyst(new_username.strip(), new_password)
                if "error" in result:
                    st.error(f"Failed: {result['error']}")
                else:
                    st.success(f"Analyst account '{new_username.strip()}' created.")
                    st.rerun()


def _render_users() -> None:
    st.markdown(section_header("All Accounts"), unsafe_allow_html=True)
    users = admin_list_users()
    if not users:
        st.info("No accounts found.")
        return

    current_uid = st.session_state.get("user_id", -1)

    for u in users:
        uid     = u.get("id", 0)
        uname   = u.get("username", "?")
        role    = u.get("role", "analyst")
        active  = bool(u.get("is_active", 1))
        is_self = uid == current_uid

        role_color = "#6b46c1" if role == "admin" else "#1d4ed8"
        self_tag = (
            ' <span style="background:#1a3a1a;color:#4caf50;font-size:9px;'
            'letter-spacing:1.5px;border-radius:2px;padding:1px 6px;'
            'text-transform:uppercase;">YOU</span>' if is_self else ""
        )

        st.markdown(
            f'<div style="background:#0d0d0d; border:1px solid #1a1a1a; border-radius:4px; '
            f'padding:12px 16px; margin-bottom:6px;">'
            f'<span style="color:#c0c0c0; font-size:13px;">{status_dot(active)}{uname}</span>'
            f'<span style="background:{role_color}; color:#fff; font-size:8px; letter-spacing:1.5px; '
            f'border-radius:2px; padding:1px 6px; text-transform:uppercase; '
            f'margin-left:10px;">{role}</span>'
            f'{self_tag}</div>',
            unsafe_allow_html=True,
        )

        if not is_self:
            c1, c2, c3, _ = st.columns([1, 1, 1, 3])
            with c1:
                toggle_label = "Deactivate" if active else "Activate"
                if st.button(toggle_label, key=f"usr_toggle_{uid}", width='stretch'):
                    res = admin_set_user_active(uid, not active)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.rerun()
            with c2:
                if st.button("Delete", key=f"usr_del_{uid}", width='stretch'):
                    st.session_state[f"del_confirm_{uid}"] = True
            with c3:
                if st.session_state.get(f"del_confirm_{uid}"):
                    if st.button("Confirm", key=f"usr_del_conf_{uid}", width='stretch'):
                        res = admin_delete_user(uid)
                        st.session_state.pop(f"del_confirm_{uid}", None)
                        if "error" in res:
                            st.error(res["error"])
                        else:
                            st.rerun()


def render_admin() -> None:
    if st.session_state.get("role") != "admin":
        st.error("Admin access required.")
        return

    st.markdown(
        '<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">'
        'ADMIN PANEL</h2>'
        '<p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">'
        'User management — create, activate / deactivate, and delete analyst accounts.</p>',
        unsafe_allow_html=True,
    )

    with st.spinner("Loading stats…"):
        _render_stats()

    st.markdown(hr(), unsafe_allow_html=True)

    _render_create_analyst()

    st.markdown(hr(), unsafe_allow_html=True)

    _render_users()
