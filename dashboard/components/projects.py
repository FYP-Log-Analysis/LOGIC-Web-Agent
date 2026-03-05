"""
projects.py — Project management page.

Lets users create new analysis projects, view existing ones,
set an active project (stored in session state), and delete them.
"""
import streamlit as st
from utils.data_client import (
    create_project,
    get_projects,
    delete_project,
)
from components.upload import render_inline_upload


def _project_card(proj: dict) -> None:
    """Render a single project card with stats + actions."""
    pid    = proj["id"]
    name   = proj.get("name", "Unnamed")
    desc   = proj.get("description") or ""
    status = proj.get("status", "idle")
    last   = proj.get("last_run_at") or "—"
    active = st.session_state.get("active_project_id") == pid

    border_color = "#6b46c1" if active else "#1e1e1e"
    label_tag    = (
        '<span style="background:#6b46c1;color:#fff;font-size:9px;'
        'letter-spacing:1.5px;border-radius:2px;padding:2px 7px;'
        'text-transform:uppercase;margin-left:8px;">ACTIVE</span>'
        if active else ""
    )

    st.markdown(
        f"""
        <div style="background:#0d0d0d; border:1px solid {border_color}; border-radius:5px;
                    padding:18px 20px; margin-bottom:12px;">
            <div style="font-size:14px; color:#e0e0e0; letter-spacing:1px; font-weight:300;">
                {name}{label_tag}
            </div>
            <div style="font-size:11px; color:#555; margin-top:4px; letter-spacing:0.5px;">
                {desc if desc else '&nbsp;'}
            </div>
            <div style="font-size:10px; color:#333; margin-top:10px; letter-spacing:1px;
                        text-transform:uppercase;">
                STATUS: {status} &nbsp;·&nbsp; LAST RUN: {last}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 3])
    with btn_col1:
        if not active:
            if st.button("Set Active", key=f"set_{pid}", width='stretch'):
                st.session_state["active_project_id"]   = pid
                st.session_state["active_project_name"] = name
                st.success(f"Active project: **{name}**")
                st.rerun()
        else:
            if st.button("Deactivate", key=f"deact_{pid}", width='stretch'):
                st.session_state.pop("active_project_id", None)
                st.session_state.pop("active_project_name", None)
                st.rerun()
    with btn_col2:
        if st.button("Delete", key=f"del_{pid}", width='stretch'):
            st.session_state[f"confirm_del_{pid}"] = True

    # Confirmation guard
    if st.session_state.get(f"confirm_del_{pid}"):
        st.warning(f"Delete **{name}** and all its data? This cannot be undone.")
        cc1, cc2 = st.columns(2)
        with cc1:
            if st.button("Confirm Delete", key=f"confdel_{pid}", width='stretch'):
                result = delete_project(pid)
                if "error" in result:
                    st.error(f"Delete failed: {result['error']}")
                else:
                    if st.session_state.get("active_project_id") == pid:
                        st.session_state.pop("active_project_id", None)
                        st.session_state.pop("active_project_name", None)
                    st.session_state.pop(f"confirm_del_{pid}", None)
                    st.rerun()
        with cc2:
            if st.button("Cancel", key=f"cancel_del_{pid}", width='stretch'):
                st.session_state.pop(f"confirm_del_{pid}", None)
                st.rerun()

    # Inline upload — available on every project card
    with st.expander("Upload Logs", expanded=False):
        render_inline_upload(pid, name)


def render_projects() -> None:
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        PROJECTS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Create and manage analysis projects. Each project has isolated log storage and results.
        </p>""",
        unsafe_allow_html=True,
    )

    # ── Create new project ────────────────────────────────────────────────
    with st.expander("New Project", expanded=False):
        with st.form("form_new_project", clear_on_submit=True):
            proj_name = st.text_input("Project Name", placeholder="e.g. Prod Server Q3")
            proj_desc = st.text_area("Description (optional)", placeholder="Brief note about this project",
                                     height=80)
            created = st.form_submit_button("Create Project", width='stretch')
            if created:
                if not proj_name.strip():
                    st.warning("Project name is required.")
                else:
                    with st.spinner("Creating project…"):
                        result = create_project(proj_name.strip(), proj_desc.strip())
                    if "error" in result:
                        st.error(f"Failed: {result['error']}")
                    else:
                        pid  = result.get("id") or result.get("project_id", "")
                        name = result.get("name", proj_name)
                        st.session_state["active_project_id"]   = pid
                        st.session_state["active_project_name"] = name
                        st.rerun()

    st.markdown('<div style="margin-top:16px;"></div>', unsafe_allow_html=True)

    # ── Active project banner ────────────────────────────────────────────
    active_id   = st.session_state.get("active_project_id")
    active_name = st.session_state.get("active_project_name", "")
    if active_id:
        st.markdown(
            f'<div style="background:#1a0d2e; border:1px solid #6b46c1; border-radius:4px; '
            f'padding:10px 16px; margin-bottom:20px; font-size:12px; color:#a78bfa; '
            f'letter-spacing:1px;">ACTIVE PROJECT: {active_name} '
            f'<span style="color:#555">({active_id[:8]}…)</span></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="background:#111; border:1px dashed #2a2a2a; border-radius:4px; '
            'padding:10px 16px; margin-bottom:20px; font-size:12px; color:#444; letter-spacing:1px;">'
            'No active project — analyses will run against global log store</div>',
            unsafe_allow_html=True,
        )

    # ── Project list ─────────────────────────────────────────────────────
    with st.spinner("Loading projects…"):
        projects = get_projects()

    if not projects:
        st.markdown(
            '<div style="border:1px dashed #2a2a2a; border-radius:4px; padding:40px; '
            'text-align:center; color:#444; font-size:13px; letter-spacing:0.8px;">'
            'NO PROJECTS YET — CREATE ONE ABOVE</div>',
            unsafe_allow_html=True,
        )
        return

    for proj in projects:
        _project_card(proj)


def render_project_selector() -> None:
    """
    Full-screen project picker shown once per login for analyst users.

    - If projects exist: display clickable project cards to set one active.
    - If no projects exist: show a minimal create-project form.
    - Either path has a "Skip" option that clears the pending flag and proceeds.
    """
    st.markdown(
        """
        <div style="max-width:640px; margin:80px auto 0 auto;">
        <div style="font-size:22px; color:#e0e0e0; font-weight:300; letter-spacing:3px;
                    margin-bottom:6px;">SELECT A PROJECT</div>
        <div style="font-size:12px; color:#555; letter-spacing:0.5px; margin-bottom:32px;">
        Choose a project to work in, or create a new one to get started.
        </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.spinner("Loading projects…"):
        projects = get_projects()

    if projects:
        for proj in projects:
            pid    = proj["id"]
            name   = proj.get("name", "Unnamed")
            desc   = proj.get("description") or ""
            status = proj.get("status", "idle")
            last   = proj.get("last_run_at") or "—"

            col_info, col_btn = st.columns([5, 1])
            with col_info:
                st.markdown(
                    f"""
                    <div style="background:#0d0d0d; border:1px solid #1e1e1e; border-radius:5px;
                                padding:16px 20px; margin-bottom:4px;">
                        <div style="font-size:14px; color:#e0e0e0; letter-spacing:1px; font-weight:300;">
                            {name}
                        </div>
                        <div style="font-size:11px; color:#555; margin-top:4px; letter-spacing:0.5px;">
                            {desc if desc else '&nbsp;'}
                        </div>
                        <div style="font-size:10px; color:#333; margin-top:8px; letter-spacing:1px;
                                    text-transform:uppercase;">
                            STATUS: {status} &nbsp;·&nbsp; LAST RUN: {last}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with col_btn:
                st.markdown('<div style="padding-top:14px;"></div>', unsafe_allow_html=True)
                if st.button("Select", key=f"sel_proj_{pid}", width='stretch'):
                    st.session_state["active_project_id"]      = pid
                    st.session_state["active_project_name"]    = name
                    st.session_state.pop("project_select_pending", None)
                    st.session_state.setdefault("page", "Overview")
                    st.rerun()

        st.markdown('<hr style="border:none; border-top:1px solid #1a1a1a; margin:24px 0;">', unsafe_allow_html=True)

        with st.expander("Create a new project instead", expanded=False):
            _render_create_form_inline()

    else:
        st.markdown(
            '<div style="background:#111; border:1px dashed #2a2a2a; border-radius:4px; '
            'padding:14px 18px; margin-bottom:24px; font-size:12px; color:#555; letter-spacing:0.5px;">'
            'No projects found — create one below to get started.</div>',
            unsafe_allow_html=True,
        )
        _render_create_form_inline()

    st.markdown('<div style="margin-top:8px;"></div>', unsafe_allow_html=True)
    if st.button("Skip — continue without a project", key="skip_project_select"):
        st.session_state.pop("project_select_pending", None)
        st.session_state.setdefault("page", "Overview")
        st.rerun()


def _render_create_form_inline() -> None:
    """Mini create-project form used inside the project selector screen."""
    with st.form("form_selector_new_project", clear_on_submit=True):
        proj_name = st.text_input("Project Name", placeholder="e.g. Prod Server Q3")
        proj_desc = st.text_area("Description (optional)", placeholder="Brief note about this project", height=70)
        if st.form_submit_button("Create & Select", width='stretch'):
            if not proj_name.strip():
                st.warning("Project name is required.")
            else:
                with st.spinner("Creating project…"):
                    result = create_project(proj_name.strip(), proj_desc.strip())
                if "error" in result:
                    st.error(f"Failed: {result['error']}")
                else:
                    pid  = result.get("id") or result.get("project_id", "")
                    name = result.get("name", proj_name)
                    st.session_state["active_project_id"]   = pid
                    st.session_state["active_project_name"] = name
                    st.session_state.pop("project_select_pending", None)
                    st.session_state.setdefault("page", "Overview")
                    st.rerun()
