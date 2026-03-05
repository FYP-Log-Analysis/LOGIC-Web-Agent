import time
import streamlit as st
from utils.data_client import upload_file, get_upload_status


_STAGES = [
    ("uploading",   "Uploading"),
    ("parsing",     "Parsing"),
    ("normalizing", "Normalizing"),
    ("saved",       "Saved to Database"),
]

def _stage_index(stage: str) -> int:
    if stage == "error":
        return -1
    return next((i for i, (k, _) in enumerate(_STAGES) if k == stage), 0)


def _render_stepper(current_stage: str, current_status: str, entry_count: int) -> None:
    current_idx = _stage_index(current_stage)
    is_error    = current_stage == "error"

    cols = st.columns(len(_STAGES))
    for i, (stage_key, stage_label) in enumerate(_STAGES):
        with cols[i]:
            if is_error and i == current_idx:
                icon  = "✗"
                color = "#ff4444"
                label_color = "#ff4444"
            elif i < current_idx or (current_stage == "saved" and current_status == "complete"):
                icon  = "✓"
                color = "#e0e0e0"
                label_color = "#e0e0e0"
            elif i == current_idx and current_status == "running":
                icon  = "◌"
                color = "#888888"
                label_color = "#cccccc"
            elif i == current_idx and current_status == "complete":
                icon  = "✓"
                color = "#e0e0e0"
                label_color = "#e0e0e0"
            else:
                icon  = "○"
                color = "#333333"
                label_color = "#555555"

            st.markdown(
                f"""
                <div style="text-align:center; padding:12px 4px;">
                    <div style="font-size:26px; color:{color}; font-weight:300; letter-spacing:1px;">{icon}</div>
                    <div style="font-size:11px; color:{label_color}; margin-top:6px; letter-spacing:0.8px; text-transform:uppercase;">{stage_label}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # connector lines via a single-row separator
    st.markdown(
        """<hr style="border:none; border-top:1px solid #222; margin:0 0 16px 0;">""",
        unsafe_allow_html=True,
    )

    if current_stage == "saved" and current_status == "complete":
        st.markdown(
            f"""<div style="text-align:center; color:#b0b0b0; font-size:13px; letter-spacing:0.5px;">
            {entry_count:,} log entries stored — ready for analysis</div>""",
            unsafe_allow_html=True,
        )
    elif is_error:
        st.markdown(
            """<div style="text-align:center; color:#ff4444; font-size:13px;">
            Processing error — check API logs</div>""",
            unsafe_allow_html=True,
        )
    else:
        stage_label = next((l for k, l in _STAGES if k == current_stage), current_stage)
        st.markdown(
            f"""<div style="text-align:center; color:#666; font-size:13px; letter-spacing:0.5px;">
            {stage_label}…</div>""",
            unsafe_allow_html=True,
        )


def _poll_progress(upload_id: str, progress_placeholder: st.delta_generator.DeltaGenerator) -> bool:
    while True:
        status = get_upload_status(upload_id)
        if "error" in status and "stage" not in status:
            progress_placeholder.error(f"Could not reach API: {status['error']}")
            return False

        stage       = status.get("stage", "uploading")
        stat        = status.get("status", "running")
        entry_count = status.get("entry_count") or 0

        with progress_placeholder.container():
            _render_stepper(stage, stat, entry_count)

        if stage == "saved" and stat == "complete":
            return True
        if stage == "error":
            return False

        time.sleep(1)


def render_upload() -> None:
    active_id   = st.session_state.get("active_project_id")
    active_name = st.session_state.get("active_project_name", "")

    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        UPLOAD LOGS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Supported formats: .log · .gz · .zip · .tar · .tgz
        </p>""",
        unsafe_allow_html=True,
    )

    # ── Active project context banner ──────────────────────────────────────
    if active_id:
        st.markdown(
            f'<div style="background:#1a0d2e; border:1px solid #6b46c1; border-radius:4px; '
            f'padding:10px 16px; margin-bottom:20px; font-size:12px; color:#a78bfa; letter-spacing:1px;">'
            f'Uploading to project: <strong>{active_name}</strong> '
            f'<span style="color:#555">({active_id[:8]}…)</span></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="background:#111; border:1px dashed #2a2a2a; border-radius:4px; '
            'padding:10px 16px; margin-bottom:20px; font-size:12px; color:#444; letter-spacing:1px;">'
            'No active project — logs will be stored in the global store. '
            'Go to <strong>Projects</strong> to create or select one.</div>',
            unsafe_allow_html=True,
        )

    uploaded_files = st.file_uploader(
        label="Drop access.log or archive",
        type=["log", "gz", "tgz", "tar", "zip"],
        label_visibility="collapsed",
        accept_multiple_files=True,
    )

    if not uploaded_files:
        st.markdown(
            """<div style="border:1px dashed #2a2a2a; border-radius:4px; padding:40px; text-align:center;
            color:#444; font-size:13px; letter-spacing:0.8px; margin-top:16px;">
            SELECT ONE OR MORE LOG FILES / ARCHIVES ABOVE TO BEGIN
            </div>""",
            unsafe_allow_html=True,
        )
        st.session_state.pop("last_upload_complete", None)
        st.session_state.pop("last_upload_count", None)
        return

    col1, col2 = st.columns([3, 1])
    with col2:
        start = st.button("Upload & Ingest", width='stretch')

    if not start:
        # Show summary of selected files
        st.markdown(
            f'<div style="color:#555; font-size:12px; margin-top:8px; letter-spacing:0.5px;">'
            f'{len(uploaded_files)} file(s) selected</div>',
            unsafe_allow_html=True,
        )
        return

    total_entries = 0

    for uploaded in uploaded_files:
        st.markdown(
            f'<div style="font-size:12px; color:#888; letter-spacing:0.5px; '
            f'margin-top:16px; margin-bottom:6px;">> {uploaded.name}</div>',
            unsafe_allow_html=True,
        )

        progress_placeholder = st.empty()
        with progress_placeholder.container():
            _render_stepper("uploading", "running", 0)

        result = upload_file(uploaded.getvalue(), uploaded.name, project_id=active_id)
        if "error" in result:
            progress_placeholder.error(f"Upload failed: {result['error']}")
            continue

        upload_id = result.get("upload_id")
        if not upload_id:
            progress_placeholder.error("API did not return an upload_id.")
            continue

        with progress_placeholder.container():
            _render_stepper("parsing", "running", 0)

        success = _poll_progress(upload_id, progress_placeholder)

        if success:
            final = get_upload_status(upload_id)
            count = final.get("entry_count") or 0
            total_entries += count
            st.success(f"**{uploaded.name}** — {count:,} entries ingested.")
        else:
            st.error(f"**{uploaded.name}** — ingestion failed. Check API logs.")

    if total_entries:
        st.info(
            f"Total: **{total_entries:,}** log entries stored. "
            "Navigate to **Analysis** to run detection."
        )


def render_inline_upload(project_id: str, project_name: str) -> None:
    """
    Slim upload form for embedding inside the Projects page.

    Takes project_id and project_name explicitly — no session state reads —
    so it works correctly even when multiple project cards are on screen.
    Always project-scoped: no fallback to global log store.
    """
    st.markdown(
        f'<div style="font-size:11px; color:#555; letter-spacing:0.5px; margin-bottom:12px;">'
        f'Uploading to: <strong style="color:#a78bfa;">{project_name}</strong></div>',
        unsafe_allow_html=True,
    )

    uploaded_files = st.file_uploader(
        label="Drop log files or archives",
        type=["log", "gz", "tgz", "tar", "zip"],
        label_visibility="collapsed",
        accept_multiple_files=True,
        key=f"inline_upload_{project_id}",
    )

    if not uploaded_files:
        st.caption("Supported: .log · .gz · .zip · .tar · .tgz")
        return

    col1, col2 = st.columns([3, 1])
    with col2:
        start = st.button("Upload", key=f"inline_upload_btn_{project_id}",
                          width='stretch')

    if not start:
        st.caption(f"{len(uploaded_files)} file(s) selected")
        return

    total_entries = 0

    for uploaded in uploaded_files:
        st.markdown(
            f'<div style="font-size:12px; color:#888; margin:12px 0 4px 0;">'
            f'> {uploaded.name}</div>',
            unsafe_allow_html=True,
        )
        progress_placeholder = st.empty()
        with progress_placeholder.container():
            _render_stepper("uploading", "running", 0)

        result = upload_file(uploaded.getvalue(), uploaded.name, project_id=project_id)
        if "error" in result:
            progress_placeholder.error(f"Upload failed: {result['error']}")
            continue

        upload_id = result.get("upload_id")
        if not upload_id:
            progress_placeholder.error("API did not return an upload_id.")
            continue

        with progress_placeholder.container():
            _render_stepper("parsing", "running", 0)

        success = _poll_progress(upload_id, progress_placeholder)

        if success:
            final = get_upload_status(upload_id)
            count = final.get("entry_count") or 0
            total_entries += count
            st.success(f"**{uploaded.name}** — {count:,} entries ingested.")
        else:
            st.error(f"**{uploaded.name}** — ingestion failed. Check API logs.")

    if total_entries:
        st.info(f"Total: **{total_entries:,}** log entries stored.")

