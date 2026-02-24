import time
import streamlit as st
from utils.api_client import upload_file, get_upload_status


_STAGES = [
    ("uploading",   "Uploading"),
    ("parsing",     "Parsing"),
    ("normalizing", "Normalizing"),
    ("saved",       "Saved to Database"),
]

_STAGE_ORDER = {s[0]: i for i, s in enumerate(_STAGES)}


def _stage_index(stage: str) -> int:
    if stage == "error":
        return -1
    return _STAGE_ORDER.get(stage, 0)


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
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        UPLOAD LOGS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Supported formats: .log · .gz · .zip · .tar · .tgz
        </p>""",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        label="Drop access.log or archive",
        type=["log", "gz", "tgz", "tar", "zip"],
        label_visibility="collapsed",
    )

    if uploaded is None:
        st.markdown(
            """<div style="border:1px dashed #2a2a2a; border-radius:4px; padding:40px; text-align:center; color:#444; font-size:13px; letter-spacing:0.8px; margin-top:16px;">
            SELECT AN access.log FILE OR ARCHIVE ABOVE TO BEGIN
            </div>""",
            unsafe_allow_html=True,
        )
        # Clear any previous upload state
        st.session_state.pop("last_upload_complete", None)
        st.session_state.pop("last_upload_count", None)
        return

    # Avoid re-triggering on re-render if already done
    file_key = f"{uploaded.name}_{uploaded.size}"
    if st.session_state.get("last_upload_key") == file_key and st.session_state.get("last_upload_complete"):
        count = st.session_state.get("last_upload_count", 0)
        st.markdown(
            f"""<div style="background:#0e1a0e; border:1px solid #1f3d1f; border-radius:4px; padding:16px 20px; color:#6fcf6f; font-size:13px; letter-spacing:0.5px; margin-top:16px;">
            ✓ &nbsp;{count:,} entries already stored from <strong>{uploaded.name}</strong>.
            Upload a different file or navigate to Analysis.
            </div>""",
            unsafe_allow_html=True,
        )
        return

    col1, col2 = st.columns([3, 1])
    with col2:
        start = st.button("Upload & Ingest", use_container_width=True)

    if not start:
        return

    # Show stepper immediately at "uploading" stage
    progress_placeholder = st.empty()
    with progress_placeholder.container():
        _render_stepper("uploading", "running", 0)

    # POST the file
    result = upload_file(uploaded.getvalue(), uploaded.name)
    if "error" in result:
        progress_placeholder.error(f"Upload failed: {result['error']}")
        return

    upload_id = result.get("upload_id")
    if not upload_id:
        progress_placeholder.error("API did not return an upload_id.")
        return

    # Advance stepper past "uploading" — file is on server, ingestion starting
    with progress_placeholder.container():
        _render_stepper("parsing", "running", 0)

    # Poll until done
    success = _poll_progress(upload_id, progress_placeholder)

    if success:
        final = get_upload_status(upload_id)
        count = final.get("entry_count") or 0
        st.session_state["last_upload_key"]      = file_key
        st.session_state["last_upload_complete"] = True
        st.session_state["last_upload_count"]    = count
        st.success(
            f"✓  {count:,} log entries ingested and stored from **{uploaded.name}**. "
            "Navigate to **Analysis** to run detection."
        )
