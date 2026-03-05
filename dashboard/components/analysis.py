import time
from datetime import datetime, timezone

import streamlit as st

from utils.api_client import api_health
from utils.analysis_client import get_log_time_range, run_analysis, get_analysis_run


def _iso_to_dt(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None


def _dt_to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _badge(label: str, color: str, bg: str) -> str:
    return (
        f'<span style="display:inline-block; padding:2px 10px; '
        f'border-radius:2px; border:1px solid {color}; color:{color}; '
        f'background:{bg}; font-size:11px; letter-spacing:1px; '
        f'text-transform:uppercase; font-weight:500;">{label}</span>'
    )


def _render_results(steps: list) -> None:
    if not steps:
        return
    import pandas as pd

    rows = []
    for s in steps:
        step = s.get("step", "")
        status = s.get("status", "")
        elapsed = s.get("elapsed_s", 0)

        if step == "rule_detection":
            rows.append({
                "Step":          "Rule-Based Detection",
                "Status":        "Complete" if status == "complete" else status,
                "Time (s)":      elapsed,
                "Matches":       s.get("total_matches", 0),
                "Unique Rules":  s.get("unique_rules", 0),
            })

    if rows:
        import pandas as pd
        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            width='stretch',
            hide_index=True,
        )


def _poll_run(run_id: str, progress_slot: st.delta_generator.DeltaGenerator) -> dict:
    spinner_frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    frame = 0
    while True:
        record = get_analysis_run(run_id)
        status = record.get("status", "pending")
        step   = record.get("current_step") or status

        icon = spinner_frames[frame % len(spinner_frames)]
        frame += 1

        with progress_slot.container():
            step_label = {
                "rule_detection": "Running rule-based detection…",
                "pending":        "Starting analysis…",
                "running":        "Processing…",
            }.get(step, f"{step}…")
            st.markdown(
                f"""<div style="padding:16px 20px; background:#111; border:1px solid #222; border-radius:4px; color:#888; font-size:13px; letter-spacing:0.5px;">
                <span style="color:#ccc;">{icon}</span>&nbsp; {step_label}
                </div>""",
                unsafe_allow_html=True,
            )

        if status in ("complete", "failed"):
            return record
        time.sleep(1.5)


def render_analysis() -> None:
    st.markdown(
        """<h2 style="color:#e0e0e0; font-weight:300; letter-spacing:2px; margin-bottom:4px;">
        ANALYSIS</h2>
        <p style="color:#555; font-size:13px; letter-spacing:0.5px; margin-bottom:24px;">
        Select a time window then run detection across stored log entries.
        </p>""",
        unsafe_allow_html=True,
    )

    if not api_health():
        st.warning("API is offline — cannot run analysis.")
        return

    start_ts: str | None = None
    end_ts:   str | None = None

    # ── Time slider ────────────────────────────────────────────────────────────
    tr = get_log_time_range()
    if tr.get("error"):
        st.error(f"Could not fetch log time range: {tr['error']}")
        return

    min_dt = _iso_to_dt(tr.get("min_timestamp"))
    max_dt = _iso_to_dt(tr.get("max_timestamp"))
    total  = tr.get("total_logs", 0)

    if not min_dt or not max_dt:
        st.info("No logs found in the database. Upload a log file first.")
        return

    st.markdown(
        f"""<div style="background:#111; border:1px solid #1e1e1e; border-radius:4px; padding:12px 16px; margin-bottom:16px; font-size:12px; color:#666; letter-spacing:0.5px;">
        {total:,} log entries &nbsp;·&nbsp;
        {min_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC  →  {max_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC
        </div>""",
        unsafe_allow_html=True,
    )

    # Use timezone-naive datetime objects — Streamlit slider requires naive datetimes
    min_naive = min_dt.replace(tzinfo=None)
    max_naive = max_dt.replace(tzinfo=None)

    if min_naive == max_naive:
        st.warning("All log entries share the same timestamp — defaulting to full range.")
        start_ts = _dt_to_iso(min_dt)
        end_ts   = _dt_to_iso(max_dt)
    else:
        sel_range = st.slider(
            "Select time window",
            min_value=min_naive,
            max_value=max_naive,
            value=(min_naive, max_naive),
            format="YYYY-MM-DD HH:mm",
            label_visibility="collapsed",
        )

        sel_start = sel_range[0].replace(tzinfo=timezone.utc)
        sel_end   = sel_range[1].replace(tzinfo=timezone.utc)
        start_ts  = _dt_to_iso(sel_start)
        end_ts    = _dt_to_iso(sel_end)

        st.markdown(
            f"""<div style="color:#888; font-size:12px; letter-spacing:0.5px; margin-bottom:20px;">
            Window: &nbsp;<span style="color:#c0c0c0;">{sel_start.strftime('%Y-%m-%d %H:%M:%S')}</span>
            &nbsp;→&nbsp;
            <span style="color:#c0c0c0;">{sel_end.strftime('%Y-%m-%d %H:%M:%S')}</span> UTC
            </div>""",
            unsafe_allow_html=True,
        )

    # ── Detection engine selector (CRS-only) ────────────────────────────────────────────
    analysis_type = "crs"  # CRS is the only detection engine

    # ── Run button ─────────────────────────────────────────────────────────────
    col1, col2 = st.columns([3, 1])
    with col2:
        run_btn = st.button("Run Analysis", width='stretch')

    if not run_btn:
        # Show previous results if available
        if "last_analysis_result" in st.session_state:
            _show_previous(st.session_state["last_analysis_result"])
        return

    response = run_analysis(
        mode="manual",
        start_ts=start_ts,
        end_ts=end_ts,
    )
    if "error" in response:
        st.error(f"Failed to start analysis: {response['error']}")
        return

    run_id = response.get("run_id")
    if not run_id:
        st.error("API did not return a run_id.")
        return

    progress_slot = st.empty()
    result = _poll_run(run_id, progress_slot)
    progress_slot.empty()

    st.session_state["last_analysis_result"] = result
    _show_previous(result)


def _show_previous(result: dict) -> None:
    status = result.get("status", "unknown")
    mode   = result.get("mode", "auto")

    if status == "complete":
        st.markdown(
            f"""<div style="background:#0a0f0a; border:1px solid #1a3a1a; border-radius:4px; padding:12px 16px; margin-bottom:20px;">
            {_badge("COMPLETE", "#4caf50", "#0a0f0a")}
            &nbsp;<span style="color:#666; font-size:12px; letter-spacing:0.5px;">
            Mode: {mode.title()}</span>
            </div>""",
            unsafe_allow_html=True,
        )
        _render_results(result.get("steps", []))
    elif status == "failed":
        st.markdown(
            f"""<div style="background:#1a0a0a; border:1px solid #3a1a1a; border-radius:4px; padding:12px 16px; margin-bottom:20px;">
            {_badge("FAILED", "#ff4444", "#1a0a0a")}
            &nbsp;<span style="color:#888; font-size:12px;">{result.get('error_msg', '')}</span>
            </div>""",
            unsafe_allow_html=True,
        )
    else:
        st.info(f"Analysis status: {status}")
