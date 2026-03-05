"""
login.py — LOGIC Web Agent auth gate.

Two-path login: Admin or Analyst.
Each path shows a credential form locked to that role.
No registration form.

Hardcoded demo accounts:
    admin   / admin123   → role: admin
    analyst / analyst123 → role: analyst

The login always tries the API for a real JWT.
If API is unavailable, falls back to a local session token.
"""
import streamlit as st
from utils.auth_client import login, get_current_user

# ── Hardcoded demo accounts ──────────────────────────────────────────────────
_DEMO_ACCOUNTS = {
    "admin":   {"password": "admin123",   "role": "admin",   "user_id": 0, "email": "admin@logic.local"},
    "analyst": {"password": "analyst123", "role": "analyst", "user_id": 1, "email": "analyst@logic.local"},
}


def _set_session(username: str, role: str, user_id: int, email: str, token: str = "demo") -> None:
    st.session_state["authenticated"] = True
    st.session_state["token"]         = token
    st.session_state["username"]      = username
    st.session_state["role"]          = role
    st.session_state["user_id"]       = user_id
    st.session_state["email"]         = email
    st.session_state["page"]          = "Admin" if role == "admin" else "Overview"


_CSS = """
<style>
[data-testid="stForm"] {
    background: #0d0d0d !important;
    border: 1px solid #1e1e1e !important;
    border-radius: 6px !important;
    padding: 24px 32px !important;
}
[data-testid="stTextInput"] > div > div > input {
    background: #111 !important;
    border: 1px solid #2a2a2a !important;
    border-radius: 3px !important;
    color: #c0c0c0 !important;
    font-family: 'SF Mono','Fira Code','Consolas',monospace !important;
    font-size: 13px !important;
    padding: 8px 12px !important;
}
[data-testid="stTextInput"] > div > div > input:focus {
    border-color: #6b46c1 !important;
    box-shadow: 0 0 0 1px #6b46c1 !important;
}
</style>
"""


def _do_login(username: str, password: str) -> bool:
    """Authenticate: try API for a real JWT; fall back to local session for demo accounts."""
    key  = username.lower().strip()
    demo = _DEMO_ACCOUNTS.get(key)

    if demo and demo["password"] != password:
        st.error("Incorrect password.")
        return False

    # Always attempt API login to get a real token
    result = login(username, password)
    token  = result.get("access_token")

    if token:
        st.session_state["token"] = token
        me = get_current_user()
        if "error" not in me:
            role = me.get("role", "analyst").lower().strip()
            if role not in ("admin", "analyst", "user"):
                role = "analyst"
            _set_session(me.get("username", key), role, me.get("user_id", 0), me.get("email", ""), token)
            return True

    # API unavailable or user not in DB — allow hardcoded demo accounts locally
    if demo:
        _set_session(key, demo["role"], demo["user_id"], demo["email"], token="local")
        return True

    st.error(result.get("error", "Login failed. Check credentials."))
    return False


def _render_cred_form(role: str) -> None:
    """Render credential form locked to a specific role."""
    is_admin = role == "admin"
    accent   = "#6b46c1" if is_admin else "#1d4ed8"
    label    = "ADMIN" if is_admin else "ANALYST"
    hint_pw  = "admin123" if is_admin else "analyst123"

    st.markdown(
        f'<div style="text-align:center; margin-bottom:20px;">'
        f'<span style="background:{accent}; color:#fff; font-size:9px; letter-spacing:3px; '
        f'text-transform:uppercase; border-radius:2px; padding:3px 12px;">{label} ACCESS</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    with st.form(f"form_{role}", clear_on_submit=False):
        st.markdown(
            '<div style="font-size:10px; letter-spacing:2px; color:#555; '
            'text-transform:uppercase; margin-bottom:14px;">CREDENTIALS</div>',
            unsafe_allow_html=True,
        )
        username  = st.text_input("Username", placeholder=role, key=f"{role}_user")
        password  = st.text_input("Password", type="password", placeholder="••••••••", key=f"{role}_pass")
        submitted = st.form_submit_button("SIGN IN", width='content')

        if submitted:
            if not username or not password:
                st.warning("Enter username and password.")
            else:
                with st.spinner("Authenticating…"):
                    if _do_login(username, password):
                        st.rerun()
                    else:
                        st.caption(f"Demo credentials — `{role}` / `{hint_pw}`")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Back", key=f"back_{role}", width='content'):
        st.session_state.pop("login_mode", None)
        st.rerun()


def render_login() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    # ── Header ────────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="text-align:center; padding:48px 0 40px 0;">
            <div style="font-size:28px; letter-spacing:8px; color:#e0e0e0; font-weight:200;
                        font-family:'SF Mono','Fira Code','Consolas',monospace;">LOGIC</div>
            <div style="font-size:10px; letter-spacing:4px; color:#333; margin-top:6px;
                        text-transform:uppercase; font-family:'SF Mono','Fira Code','Consolas',monospace;">
                Web Agent &middot; Security Analysis</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_c, col_r = st.columns([1, 1.4, 1])

    with col_c:
        mode = st.session_state.get("login_mode")  # "admin" | "analyst" | None

        if mode is None:
            # ── Role selection screen ────────────────────────────────────
            st.markdown(
                '<div style="font-size:10px; letter-spacing:3px; color:#444; '
                'text-transform:uppercase; text-align:center; margin-bottom:24px;">Select Access Level</div>',
                unsafe_allow_html=True,
            )
            btn_a, btn_b = st.columns(2)
            with btn_a:
                if st.button("Login as Admin", key="sel_admin", width='content'):
                    st.session_state["login_mode"] = "admin"
                    st.rerun()
            with btn_b:
                if st.button("Login as Analyst", key="sel_analyst", width='content'):
                    st.session_state["login_mode"] = "analyst"
                    st.rerun()

        elif mode == "admin":
            _render_cred_form("admin")

        elif mode == "analyst":
            _render_cred_form("analyst")

        st.markdown(
            '<div style="text-align:center; color:#222; font-size:10px; '
            'letter-spacing:1px; margin-top:32px;">LOGIC Web Agent — FYP 2024</div>',
            unsafe_allow_html=True,
        )
