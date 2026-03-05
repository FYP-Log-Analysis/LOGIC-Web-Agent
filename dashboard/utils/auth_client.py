"""Auth API calls — login, register, get current user."""
from typing import Dict
from utils.api_client import _get, _post, API_BASE
import requests
import streamlit as st


def login(username: str, password: str) -> Dict:
    """Returns {access_token, token_type} or {error}."""
    try:
        r = requests.post(
            f"{API_BASE}/api/auth/login",
            data={"username": username, "password": password},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        try:
            return {"error": exc.response.json().get("detail", str(exc))}
        except Exception:
            return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def register(username: str, email: str, password: str) -> Dict:
    return _post("/api/auth/register", json={
        "username": username,
        "email":    email,
        "password": password,
    })


def get_current_user() -> Dict:
    return _get("/api/auth/me", timeout=10)
