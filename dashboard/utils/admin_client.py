"""Admin API calls — user and project management."""
from typing import Dict, List
from utils.api_client import _get, _post, _delete


def admin_list_users() -> List[Dict]:
    result = _get("/api/admin/users", timeout=10)
    return result if isinstance(result, list) else []


def admin_set_user_active(user_id: int, active: bool) -> Dict:
    action = "activate" if active else "deactivate"
    return _post(f"/api/admin/users/{user_id}/{action}")


def admin_delete_user(user_id: int) -> Dict:
    return _delete(f"/api/admin/users/{user_id}")


def admin_create_analyst(username: str, password: str) -> Dict:
    """Create a new analyst account via the register endpoint."""
    return _post("/api/auth/register", json={
        "username": username,
        "email":    f"{username}@logic.local",
        "password": password,
    })


def admin_stats() -> Dict:
    return _get("/api/admin/stats", timeout=10)
