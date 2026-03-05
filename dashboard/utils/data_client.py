"""Data API calls — file upload and project management."""
from typing import Dict, List, Optional
from utils.api_client import _get, _post, _delete, API_BASE, _auth_header
import requests


def upload_file(file_bytes: bytes, filename: str, project_id: Optional[str] = None) -> Dict:
    try:
        files = {"file": (filename, file_bytes, "application/octet-stream")}
        data  = {"project_id": project_id} if project_id else {}
        r = requests.post(
            f"{API_BASE}/api/upload",
            files=files,
            data=data,
            headers=_auth_header(),
            timeout=120,
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


def get_upload_status(upload_id: str) -> Dict:
    return _get(f"/api/upload/status/{upload_id}", timeout=10)


def create_project(name: str, description: str = "") -> Dict:
    return _post("/api/projects", json={"name": name, "description": description})


def get_projects() -> List[Dict]:
    result = _get("/api/projects", timeout=10)
    if isinstance(result, list):
        return result
    return result.get("projects", []) if isinstance(result, dict) and "projects" in result else []


def get_project_stats(project_id: str) -> Dict:
    return _get(f"/api/projects/{project_id}/stats", timeout=10)


def delete_project(project_id: str) -> Dict:
    return _delete(f"/api/projects/{project_id}")
