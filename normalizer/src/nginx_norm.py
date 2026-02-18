"""
Nginx Log Normalizer — LOGIC Web Agent
Handles both access logs (same Combined Format as Apache) and Nginx error logs.
"""

from normalizer.src.utils import (
    classify_status,
    extract_path_parts,
    is_bot,
    categorise_request,
)


def normalise_nginx_access(entry: dict) -> dict:
    """Normalise a parsed Nginx access log entry."""
    path_info = extract_path_parts(entry.get("path", "/"))
    return {
        "source":         entry.get("source"),
        "log_type":       "access",
        "server_type":    "nginx",
        "timestamp":      entry.get("timestamp"),
        "client_ip":      entry.get("ip"),
        "auth_user":      entry.get("user"),
        "http_method":    entry.get("method"),
        "request_path":   entry.get("path"),
        "path_clean":     path_info["path_clean"],
        "query_string":   path_info["query_string"],
        "query_params":   path_info["query_params"],
        "file_extension": path_info["extension"],
        "protocol":       entry.get("protocol"),
        "status_code":    entry.get("status"),
        "status_class":   classify_status(entry.get("status", 0)),
        "response_size":  entry.get("size", 0),
        "referer":        entry.get("referer"),
        "user_agent":     entry.get("user_agent"),
        "is_bot":         is_bot(entry.get("user_agent")),
        "category":       categorise_request(
                              entry.get("method", ""),
                              entry.get("path", ""),
                              entry.get("status", 0),
                          ),
        "raw": entry.get("raw"),
    }


def normalise_nginx_error(entry: dict) -> dict:
    """Normalise a parsed Nginx error log entry."""
    return {
        "source":      entry.get("source"),
        "log_type":    "error",
        "server_type": "nginx",
        "timestamp":   entry.get("timestamp"),
        "client_ip":   entry.get("ip"),
        "level":       entry.get("level", "error").lower(),
        "message":     entry.get("message"),
        "raw":         entry.get("raw"),
    }
