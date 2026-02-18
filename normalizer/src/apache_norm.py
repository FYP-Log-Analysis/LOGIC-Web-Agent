"""
Apache Access Log Normalizer — LOGIC Web Agent
Enriches parsed Apache access-log records with derived / standardised fields.
"""

from normalizer.src.utils import (
    classify_status,
    extract_path_parts,
    is_bot,
    categorise_request,
)


def normalise_apache_entry(entry: dict) -> dict:
    """
    Takes a parsed access-log dict (from parser/src/parse_logs.py) and
    returns a normalised dict with a consistent schema.
    """
    path_info = extract_path_parts(entry.get("path", "/"))

    normalised = {
        # --- identity ---
        "source":       entry.get("source"),
        "log_type":     "access",
        "server_type":  "apache",

        # --- temporal ---
        "timestamp":    entry.get("timestamp"),

        # --- network ---
        "client_ip":    entry.get("ip"),
        "auth_user":    entry.get("user"),

        # --- request ---
        "http_method":  entry.get("method"),
        "request_path": entry.get("path"),
        "path_clean":   path_info["path_clean"],
        "query_string": path_info["query_string"],
        "query_params": path_info["query_params"],
        "file_extension": path_info["extension"],
        "protocol":     entry.get("protocol"),

        # --- response ---
        "status_code":  entry.get("status"),
        "status_class": classify_status(entry.get("status", 0)),
        "response_size": entry.get("size", 0),

        # --- metadata ---
        "referer":       entry.get("referer"),
        "user_agent":    entry.get("user_agent"),
        "is_bot":        is_bot(entry.get("user_agent")),
        "category":      categorise_request(
                            entry.get("method", ""),
                            entry.get("path", ""),
                            entry.get("status", 0),
                        ),

        # --- raw ---
        "raw": entry.get("raw"),
    }

    return normalised
