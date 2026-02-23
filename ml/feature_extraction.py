"""
Feature Extraction — LOGIC Web Agent
Converts normalised web log entries into numeric feature vectors for ML.
"""

import re
from urllib.parse import unquote_plus

SQLI_RE    = re.compile(r"(union\s+select|select\s.*from|'|\"|%27|%22|--|;|/\*)", re.I)
XSS_RE     = re.compile(r"(<script|javascript:|on\w+=|alert\(|document\.)", re.I)
LFI_RE     = re.compile(r"(\.\./|%2e%2e|/etc/passwd|php://)", re.I)
SCANNER_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|nuclei|burpsuite)", re.I
)

ADMIN_PATHS = {"/wp-admin", "/wp-login", "/admin", "/login", "/phpmyadmin",
               "/.env", "/.git", "/config", "/backup"}


def extract_features(entry: dict) -> dict:
    """
    Returns a flat dict of numeric/boolean features from a normalised log entry.
    Compatible with sklearn models (all values are int or float).
    """
    path      = entry.get("request_path", "") or ""
    qs        = entry.get("query_string",  "") or ""
    ua        = entry.get("user_agent",    "") or ""
    method    = entry.get("http_method",   "") or ""
    status    = entry.get("status_code",    0) or 0
    resp_size = entry.get("response_size",  0) or 0

    search_str = unquote_plus(path + " " + qs).lower()

    return {
        "path_depth":      path.count("/"),
        "path_length":     len(path),
        "qs_length":       len(qs),
        "response_size":   resp_size,
        "has_sqli":        int(bool(SQLI_RE.search(search_str))),
        "has_xss":         int(bool(XSS_RE.search(search_str))),
        "has_lfi":         int(bool(LFI_RE.search(search_str))),
        "has_scanner_ua":  int(bool(SCANNER_RE.search(ua))),
        "is_admin_path":   int(any(a in path.lower() for a in ADMIN_PATHS)),
        "is_get":          int(method == "GET"),
        "is_post":         int(method == "POST"),
        "is_other_method": int(method not in {"GET", "POST", "HEAD"}),
        "is_2xx":          int(200 <= status < 300),
        "is_4xx":          int(400 <= status < 500),
        "is_5xx":          int(500 <= status < 600),
        "is_404":          int(status == 404),
        "is_403":          int(status == 403),
    }


# Derived at import time — used by isolation_forest to pre-allocate numpy arrays
FEATURE_NAMES: list[str] = list(extract_features({}).keys())
