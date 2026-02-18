"""
Rule Matcher — LOGIC Web Agent
Evaluates a single normalised log entry against a single detection rule.
"""

import re
import logging

logger = logging.getLogger(__name__)


def _get_field_value(entry: dict, field: str) -> str:
    """Return the field as a lowercase string for comparison."""
    val = entry.get(field)
    if val is None:
        return ""
    return str(val).lower()


def _check_keywords(entry: dict, keywords: list[str], fields: list[str] | None) -> bool:
    """Return True if ANY keyword appears in ANY of the target fields."""
    search_fields = fields or ["request_path", "query_string", "user_agent", "referer"]
    for kw in keywords:
        kw_lower = kw.lower()
        for field in search_fields:
            if kw_lower in _get_field_value(entry, field):
                return True
    return False


def _check_patterns(entry: dict, patterns: list[str], fields: list[str] | None) -> bool:
    """Return True if ANY regex pattern matches ANY of the target fields."""
    search_fields = fields or ["request_path", "query_string", "user_agent", "referer"]
    for pat in patterns:
        try:
            compiled = re.compile(pat, re.IGNORECASE)
            for field in search_fields:
                if compiled.search(_get_field_value(entry, field)):
                    return True
        except re.error as exc:
            logger.warning(f"Invalid regex '{pat}': {exc}")
    return False


def _check_conditions(entry: dict, conditions: dict) -> bool:
    """
    Field-level conditions. Supports:
      status: 403          (exact int or string match)
      status_gte: 500      (≥)
      method: POST         (exact, case-insensitive)
      is_bot: true/false
    """
    for key, expected in conditions.items():
        if key.endswith("_gte"):
            field = key[:-4]
            try:
                if int(entry.get(field, 0)) < int(expected):
                    return False
            except (ValueError, TypeError):
                return False
        elif key.endswith("_lte"):
            field = key[:-4]
            try:
                if int(entry.get(field, 0)) > int(expected):
                    return False
            except (ValueError, TypeError):
                return False
        else:
            actual = str(entry.get(key, "")).lower()
            if actual != str(expected).lower():
                return False
    return True


def check_if_entry_matches_rule(entry: dict, rule: dict) -> bool:
    """
    Returns True if the normalised log entry triggers the detection rule.

    Rule `detection` block may contain:
      keywords:  [list]       (substring search)
      patterns:  [list]       (regex search)
      conditions: {dict}      (field matcher)
      fields:    [list]       (restrict keyword/pattern target fields)
      logic:     all | any    (default: any for keywords/patterns, all for conditions)
    """
    detection = rule.get("detection", {})
    if not detection:
        return False

    fields    = detection.get("fields")
    keywords  = detection.get("keywords", [])
    patterns  = detection.get("patterns", [])
    conditions = detection.get("conditions", {})
    logic      = detection.get("logic", "any").lower()

    results = []

    if keywords:
        results.append(_check_keywords(entry, keywords, fields))
    if patterns:
        results.append(_check_patterns(entry, patterns, fields))
    if conditions:
        results.append(_check_conditions(entry, conditions))

    if not results:
        return False

    return all(results) if logic == "all" else any(results)
