# Checks whether a single normalised log entry triggers a detection rule.
# Supports keyword substring search, regex matching, and field-level conditions.

import re
import logging

logger = logging.getLogger(__name__)


def _get_field_value(entry: dict, field: str) -> str:
    # Returns a lowercased string so all comparisons are case-insensitive
    val = entry.get(field)
    if val is None:
        return ""
    return str(val).lower()


def _check_keywords(entry: dict, keywords: list[str], fields: list[str] | None) -> bool:
    # Return True if any keyword appears anywhere in any of the target fields
    search_fields = fields or ["request_path", "query_string", "user_agent", "referer"]
    for kw in keywords:
        kw_lower = kw.lower()
        for field in search_fields:
            if kw_lower in _get_field_value(entry, field):
                return True
    return False


def _check_patterns(entry: dict, patterns: list[str], fields: list[str] | None) -> bool:
    # Return True if any regex matches any field; skip and log bad patterns quietly
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
    # Supports exact match, _gte (>=) and _lte (<=) suffixes on any field name
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
    # Runs whichever detectors the rule defines (keywords/patterns/conditions)
    # and combines results with 'any' (default) or 'all' logic
    detection = rule.get("detection", {})
    if not detection:
        return False

    fields     = detection.get("fields")
    keywords   = detection.get("keywords", [])
    patterns   = detection.get("patterns", [])
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
