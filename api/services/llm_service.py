"""
LLM Analysis Service — LOGIC Web Agent
Supports two LLM backends:
  1. Groq Cloud       — llama-3.3-70b-versatile (requires GROQ_API_KEY)
  2. LM Studio (local)— any model loaded in LM Studio, OpenAI-compatible API
                        at http://localhost:1234/v1 by default.
                        Override with LM_STUDIO_BASE_URL / LM_STUDIO_MODEL env vars.
"""

import os
import json
import logging
import requests
from typing import Dict, List, Optional

from groq import Groq
from openai import OpenAI  # LM Studio uses the OpenAI-compatible REST API

logger = logging.getLogger(__name__)

# ── LM Studio defaults ────────────────────────────────────────────────────────
LM_STUDIO_BASE_URL = os.getenv("LM_STUDIO_BASE_URL", "http://localhost:1234/v1")
LM_STUDIO_MODEL    = os.getenv("LM_STUDIO_MODEL",    "local-model")


# ── Groq client ───────────────────────────────────────────────────────────────
def _get_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Export it before starting the API."
        )
    return Groq(api_key=api_key)


# ── LM Studio client ──────────────────────────────────────────────────────────
LM_STUDIO_TIMEOUT = int(os.getenv("LM_STUDIO_TIMEOUT", "300"))  # seconds


def _get_lm_studio_client() -> OpenAI:
    """Return an OpenAI-SDK client pointed at the local LM Studio server.

    A generous timeout is required for reasoning models (e.g. deepseek-r1)
    that produce long chain-of-thought sequences before the final answer.
    Without it the underlying HTTP connection is closed by the OS or LM Studio
    before the response arrives, giving a RemoteDisconnected error.
    """
    return OpenAI(
        base_url=LM_STUDIO_BASE_URL,
        api_key="lm-studio",
        timeout=LM_STUDIO_TIMEOUT,
    )


def lm_studio_reachable() -> bool:
    """Return True if LM Studio is up and serving at least one model."""
    try:
        r = requests.get(f"{LM_STUDIO_BASE_URL}/models", timeout=4)
        return r.status_code == 200
    except Exception:
        return False


def _build_summary(detection_data: Dict) -> str:
    matches  = detection_data.get("matches", [])
    severity_counts: Dict[str, int] = {}
    rule_counts:     Dict[str, int] = {}
    ips: set = set()

    for m in matches:
        sev = m.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rule = m.get("rule_title", "Unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        if m.get("client_ip"):
            ips.add(m["client_ip"])

    lines = [
        f"Total Detections      : {len(matches)}",
        f"Unique Rules Triggered: {len(detection_data.get('matched_rules', []))}",
        f"Unique Source IPs     : {len(ips)}",
        "",
        "Severity Breakdown:",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            lines.append(f"  {sev.upper()}: {cnt}")

    lines += ["", "Top Triggered Rules:"]
    for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  - {rule}: {cnt} match(es)")

    top_ips = sorted(
        [(ip, sum(1 for m in matches if m.get("client_ip") == ip)) for ip in ips],
        key=lambda x: -x[1],
    )[:5]
    if top_ips:
        lines += ["", "Top Offending IPs:"]
        for ip, cnt in top_ips:
            lines.append(f"  - {ip}: {cnt} match(es)")

    return "\n".join(lines)


def analyse_detection_results(detection_data: Dict) -> Dict:
    try:
        summary = _build_summary(detection_data)
        client  = _get_client()

        system_prompt = (
            "You are a web application security expert. "
            "Analyse the provided web server threat detection results and provide:\n"
            "1. Key attack patterns and techniques observed\n"
            "2. Top 3 most critical findings\n"
            "3. Risk assessment (Critical/High/Medium/Low)\n"
            "4. Recommended immediate actions\n"
            "5. Long-term hardening recommendations\n"
            "Be concise, technical, and actionable."
        )
        user_prompt = (
            f"Analyse these web server security detections:\n\n{summary}\n\n"
            "Provide a comprehensive threat analysis."
        )

        logger.info("Calling Groq API for bulk threat analysis …")
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )

        return {
            "status":   "success",
            "analysis": response.choices[0].message.content,
            "detection_summary": {
                "total_matches":  detection_data.get("total_matches", 0),
                "unique_rules":   len(detection_data.get("matched_rules", [])),
            },
        }
    except Exception as exc:
        logger.error(f"LLM analysis failed: {exc}", exc_info=True)
        return {"status": "error", "error_message": str(exc), "analysis": None}


def analyse_specific_match(match_data: Dict) -> Dict:
    try:
        client = _get_client()
        entry  = match_data.get("entry", {})
        user_prompt = (
            f"Analyse this web server security detection:\n\n"
            f"Rule     : {match_data.get('rule_title')}\n"
            f"Severity : {match_data.get('severity')}\n"
            f"Source IP: {match_data.get('client_ip')}\n"
            f"Method   : {match_data.get('method')}\n"
            f"Path     : {match_data.get('path')}\n"
            f"Status   : {match_data.get('status_code')}\n"
            f"UA       : {entry.get('user_agent')}\n"
            f"Timestamp: {match_data.get('timestamp')}\n\n"
            "In 3-4 sentences: what attack does this indicate, why is it important, "
            "and what should be done?"
        )
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=512,
            messages=[
                {"role": "system", "content": "You are a web security analyst."},
                {"role": "user",   "content": user_prompt},
            ],
        )
        return {
            "status":   "success",
            "analysis": response.choices[0].message.content,
            "rule_id":  match_data.get("rule_id"),
        }
    except Exception as exc:
        logger.error(f"Specific match analysis failed: {exc}", exc_info=True)
        return {"status": "error", "error_message": str(exc)}


# ── LM Studio helpers ─────────────────────────────────────────────────────────

def _build_anomaly_summary(anomaly_data: List[Dict]) -> str:
    """Build a concise text summary of anomaly scores for the LLM prompt."""
    total     = len(anomaly_data)
    anomalies = [e for e in anomaly_data if e.get("is_anomaly")]
    normal    = total - len(anomalies)

    top = sorted(anomalies, key=lambda x: x.get("anomaly_score", 0), reverse=True)[:10]

    lines = [
        f"Total Log Entries : {total}",
        f"Anomalous Entries : {len(anomalies)} ({100*len(anomalies)/max(total,1):.1f}%)",
        f"Normal  Entries   : {normal}",
        "",
        "Top 10 Most Anomalous Requests:",
    ]
    for i, e in enumerate(top, 1):
        lines.append(
            f"  {i}. score={e.get('anomaly_score','?'):.4f} | "
            f"IP={e.get('client_ip','?')} | "
            f"{e.get('http_method','?')} {e.get('request_path','?')} | "
            f"status={e.get('status_code','?')} | "
            f"UA={str(e.get('user_agent','?'))[:60]}"
        )
    return "\n".join(lines)


def analyse_with_lm_studio(
    rule_data: Dict,
    anomaly_data: Optional[List[Dict]] = None,
) -> Dict:
    """
    Send both rule-match results AND (optionally) anomaly results to the local
    LM Studio server and return combined insights + mitigations.
    """
    try:
        client  = _get_lm_studio_client()
        rule_summary = _build_summary(rule_data)

        combined = f"=== Rule-Based Detection Summary ===\n{rule_summary}"
        if anomaly_data:
            anom_summary = _build_anomaly_summary(anomaly_data)
            combined += f"\n\n=== Anomaly Detection Summary ===\n{anom_summary}"

        system_prompt = (
            "You are an expert web-application security analyst. "
            "You are given structured summaries from two detection systems: "
            "YAML rule-based matching and ML anomaly detection (Isolation Forest). "
            "Your task is to produce a comprehensive security report with the following sections:\n\n"
            "## 1. Executive Summary\n"
            "A concise plain-English overview of the security posture (2-3 sentences).\n\n"
            "## 2. Key Threat Insights\n"
            "Detail each significant attack type or pattern identified, referencing both "
            "rule matches and anomalous requests where applicable.\n\n"
            "## 3. Risk Assessment\n"
            "Rate overall risk (Critical / High / Medium / Low) with justification.\n\n"
            "## 4. Immediate Mitigations\n"
            "Actionable steps the team should take right now (firewall rules, IP blocks, "
            "WAF tuning, rate limiting, etc.).\n\n"
            "## 5. Long-Term Hardening\n"
            "Strategic recommendations to reduce the attack surface.\n\n"
            "Use clear, non-technical language where possible so a manager can understand."
        )

        logger.info("Calling LM Studio for combined threat + anomaly analysis …")
        response = client.chat.completions.create(
            model=LM_STUDIO_MODEL,
            max_tokens=1024,  # kept moderate — reasoning models add hidden thinking tokens
            temperature=0.3,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": combined},
            ],
        )

        return {
            "status":   "success",
            "backend":  "lm_studio",
            "model":    LM_STUDIO_MODEL,
            "analysis": response.choices[0].message.content,
            "detection_summary": {
                "total_rule_matches": rule_data.get("total_matches", 0),
                "unique_rules":       len(rule_data.get("matched_rules", [])),
                "total_anomalies":    len([e for e in (anomaly_data or []) if e.get("is_anomaly")]),
            },
        }
    except Exception as exc:
        logger.error(f"LM Studio analysis failed: {exc}", exc_info=True)
        return {"status": "error", "backend": "lm_studio", "error_message": str(exc), "analysis": None}


def analyse_anomalies_with_lm_studio(anomaly_data: List[Dict]) -> Dict:
    """Analyse only anomaly-detection results with LM Studio."""
    try:
        client  = _get_lm_studio_client()
        summary = _build_anomaly_summary(anomaly_data)

        system_prompt = (
            "You are a machine-learning security analyst specialising in web server anomaly detection. "
            "The data below comes from an Isolation Forest model applied to normalised log features. "
            "Provide:\n"
            "1. **Natural Language Explanation** — what the anomalies likely represent in plain English\n"
            "2. **Behavioural Patterns** — describe the common behaviours of the top anomalous requests\n"
            "3. **Threat Assessment** — are these likely attacks, crawlers, misconfigurations, or other?\n"
            "4. **Recommended Mitigations** — specific, actionable steps\n"
            "Keep the response structured with clear headers."
        )

        logger.info("Calling LM Studio for anomaly-only analysis …")
        response = client.chat.completions.create(
            model=LM_STUDIO_MODEL,
            max_tokens=768,  # kept moderate for reasoning models
            temperature=0.3,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": summary},
            ],
        )

        anomalies = [e for e in anomaly_data if e.get("is_anomaly")]
        return {
            "status":          "success",
            "backend":         "lm_studio",
            "model":           LM_STUDIO_MODEL,
            "analysis":        response.choices[0].message.content,
            "total_entries":   len(anomaly_data),
            "total_anomalies": len(anomalies),
        }
    except Exception as exc:
        logger.error(f"LM Studio anomaly analysis failed: {exc}", exc_info=True)
        return {"status": "error", "backend": "lm_studio", "error_message": str(exc), "analysis": None}
