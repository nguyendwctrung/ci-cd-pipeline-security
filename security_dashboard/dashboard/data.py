from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional

import pandas as pd
from pymongo import DESCENDING, MongoClient


def load_runs(
    mongodb_uri: str,
    database: str,
    *,
    days: int = 30,
    limit: int = 500,
) -> list[Dict[str, Any]]:
    """Load sanitized monitoring runs from the dedicated database."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        client.admin.command("ping")
        cursor = (
            client[database].security_runs
            .find({"run_started_at": {"$gte": since}}, {"_id": False})
            .sort("run_started_at", DESCENDING)
            .limit(limit)
        )
        return list(cursor)
    finally:
        client.close()


def filter_runs(
    runs: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    search: str = "",
) -> list[Dict[str, Any]]:
    query = search.strip().lower()
    filtered = []
    for run in runs:
        if status and status != "ALL" and run.get("pipeline_status") != status:
            continue
        searchable = " ".join((
            str(run.get("run_id", "")),
            str(run.get("github", {}).get("repository", "")),
            str(run.get("github", {}).get("ref", "")),
            str(run.get("git", {}).get("commit_sha", "")),
        )).lower()
        if query and query not in searchable:
            continue
        filtered.append(run)
    return filtered


def build_overview(runs: list[Dict[str, Any]]) -> Dict[str, Any]:
    latest = runs[0] if runs else None
    status_counts = {status: 0 for status in ("COMPLETED", "BLOCKED", "ERROR")}
    for run in runs:
        current = run.get("pipeline_status")
        if current in status_counts:
            status_counts[current] += 1
    last_success = next(
        (run for run in runs if run.get("pipeline_status") == "COMPLETED"),
        None,
    )
    return {
        "latest": latest,
        "last_success": last_success,
        "status_counts": status_counts,
    }


def runs_frame(runs: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for run in runs:
        findings = run.get("findings_by_tool", {})
        rows.append({
            "run_id": str(run.get("run_id") or run.get("github", {}).get("run_id", "")),
            "started": pd.to_datetime(run.get("run_started_at"), utc=True, errors="coerce"),
            "status": run.get("pipeline_status", "UNKNOWN"),
            "decision": run.get("final_decision") or "UNAVAILABLE",
            "policy": run.get("policy_decision") or "UNAVAILABLE",
            "repository": run.get("github", {}).get("repository", "unknown"),
            "branch": run.get("github", {}).get("ref", "unknown"),
            "commit": run.get("git", {}).get("commit_sha", run.get("github", {}).get("sha", "unknown")),
            "duration_seconds": float(run.get("duration_seconds", 0)),
            "findings": sum(int(value) for value in findings.values()),
            "high": int(run.get("findings_by_severity", {}).get("HIGH", 0)),
            "critical": int(run.get("findings_by_severity", {}).get("CRITICAL", 0)),
            "gemini_available": bool(run.get("llm_available")),
            "run_url": run.get("github", {}).get("run_url"),
        })
    return pd.DataFrame(rows)


def stage_frame(run: Dict[str, Any]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "stage": name.replace("_", " ").title(),
            "status": stage.get("status", "UNKNOWN"),
            "duration_seconds": float(stage.get("duration_seconds", 0)),
            "error": stage.get("error") or "",
        }
        for name, stage in run.get("stages", {}).items()
    ])
