from __future__ import annotations

import os
import time

import altair as alt
import pandas as pd
import streamlit as st

from auth import verify_password
from configuration import mongodb_configuration_error
from dashboard_data import (
    SEVERITY_ORDER,
    build_overview,
    filter_runs,
    load_runs,
    parse_timestamp,
    runs_frame,
    severity_rows,
    stage_frame,
)


SESSION_SECONDS = 8 * 60 * 60


st.set_page_config(
    page_title="Security Pipeline Monitor",
    page_icon=":shield:",
    layout="wide",
)


def setting(name: str, default: str = "") -> str:
    try:
        value = st.secrets.get(name)
    except FileNotFoundError:
        value = None
    return str(value or os.getenv(name.upper(), default))


def authenticated() -> bool:
    login_time = st.session_state.get("login_time", 0)
    if st.session_state.get("authenticated") and time.time() - login_time < SESSION_SECONDS:
        return True
    st.session_state["authenticated"] = False
    return False


def login() -> None:
    st.title("Security Pipeline Monitor")
    st.caption("Private access to sanitized CI security metrics")
    password_hash = setting("dashboard_password_hash")
    if not password_hash:
        st.error("Dashboard password hash is not configured.")
        st.stop()
    with st.form("login_form", clear_on_submit=True):
        password = st.text_input("Dashboard password", type="password")
        submitted = st.form_submit_button("Sign in", width="stretch")
    if submitted:
        if verify_password(password, password_hash):
            st.session_state["authenticated"] = True
            st.session_state["login_time"] = time.time()
            st.rerun()
        st.error("Invalid password.")


def format_time(value: object) -> str:
    if not value:
        return "Never"
    parsed = parse_timestamp(value)
    if parsed is None:
        return "Unknown"
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


@st.cache_data(ttl=30, show_spinner=False)
def cached_runs(uri: str, database: str, days: int) -> list[dict]:
    return load_runs(uri, database, days=days)


def render_dashboard() -> None:
    with st.sidebar:
        st.header("SecMonitor")
        st.caption("Security pipeline operations")
        days = st.select_slider("History", options=[7, 14, 30, 60, 90], value=30)
        if st.button("Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
        if st.button("Log out", width="stretch"):
            st.session_state.clear()
            st.rerun()

    st.title("Security pipeline overview")
    st.caption("Scanner health, policy decisions, and sanitized execution history")

    uri = setting("mongodb_uri")
    database = setting("mongodb_database", "security_monitor")
    configuration_error = mongodb_configuration_error(uri)
    if configuration_error:
        st.error(configuration_error)
        st.stop()
    try:
        runs = cached_runs(uri, database, days)
    except Exception as exc:
        st.error(f"Monitoring database is unavailable: {str(exc)[:300]}")
        st.stop()

    if not runs:
        st.info("No monitoring runs are available for the selected period.")
        st.stop()

    overview = build_overview(runs)
    latest = overview["latest"]
    findings = latest.get("findings_by_severity", {})
    total_findings = sum(latest.get("findings_by_tool", {}).values())

    status, decision, finding_metric, duration, gemini = st.columns(5)
    status.metric("Pipeline status", latest.get("pipeline_status", "UNKNOWN"))
    decision.metric("Final decision", latest.get("final_decision") or "UNAVAILABLE")
    finding_metric.metric("Findings", total_findings, f"{findings.get('CRITICAL', 0)} critical")
    duration.metric("Duration", f"{latest.get('duration_seconds', 0)}s")
    gemini.metric("Gemini", "Available" if latest.get("llm_available") else "Unavailable")
    st.caption(f"Latest run: {format_time(latest.get('run_finished_at'))}")

    health_tab, trends_tab, history_tab = st.tabs(("Health", "Trends", "Run history"))

    with health_tab:
        left, right = st.columns((2, 1))
        with left:
            st.subheader("Scanner health")
            scanner_rows = [
                {"scanner": name.title(), "status": details.get("status", "UNKNOWN"), "error": details.get("error") or ""}
                for name, details in latest.get("scanner_health", {}).items()
            ]
            st.dataframe(scanner_rows, hide_index=True, width="stretch")
        with right:
            st.subheader("Run outcomes")
            counts = pd.DataFrame([
                {"status": key, "runs": value}
                for key, value in overview["status_counts"].items()
            ])
            st.bar_chart(counts, x="status", y="runs", horizontal=True)

        severity = pd.DataFrame(severity_rows(latest.get("findings_by_severity", {})))
        severity_chart = alt.Chart(severity).mark_bar().encode(
            x=alt.X("severity:N", title="Severity", sort=list(SEVERITY_ORDER)),
            y=alt.Y("findings:Q", title="Findings"),
            color=alt.Color(
                "severity:N",
                title="Severity",
                scale=alt.Scale(
                    domain=list(SEVERITY_ORDER),
                    range=["#dc2626", "#f97316", "#eab308", "#16a34a"],
                ),
            ),
            tooltip=("severity:N", "findings:Q"),
        )
        st.subheader("Latest findings by severity")
        st.altair_chart(severity_chart, width="stretch")

    with trends_tab:
        frame = runs_frame(reversed(runs))
        if frame.empty:
            st.info("No trend data is available.")
        else:
            duration_chart = alt.Chart(frame).mark_line(point=True).encode(
                x=alt.X("started:T", title="Run time"),
                y=alt.Y("duration_seconds:Q", title="Seconds"),
                color=alt.Color("status:N", title="Status"),
                tooltip=("run_id", "status", "duration_seconds", "started"),
            ).properties(title="Pipeline duration")
            st.altair_chart(duration_chart, width="stretch")

            severity_chart = alt.Chart(frame).transform_fold(
                ["high", "critical"], as_=["severity", "findings"]
            ).mark_bar().encode(
                x=alt.X("started:T", title="Run time"),
                y=alt.Y("findings:Q", title="Findings"),
                color=alt.Color("severity:N", scale=alt.Scale(domain=["high", "critical"], range=["#f59e0b", "#ef4444"])),
                tooltip=("run_id", "severity:N", "findings:Q"),
            ).properties(title="High and critical findings")
            st.altair_chart(severity_chart, width="stretch")

            availability = round(frame["gemini_available"].mean() * 100, 1)
            st.metric("Gemini availability", f"{availability}%", f"Last {len(frame)} runs")

    with history_tab:
        filter_one, filter_two = st.columns((1, 2))
        selected_status = filter_one.selectbox("Status", ("ALL", "COMPLETED", "BLOCKED", "ERROR"))
        search = filter_two.text_input("Search", placeholder="Run ID, repository, branch, or commit")
        filtered = filter_runs(runs, status=selected_status, search=search)
        frame = runs_frame(filtered)
        if frame.empty:
            st.info("No runs match the selected filters.")
        else:
            table = frame[["run_id", "started", "status", "decision", "repository", "branch", "commit", "findings", "duration_seconds"]]
            st.dataframe(table, hide_index=True, width="stretch")
            selected_id = st.selectbox("Inspect run", frame["run_id"].tolist())
            selected = next(run for run in filtered if str(run.get("run_id") or run.get("github", {}).get("run_id")) == selected_id)
            st.subheader(f"Run {selected_id}")
            detail_one, detail_two, detail_three = st.columns(3)
            detail_one.metric("Policy", selected.get("policy_decision") or "UNAVAILABLE")
            detail_two.metric("Final", selected.get("final_decision") or "UNAVAILABLE")
            detail_three.metric("Duration", f"{selected.get('duration_seconds', 0)}s")
            stages = stage_frame(selected)
            if not stages.empty:
                st.dataframe(stages, hide_index=True, width="stretch")
            if selected.get("error"):
                st.error(f"{selected['error'].get('category')}: {selected['error'].get('message')}")
            run_url = selected.get("github", {}).get("run_url")
            if run_url:
                st.link_button("Open GitHub Actions run", run_url)


if not authenticated():
    login()
else:
    render_dashboard()
