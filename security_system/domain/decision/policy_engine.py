"""
Policy-based decision engine for scan issues.

Contains pure business rules that convert normalized SecurityIssue entries
into a DecisionReport.
"""

from __future__ import annotations

from datetime import datetime

from security_system.domain.models import DecisionReport, SecurityIssue


class PolicyEngine:
    """Evaluates security issues using simple severity-based policy rules."""

    def evaluate(self, issues: list[SecurityIssue]) -> DecisionReport:
        """
        Apply policy rules to a list of security issues.

        Rules (priority order):
        - Any Gitleaks secret -> FAIL
        - Any CRITICAL issue -> FAIL
        - Else any HIGH issue -> WARN
        - Else -> PASS
        """
        total_issue_count = len(issues)
        has_secret = any(issue.tool.lower() == "gitleaks" for issue in issues)
        has_critical = any(self._severity_of(issue) == "CRITICAL" for issue in issues)
        has_high = any(self._severity_of(issue) == "HIGH" for issue in issues)

        if has_secret:
            decision = "FAIL"
            summary = "Secret detected by Gitleaks; policy evaluation result is FAIL"
        elif has_critical:
            decision = "FAIL"
            summary = (
                "Critical severity issue detected; policy evaluation result is FAIL"
            )
        elif has_high:
            decision = "WARN"
            summary = "High severity issue detected; policy evaluation result is WARN"
        else:
            decision = "PASS"
            summary = "No HIGH or CRITICAL issues detected; policy evaluation result is PASS"

        return DecisionReport(
            timestamp=datetime.now().isoformat(),
            decision=decision,
            reason=summary,
            is_malicious=False,
            detected_patterns=[],
            recommendations=[],
            metadata={
                "status": decision,
                "summary": summary,
                "total_issue_count": total_issue_count,
                "gitleaks_secret_count": sum(
                    1 for issue in issues if issue.tool.lower() == "gitleaks"
                ),
            },
        )

    @staticmethod
    def _severity_of(issue: SecurityIssue) -> str:
        """Returns a normalized severity string for a SecurityIssue."""
        severity = issue.severity
        if hasattr(severity, "value"):
            return str(severity.value).upper()
        return str(severity).upper()
