from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_system.application.aggregate_pipeline import run_aggregation
from security_system.application.scanner_job import run_scanner_job
from security_system.domain.models import AnalysisResult, GitContext


def _manifest(directory: Path, tool: str, status: str = "COMPLETED", error=None) -> None:
    (directory / f"{tool}-manifest.json").write_text(json.dumps({
        "schema_version": "1.0",
        "tool": tool,
        "status": status,
        "duration_seconds": 1.25,
        "report": f"{tool}-report.json",
        "error": error,
    }), encoding="utf-8")


def _empty_reports(directory: Path) -> None:
    (directory / "gitleaks-report.json").write_text("[]", encoding="utf-8")
    (directory / "semgrep-report.json").write_text('{"results": []}', encoding="utf-8")
    (directory / "trivy-report.json").write_text('{"Results": []}', encoding="utf-8")


def _unavailable_analysis(*args, **kwargs) -> AnalysisResult:
    return AnalysisResult.fallback("2026-06-15T00:00:00", "LLM unavailable")


class ScannerJobTest(unittest.TestCase):
    def test_success_and_empty_findings_write_valid_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)

            def empty_scanner(target, output_path):
                return []

            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"gitleaks": empty_scanner},
                clear=False,
            ):
                manifest = run_scanner_job("gitleaks", Path("."), output)

            self.assertEqual(manifest["status"], "COMPLETED")
            self.assertEqual(json.loads((output / "gitleaks-report.json").read_text()), [])

    def test_missing_binary_or_timeout_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"trivy": lambda target, output_path: None},
                clear=False,
            ):
                manifest = run_scanner_job("trivy", Path("."), output)

            self.assertEqual(manifest["status"], "ERROR")
            self.assertIn("failed or is unavailable", manifest["error"])

    def test_install_failure_records_error_without_running_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = run_scanner_job(
                "semgrep",
                Path("."),
                Path(tmp),
                installation_status="failure",
            )

        self.assertEqual(manifest["status"], "ERROR")
        self.assertIn("installation failed", manifest["error"])

    def test_malformed_output_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)

            def malformed(target, output_path):
                output_path.write_text("not-json", encoding="utf-8")
                return []

            with patch.dict(
                "security_system.application.scanner_job.SCANNERS",
                {"semgrep": malformed},
                clear=False,
            ):
                manifest = run_scanner_job("semgrep", Path("."), output)

            self.assertEqual(manifest["status"], "ERROR")


class AggregationPipelineTest(unittest.TestCase):
    def _run(self, scanner_dir: Path, reports_dir: Path):
        with patch(
            "security_system.application.aggregate_pipeline.GitService.get_context",
            return_value=GitContext.empty(),
        ), patch(
            "security_system.application.aggregate_pipeline.analyze",
            side_effect=_unavailable_analysis,
        ):
            return run_aggregation(scanner_dir, reports_dir)

    def test_empty_successful_reports_pass(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            for tool in ("gitleaks", "semgrep", "trivy"):
                _manifest(scanner_dir, tool)

            decision = self._run(scanner_dir, Path(reports))

            self.assertEqual(decision.decision, "PASS")

    def test_high_and_medium_findings_fail_and_block_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            semgrep = {
                "results": [{
                    "check_id": f"rule-{index}",
                    "severity": "WARNING",
                    "path": "app.py",
                    "start": {"line": index + 1},
                    "extra": {"message": "medium finding"},
                } for index in range(7)]
            }
            trivy = {"Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": f"CVE-{index}",
                    "PkgName": "pkg",
                    "Severity": "HIGH",
                    "Title": "high finding",
                } for index in range(21)],
            }]}
            (scanner_dir / "semgrep-report.json").write_text(json.dumps(semgrep), encoding="utf-8")
            (scanner_dir / "trivy-report.json").write_text(json.dumps(trivy), encoding="utf-8")
            for tool in ("gitleaks", "semgrep", "trivy"):
                _manifest(scanner_dir, tool)

            reports_dir = Path(reports)
            decision = self._run(scanner_dir, reports_dir)
            monitor = json.loads((reports_dir / "monitor_report.json").read_text())

            self.assertEqual(decision.decision, "FAIL")
            self.assertEqual(decision.exit_code(), 1)
            self.assertEqual(monitor["pipeline_status"], "BLOCKED")
            self.assertEqual(monitor["findings_by_severity"]["HIGH"], 21)
            self.assertEqual(monitor["findings_by_severity"]["MEDIUM"], 7)

    def test_failed_scanner_preserves_available_findings_and_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
            scanner_dir = Path(scans)
            _empty_reports(scanner_dir)
            semgrep = {"results": [{
                "check_id": "rule",
                "severity": "WARNING",
                "path": "app.py",
                "start": {"line": 1},
                "extra": {"message": "medium finding"},
            }]}
            (scanner_dir / "semgrep-report.json").write_text(json.dumps(semgrep), encoding="utf-8")
            _manifest(scanner_dir, "gitleaks")
            _manifest(scanner_dir, "semgrep")
            _manifest(scanner_dir, "trivy", "ERROR", "scanner timed out")

            reports_dir = Path(reports)
            decision = self._run(scanner_dir, reports_dir)
            summary = json.loads((reports_dir / "summary.json").read_text())
            monitor = json.loads((reports_dir / "monitor_report.json").read_text())

            self.assertEqual(decision.decision, "FAIL")
            self.assertEqual(summary["by_severity"]["MEDIUM"], 1)
            self.assertEqual(monitor["pipeline_status"], "ERROR")

    def test_missing_or_malformed_artifact_fails_closed(self) -> None:
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as scans, tempfile.TemporaryDirectory() as reports:
                scanner_dir = Path(scans)
                _empty_reports(scanner_dir)
                _manifest(scanner_dir, "gitleaks")
                _manifest(scanner_dir, "semgrep")
                if malformed:
                    _manifest(scanner_dir, "trivy")
                    (scanner_dir / "trivy-report.json").write_text("bad-json", encoding="utf-8")

                decision = self._run(scanner_dir, Path(reports))

                self.assertEqual(decision.decision, "FAIL")
                monitor = json.loads((Path(reports) / "monitor_report.json").read_text())
                self.assertEqual(monitor["pipeline_status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
