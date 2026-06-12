from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from security_system.application.pipeline import _save_scanner_failure_decision


class PipelineTest(unittest.TestCase):
    def test_scanner_failure_is_blocking_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports_dir = Path(tmp)
            report = _save_scanner_failure_decision(
                reports_dir,
                RuntimeError("Trivy scanner failed or is not installed."),
            )

            saved = json.loads((reports_dir / "decision_report.json").read_text())

        self.assertEqual(report.decision, "FAIL")
        self.assertEqual(saved["decision"], "FAIL")
        self.assertEqual(saved["metadata"]["final_decision_source"], "scanner_failure")
        self.assertNotIn("risk_score", saved)
        self.assertNotIn("fail_threshold", saved)
        self.assertNotIn("warn_threshold", saved)


if __name__ == "__main__":
    unittest.main()
