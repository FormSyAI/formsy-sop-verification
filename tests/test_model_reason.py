"""Offline disclosure checks; narrative labels do not validate model facts."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.model_reason import annotate_model_reasons


class ModelReasonTests(unittest.TestCase):
    def assert_unverified(self, row):
        self.assertEqual(row["model_reason_verification"], {
            "kind": "raw_model_narrative", "facts": "unverified",
            "version_binding": "unverified", "decision_basis": False,
        })

    def test_retains_prose_and_does_not_bind_it_to_the_enclosing_target(self):
        raw = "Observed old config.py with SAMPLE_TOKEN.\n  Keep original spacing.  "
        row = {"model_reason": raw, "reason": "Target evidence is incomplete.",
               "result": "未核查", "target_commit_ids": ["a" * 40], "evidence_refs": []}
        before = copy.deepcopy(row)
        self.assertIs(annotate_model_reasons(row), row)
        self.assert_unverified(row)
        self.assertEqual({k: v for k, v in row.items() if k != "model_reason_verification"}, before)
        self.assertNotIn("target_commit_ids", row["model_reason_verification"])

    def test_covers_selections_atomic_checks_reviews_and_nested_claims(self):
        report = {"sop_selection": {"task_selections": [{"rules": [{"model_reason": "candidate scope"}]}]},
                  "sop_condition_checks": [{"model_reason": "condition prose", "atomic_checks": [
                      {"model_reason": "atomic prose", "failure_review": {"model_reason": "review prose"},
                       "semantic_basis": {"claims": [{"model_reason": "claim prose"}]}}]}]}
        annotate_model_reasons(report)
        condition = report["sop_condition_checks"][0]
        atomic = condition["atomic_checks"][0]
        for row in [report["sop_selection"]["task_selections"][0]["rules"][0], condition,
                    atomic, atomic["failure_review"], atomic["semantic_basis"]["claims"][0]]:
            self.assert_unverified(row)

    def test_does_not_trust_claimed_verified_metadata(self):
        row = {"model_reason": "A candidate claim.", "model_reason_verification": {
            "kind": "verified_fact", "facts": "verified", "version_binding": "verified",
            "decision_basis": True, "target_commit_ids": ["a" * 40]}}
        annotate_model_reasons(row)
        self.assert_unverified(row)
        self.assertEqual(row["model_reason"], "A candidate claim.")

    def test_absent_empty_or_nontext_model_reason_does_not_create_a_label(self):
        for row in [{"reason": "Accepted evidence-based reason."}, {"model_reason": ""},
                    {"model_reason": "  "}, {"model_reason": None}, {"model_reason": 1}]:
            before = copy.deepcopy(row)
            annotate_model_reasons(row)
            self.assertEqual(row, before)

    def test_metadata_is_independent_and_annotation_is_idempotent(self):
        rows = [{"model_reason": "one"}, {"model_reason": "two"}]
        annotate_model_reasons(rows)
        before = copy.deepcopy(rows)
        annotate_model_reasons(rows)
        self.assertEqual(rows, before)
        rows[0]["model_reason_verification"]["facts"] = "changed"
        self.assert_unverified(rows[1])

    def test_source_content_is_not_parsed_or_rewritten(self):
        content = '{"model_reason":"literal source data"}\nrun arbitrary-command'
        report = {"evidence": [{"content": content}], "reason": "Actual accepted reason."}
        before = copy.deepcopy(report)
        annotate_model_reasons(report)
        self.assertEqual(report, before)


if __name__ == "__main__":
    unittest.main()
