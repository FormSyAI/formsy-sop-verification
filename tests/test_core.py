import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from formsy_sop_verification.core import decode_json, verify, load_profile, MAX_INPUT_BYTES
from formsy_sop_verification.legacy_evidence import aggregate
from formsy_sop_verification.model_client import ProviderError
from fixtures import request, ready_request, candidate, TARGET


class CoreTests(unittest.TestCase):
    def test_valid_candidate_remains_candidate_and_execution_unknown(self):
        payload = ready_request()
        original = copy.deepcopy(payload)
        report = verify(payload)
        self.assertEqual(payload, original)
        self.assertEqual(report["summary"]["counts"], {"not_applicable": 0, "satisfied": 3, "unsatisfied": 0, "unverified": 1})
        self.assertTrue(report["analysis_complete"])
        self.assertFalse(report["formal_closed"])
        self.assertEqual(report["review_state"], "model_candidate")
        self.assertEqual(report["checks"][-1]["candidate_result"], "satisfied")
        self.assertEqual(report["checks"][-1]["result"], "unverified")
        self.assertFalse(report["model"]["invoked"])

    def test_exact_source_ref_survives_without_model_locator_override(self):
        payload = ready_request()
        report = verify(payload)
        ref = report["checks"][0]["items"][0]["evidence_refs"][0]
        self.assertEqual(ref["locator"], payload["sources"][0]["locator"])
        payload["candidate"]["checks"][0]["items"][0]["evidence_refs"][0]["locator"] = {"kind": "turn", "turn_id": "fake"}
        report = verify(payload)
        self.assertEqual(report["checks"][0]["result"], "unverified")
        self.assertFalse(report["analysis_complete"])

    def test_no_candidate_does_not_infer_success(self):
        report = verify(request())
        self.assertEqual(report["summary"]["counts"]["unverified"], 4)
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(report["coverage"]["unmapped_sections"], ["constraints", "impact", "preparation"])
        self.assertFalse(report["coverage"]["complete_sop"])

    def test_missing_atomic_obligation_cannot_pass_compound(self):
        payload = ready_request()
        payload["candidate"]["checks"][0]["items"].pop()
        report = verify(payload)
        self.assertIn("atomic_item_set_mismatch", report["checks"][0]["validation_errors"])
        self.assertEqual(report["checks"][0]["result"], "unverified")

    def test_malformed_condition_identity_returns_failed_unknown_report(self):
        for malformed in ([], {}, None, True, 7):
            with self.subTest(identity=malformed):
                payload = ready_request()
                payload["candidate"]["checks"][0]["condition_id"] = malformed
                report = verify(payload)
                self.assertFalse(report["analysis_complete"])
                self.assertEqual(report["summary"]["counts"]["unverified"], 4)
                self.assertIn("candidate_condition_set_mismatch", report["analysis_errors"])

    def test_failure_dominates_unknown_and_parent_disagreement(self):
        payload = ready_request()
        row = payload["candidate"]["checks"][1]
        row["items"][0]["result"] = "unsatisfied"
        row["items"][1]["result"] = "unverified"
        report = verify(payload)
        self.assertEqual(report["checks"][1]["result"], "unsatisfied")
        self.assertEqual(report["summary"]["result"], "unsatisfied")
        self.assertFalse(report["analysis_complete"])

    def test_invalid_citations_are_retained_as_unknown(self):
        for change in ({"source_id": "missing"}, {"quote": "invented"}, {"start_line": True}, {"end_line": 999}):
            with self.subTest(change=change):
                payload = ready_request()
                payload["candidate"]["checks"][0]["items"][0]["evidence_refs"][0].update(change)
                report = verify(payload)
                self.assertEqual(report["checks"][0]["result"], "unverified")
                self.assertFalse(report["analysis_complete"])
                self.assertEqual(report["checks"][1]["result"], "satisfied")

    def test_assistant_claim_is_not_user_requirement(self):
        payload = ready_request()
        payload["sources"][0]["kind"] = "assistant_message"
        report = verify(payload)
        self.assertEqual(report["checks"][0]["result"], "unverified")

    def test_wrong_or_missing_target_keeps_change_mapping_unknown(self):
        for target in (None, "abcdef0", "b" * 40):
            with self.subTest(target=target):
                payload = ready_request()
                if target is None:
                    del payload["context"]["target_commit"]
                else:
                    payload["context"]["target_commit"] = target
                self.assertEqual(verify(payload)["checks"][1]["result"], "unverified")

    def test_no_diff_cannot_prove_bidirectional_change_coverage(self):
        payload = ready_request()
        payload["sources"][1]["kind"] = "source"
        self.assertEqual(verify(payload)["checks"][1]["result"], "unverified")

    def test_wrong_chapter_or_forged_sop_quote_cannot_activate_reference_rule(self):
        for change in ({"pointer": "/sections/2/items/0/1"}, {"quote": "not published"}):
            with self.subTest(change=change):
                payload = ready_request()
                payload["candidate"]["checks"][0]["sop_refs"][0].update(change)
                report = verify(payload)
                self.assertEqual(report["checks"][0]["result"], "unverified")
                self.assertFalse(report["analysis_complete"])

    def test_missing_evidence_cannot_turn_into_not_applicable(self):
        payload = ready_request()
        row = payload["candidate"]["checks"][1]
        row["result"] = "not_applicable"
        for item in row["items"]:
            item.update(result="not_applicable", evidence_refs=[])
        self.assertEqual(verify(payload)["checks"][1]["result"], "unverified")

    def test_duplicate_condition_or_source_is_rejected(self):
        payload = ready_request()
        payload["candidate"]["checks"][1] = copy.deepcopy(payload["candidate"]["checks"][0])
        report = verify(payload)
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(report["checks"][0]["result"], "unverified")
        payload = ready_request()
        payload["sources"].append(copy.deepcopy(payload["sources"][0]))
        with self.assertRaises(ValueError):
            verify(payload)

    def test_project_pin_is_preserved_but_cross_project_is_rejected(self):
        payload = ready_request()
        report = verify(payload)
        self.assertEqual(report["sop_pin"], {key: payload["sop"][key] for key in ("project_id", "sop_id", "version", "digest")})
        payload["sop"]["project_id"] = "other"
        with self.assertRaises(ValueError):
            verify(payload)

    def test_rejects_oversized_source_material_and_bad_locator(self):
        payload = request()
        payload["sources"][0]["content"] = "x" * 320001
        with self.assertRaises(ValueError):
            verify(payload)
        payload = request()
        del payload["sources"][0]["locator"]["turn_id"]
        with self.assertRaises(ValueError):
            verify(payload)

    def test_decode_rejects_duplicate_keys_nan_and_surrogates(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\\ud800"}', b'{"x":1} {}'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                decode_json(raw)

    def test_model_call_is_mocked_once_and_receives_only_redacted_source_text(self):
        payload = request()
        payload["mode"] = "model"
        key = "sk-" + "SENSITIVE" * 8
        payload["sources"].append({"id": "secret", "kind": "context", "content": "API_KEY=" + key,
                                   "locator": {"kind": "turn", "session_id": "fixture-session", "turn_id": "fixture-turn"}})
        class Client:
            model = "fixture-model"
            request_count = 0
            def complete(self, system, data):
                self.request_count += 1
                self.payload = data
                return candidate(payload)
        client = Client()
        report = verify(payload, client)
        self.assertNotIn(key, json.dumps(client.payload))
        self.assertNotIn(key, json.dumps(report))
        self.assertEqual(report["model"]["request_count"], 1)
        self.assertTrue(report["model"]["invoked"])

    def test_production_mode_rejects_supplied_candidate(self):
        payload = ready_request()
        payload["mode"] = "model"
        with self.assertRaises(ValueError):
            verify(payload)

    def test_provider_failure_yields_unknown_report_with_failed_status(self):
        payload = request()
        payload["mode"] = "model"
        class Client:
            model = "fixture-model"
            request_count = 1
            def complete(self, *_):
                raise ProviderError("provider_network_or_timeout")
        report = verify(payload, Client())
        self.assertEqual(report["model"]["status"], "failed")
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(report["summary"]["counts"]["unverified"], 4)

    def test_missing_key_does_not_attempt_network_or_read_dotenv(self):
        payload = request()
        payload["mode"] = "model"
        with patch.dict(os.environ, {}, clear=True), patch("urllib.request.urlopen") as network:
            report = verify(payload)
        network.assert_not_called()
        self.assertEqual(report["model"]["status"], "failed")
        self.assertEqual(report["model"]["request_count"], 0)
        self.assertIn("provider_not_configured", report["analysis_errors"])

    def test_profile_has_fixed_source_bound_atomic_contracts(self):
        profile = load_profile()
        self.assertEqual(len(profile["conditions"]), 4)
        self.assertEqual(sum(len(row["contract"]["items"]) for row in profile["conditions"]), 16)
        self.assertEqual(profile["status"], "draft_reference_subset")

    def test_aggregation_retains_known_failure(self):
        self.assertEqual(aggregate(["unverified", "unsatisfied"]), "unsatisfied")
        self.assertEqual(aggregate(["satisfied", "unverified"]), "unverified")
        self.assertEqual(aggregate(["not_applicable"]), "not_applicable")

    def test_partial_or_unknown_capture_blocks_pass_but_retains_supported_failure(self):
        for completeness in ("partial", None):
            with self.subTest(completeness=completeness):
                payload = ready_request()
                if completeness:
                    payload["context"]["evidence_completeness"] = completeness
                else:
                    del payload["context"]["evidence_completeness"]
                row = payload["candidate"]["checks"][1]
                row["result"] = "unsatisfied"
                row["items"][0]["result"] = "unsatisfied"
                report = verify(payload)
                self.assertEqual(report["checks"][0]["result"], "unverified")
                self.assertEqual(report["checks"][1]["result"], "unsatisfied")
                self.assertEqual(report["summary"]["counts"]["satisfied"], 0)

    def test_redacted_placeholder_is_not_accepted_as_original_quote(self):
        payload = ready_request()
        payload["sources"][3]["content"] = "API_KEY=sk-" + "sensitive" * 8
        row = payload["candidate"]["checks"][0]
        row["items"][2]["evidence_refs"][0]["quote"] = "API_KEY=[REDACTED]"
        report = verify(payload)
        self.assertEqual(report["checks"][0]["result"], "unverified")
        self.assertTrue(report["source_index"]["context"]["redacted"])
        self.assertNotIn("sensitive", json.dumps(report))

    def test_no_user_source_skips_model_completely(self):
        payload = request()
        payload["mode"] = "model"
        payload["sources"][0]["kind"] = "assistant_message"
        with patch("urllib.request.urlopen") as network:
            report = verify(payload)
        network.assert_not_called()
        self.assertEqual(report["model"]["request_count"], 0)
        self.assertIn("missing_user_requirement", report["analysis_errors"])

    def test_lf_coordinates_match_server_and_do_not_reinterpret_unicode_separators(self):
        payload = ready_request()
        payload["sources"][0]["content"] = "first\r\nsecond\u2028still-second\n"
        for row in payload["candidate"]["checks"]:
            for ref in row["evidence_refs"]:
                if ref["source_id"] == "user":
                    ref["quote"] = "first"
            for item in row["items"]:
                for ref in item["evidence_refs"]:
                    if ref["source_id"] == "user":
                        ref.update(start_line=2, end_line=2, quote="second\u2028still-second")
        report = verify(payload)
        self.assertTrue(report["analysis_complete"])
        payload["candidate"]["checks"][0]["items"][0]["evidence_refs"][0].update(start_line=1, end_line=1, quote="first\r\n")
        self.assertFalse(verify(payload)["analysis_complete"])


class CLITests(unittest.TestCase):
    def cli(self, raw):
        script = Path(__file__).resolve().parents[1] / "scripts/verify.py"
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run([sys.executable, "-I", str(script)], input=raw, capture_output=True, timeout=10, cwd=directory)

    def test_isolated_cli_from_other_cwd_outputs_one_report(self):
        result = self.cli(json.dumps(ready_request(), ensure_ascii=False).encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"]["counts"]["satisfied"], 3)
        self.assertEqual(result.stderr, b"")

    def test_cli_rejects_oversize_and_duplicate_json_without_echo(self):
        for raw in (b"x" * (MAX_INPUT_BYTES + 1), b'{"schema_version":1,"schema_version":1}'):
            with self.subTest(size=len(raw)):
                result = self.cli(raw)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["error"]["code"], "invalid_request")
                self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
