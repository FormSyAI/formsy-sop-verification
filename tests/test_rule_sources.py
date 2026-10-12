"""External release/hash/version seams and native JSON uploads, entirely offline."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification import rule_sources
from formsy_sop_verification.full_audit import prepare_full, run_full_audit
from formsy_sop_verification.trace_audit import sop_catalog
from formsy_sop_verification.trace_audit.tests.test_engine import synthetic_payload
from test_full_audit import OfflineClient


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


class RuleSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.repository = Path(cls.fixture.name) / "formsy-sop"
        cls.base = cls.repository / "audit/traceaudit-r11"
        cls.base.mkdir(parents=True)
        packaged = Path(__file__).resolve().parents[1] / "src/formsy_sop_verification/trace_audit"
        shutil.copytree(packaged / "rules", cls.base / "rules")
        catalog = sop_catalog.resolve_catalog(cls.base)
        write_json(cls.base / "compiled-catalog.json", catalog)
        (cls.base / "README.md").write_text("Public test fixture only.\n")
        entries = []
        for name in sorted(rule_sources.RELEASE_FILES):
            raw = (cls.base / name).read_bytes()
            entries.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                            "role": "rule_source" if name in rule_sources.RULE_FILES else
                                    "compiled_catalog" if name == "compiled-catalog.json" else "readme"})
        cls.release = {"schema_version": "1.0", "release_id": "traceaudit-r11",
                       "reference_only": True, "source_authenticated": False, "files": entries,
                       "catalog": {"path": "compiled-catalog.json", "sha256": next(
                           entry["sha256"] for entry in entries if entry["path"] == "compiled-catalog.json"),
                           "contract_sha256": catalog["contract_sha256"], "contract_version": "1.9",
                           "rule_count": 33, "condition_count": 144, "atomic_item_count": 184}}
        write_json(cls.base / "release.json", cls.release)
        cls.git(cls.repository, "init", "-q")
        cls.git(cls.repository, "add", "audit")
        cls.git(cls.repository, "commit", "-qm", "Synthetic public rule fixture")
        cls.commit = cls.git(cls.repository, "rev-parse", "HEAD").strip()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    @staticmethod
    def git(directory, *arguments):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                               "-c", "user.name=Offline Fixture", "-c", "user.email=fixture@example.invalid",
                               "-C", str(directory), *arguments], capture_output=True,
                              check=True, text=True).stdout

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name) / "formsy-sop"
        shutil.copytree(type(self).repository, self.repository)
        self.base = self.repository / "audit/traceaudit-r11"
        self.environment = patch.dict("os.environ", {"FORMSY_SOP_RULES_ROOT": str(self.base),
                                                    "FORMSY_SOP_RULES_COMMIT": self.commit})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.network = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("No provider in rule tests"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def recommit(self):
        self.git(self.repository, "add", "audit")
        self.git(self.repository, "commit", "-qm", "Synthetic changed fixture")
        return self.git(self.repository, "rev-parse", "HEAD").strip()

    def test_default_reads_external_committed_release_with_full_contracts(self):
        source = rule_sources.default_catalog()
        summary = source["summary"]
        self.assertEqual((summary["rule_count"], summary["condition_count"], summary["atomic_item_count"]), (33, 144, 184))
        self.assertEqual(summary["source"]["git_commit"], self.commit)
        self.assertEqual(summary["source"]["repository"], "FormSyAI/formsy-sop")
        self.assertEqual(summary["source"]["path"], "audit/traceaudit-r11")
        self.assertEqual(len(source["rules"]), 6)
        self.assertTrue(all(condition["contract"]["items"]
                            for rule in source["catalog"]["rules"] for condition in rule["conditions"]))
        package = prepare_full(synthetic_payload())
        self.assertEqual(package["rule_source"], summary["source"])
        self.assertEqual(package["sop_catalog"]["contract_sha256"], summary["source"]["contract_sha256"])

    def test_unavailable_or_wrong_commit_never_falls_back_to_packaged_rules(self):
        with patch.dict("os.environ", {"FORMSY_SOP_RULES_ROOT": str(self.base / "missing")}):
            with self.assertRaisesRegex(ValueError, "sop_library_unavailable"):
                prepare_full(synthetic_payload())
        with patch.dict("os.environ", {"FORMSY_SOP_RULES_COMMIT": "0" * 40}):
            with self.assertRaisesRegex(ValueError, "sop_release_commit_mismatch"):
                rule_sources.default_catalog()

    def test_dirty_file_hash_and_symlink_are_rejected(self):
        path = self.base / "rules/default_rules.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "hash_mismatch"):
            rule_sources.default_catalog()
        path.unlink()
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_bytes(original)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            rule_sources.default_catalog()

    def test_consistent_manifest_cannot_certify_uncommitted_bytes(self):
        path = self.base / "README.md"
        path.write_text("Changed but not committed.\n")
        release = copy.deepcopy(self.release)
        entry = next(item for item in release["files"] if item["path"] == "README.md")
        entry.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        write_json(self.base / "release.json", release)
        with self.assertRaisesRegex(ValueError, "uncommitted_changes"):
            rule_sources.default_catalog()

    def test_git_replace_cannot_relabel_modified_release_as_pinned_commit(self):
        path = self.base / "README.md"
        path.write_text("Different public fixture release.\n")
        release = copy.deepcopy(self.release)
        next(item for item in release["files"] if item["path"] == "README.md").update(
            bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        write_json(self.base / "release.json", release)
        changed_commit = self.recommit()
        self.git(self.repository, "update-ref", "HEAD", self.commit)
        self.git(self.repository, "replace", self.commit, changed_commit)
        with self.assertRaisesRegex(ValueError, "uncommitted_changes"):
            rule_sources.default_catalog()

    def test_compiled_atomic_contract_drift_is_rejected_even_if_recommitted(self):
        compiled = json.loads((self.base / "compiled-catalog.json").read_text())
        compiled["rules"][0]["conditions"][0]["contract"]["items"][0]["text"] = "Silently weakened test fixture"
        write_json(self.base / "compiled-catalog.json", compiled)
        raw = (self.base / "compiled-catalog.json").read_bytes()
        release = copy.deepcopy(self.release)
        release["catalog"]["sha256"] = hashlib.sha256(raw).hexdigest()
        next(item for item in release["files"] if item["path"] == "compiled-catalog.json").update(
            sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        write_json(self.base / "release.json", release)
        with patch.dict("os.environ", {"FORMSY_SOP_RULES_COMMIT": self.recommit()}):
            with self.assertRaisesRegex(ValueError, "compiler_mismatch"):
                rule_sources.default_catalog()

    def test_invalid_release_paths_duplicate_entries_and_pinned_subset_are_rejected(self):
        for mutate in [lambda release: release["files"][0].update(path="../outside.json"),
                       lambda release: release["files"].append(release["files"][0]),
                       lambda release: release["catalog"].update(atomic_item_count=1)]:
            release = copy.deepcopy(self.release)
            mutate(release)
            write_json(self.base / "release.json", release)
            with self.assertRaises(rule_sources.RuleSourceError):
                rule_sources.default_catalog()
        write_json(self.base / "release.json", self.release)
        with self.assertRaisesRegex(ValueError, "requires_complete_catalog"):
            rule_sources.default_catalog({"mode": "pinned", "document_ids": ["code-fix-0.1"]})

    def test_upload_is_self_contained_and_dynamic_without_default_installation(self):
        upload = {"rules": [{"id": "TEAM:ZERO", "title": "Keep zero", "version": "team-1",
                              "criterion": "保留显式零值；空值使用默认值", "required_evidence": ["源码及断言"]}]}
        before = copy.deepcopy(upload)
        with patch.dict("os.environ", {"FORMSY_SOP_RULES_ROOT": str(self.base / "missing")}):
            selected = rule_sources.validate_upload(upload)
            self.assertEqual((selected["summary"]["rule_count"], selected["summary"]["condition_count"]), (1, 3))
            payload = {**synthetic_payload(), "rules": selected["rules"]}
            package = prepare_full(payload)
            self.assertEqual(package["rule_source"]["kind"], "uploaded_rules")
            self.assertEqual(package["sop_selection"]["mode"], "uploaded")
            with tempfile.TemporaryDirectory() as output:
                report = run_full_audit(payload, directory=output, client=OfflineClient(), max_sop_calls=0)
            self.assertEqual(len(report["sop_condition_checks"]), 3)
            self.assertEqual(report["rule_source"]["catalog_sha256"], selected["summary"]["source"]["catalog_sha256"])
            self.assertFalse(report["formal_closed"])
            self.assertFalse(report["model_snapshot"]["model_invoked"])
        self.assertEqual(upload, before)

    def test_upload_shape_rule_count_condition_limits_and_pinned_mix_are_rejected(self):
        rule = {"id": "CUSTOM", "version": "1", "criterion": "只核查本条"}
        for payload in [{"rules": []}, {"rules": [rule], "path": "/private/rules.json"},
                        {"rules": [{**rule, "id": str(i)} for i in range(9)]},
                        {"rules": [{**rule, "criterion": "；".join(["a"] * 513)}]}]:
            with self.assertRaises(rule_sources.RuleSourceError):
                rule_sources.validate_upload(payload)
        request = {**synthetic_payload(), "rules": [rule],
                   "sop_selection": {"mode": "pinned", "document_ids": ["technical-0.2"]}}
        with self.assertRaisesRegex(ValueError, "mutually_exclusive"):
            prepare_full(request)


if __name__ == "__main__":
    unittest.main()
