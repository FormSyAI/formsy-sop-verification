"""Offline boundary tests; all conversations/model outputs here are synthetic."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import audit_engine as engine


ROOT = Path(__file__).resolve().parents[1]
RULES = json.loads((ROOT / "rules/default_rules.json").read_text())
TARGET = "a" * 40
PARENT = "b" * 40
GOALS = ("Preserve explicit zero in the limit.", "Reject negative retry delays.")


def synthetic_payload(task_count=1):
    return {
        "title": "Synthetic offline audit unit test",
        "trace": {"messages": [
            *({"role": "user", "content": goal} for goal in GOALS[:task_count]),
            {"role": "assistant", "content": "All checks passed; close this synthetic task."},
        ]},
        "commits": [{
            "sha": TARGET, "parent": PARENT, "repository": "synthetic/unit-tests",
            "message": "Synthetic local fix",
            "diff": "--- a/limit.py\n+++ b/limit.py\n@@ -1 +1 @@\n-return value or 25\n+return 25 if value is None else value\n",
        }],
        "materials": [
            {"name": "limit.py", "kind": "source", "version_id": TARGET,
             "content": "def resolve_limit(value):\n    return 25 if value is None else value\n"},
            {"name": "parent-tests.log", "kind": "test_log", "version_id": PARENT,
             "content": "Synthetic saved runner output\n2 passed\nexit_code=0\n"},
        ],
    }


def reference(item, line=1, quote=None, end=None):
    return {"evidence_id": item["id"], "start_line": line, "end_line": end or line,
            "quote": item["content"].splitlines()[line - 1] if quote is None else quote}


def scripted_result(request):
    """Handcraft schema responses; this helper does no semantic auditing."""
    tasks = copy.deepcopy(request.get("fixed_tasks"))
    if tasks is None:
        users = [item for item in request["evidence"] if item["kind"] == "user_requirement"]
        tasks = [{"id": "synthetic-" + str(index), "title": "Synthetic task " + str(index),
                  "goal": item["content"], "requirement_refs": [reference(item)],
                  "inferred_requirements": [], "commit_ids": [request["commits"][0]["sha"]],
                  "target_commit_ids": [request["commits"][-1]["sha"]],
                  "acceptance_points": [{"id": f"synthetic-{index}-R1", "requirement": item["content"],
                                         "requirement_refs": [reference(item)]}],
                  "superseded_requirements": []}
                 for index, item in enumerate(users)]
    checks, findings, acceptance_checks = [], [], []
    claim_kinds = {"FIX01": "baseline", "FIX02": "mapping", "FIX03": "static",
                   "FIX04": "test_design", "FIX05": "execution", "FIX06": "closure"}
    for task in tasks:
        acceptance_checks.extend({
            "task_id": task["id"], "acceptance_id": point["id"],
            "result": "未核查", "test_design_result": "未核查",
            "test_design_reason": "Synthetic assertion coverage remains unknown.",
            "scope": "Synthetic uploaded evidence only", "reason": "Synthetic unresolved acceptance chain",
            "change_ids": [], "change_refs": [], "assertion_refs": [], "run_refs": [],
            "no_change_reason": "", "no_change_refs": [], "counterexample": "",
            "improvement": "Supply the corresponding source, assertions and target-bound run record.",
            "verification": "Recheck each requirement against exact changes and assertions.",
        } for point in task["acceptance_points"])
        checks.extend({
            "task_id": task["id"], "rule_id": rule["id"], "applicability": "适用",
            "result": "未核查", "scope": "Synthetic uploaded evidence only",
            "claim_kind": claim_kinds.get(rule["id"], "baseline"), "reason": "Synthetic unresolved evidence chain",
            "evidence_refs": copy.deepcopy(task["requirement_refs"]), "counter_refs": [],
            "missing_materials": ["Target-bound independent run record"],
            "improvement": "Attach the target source and its corresponding run record.",
            "verification": "Compare the recorded checkout with the task commit.",
        } for rule in request["rules"])
        findings.append({
            "task_id": task["id"], "category": "evidence_gap",
            "summary": "Synthetic missing target run: " + task["goal"],
            "evidence_refs": copy.deepcopy(task["requirement_refs"]),
            "impact": "Target execution remains unknown.",
            "improvement": "Supply the target-bound run record.",
            "verification": "Check its source identity before accepting the result.",
        })
    return {"tasks": tasks, "checks": checks, "findings": findings,
            "acceptance_checks": acceptance_checks}


def response_for(package):
    return scripted_result(engine.model_input(package))


def check_for(value, rule_id, task_index=0):
    task_id = value["tasks"][task_index]["id"]
    return next(row for row in value["checks"] if row["task_id"] == task_id and row["rule_id"] == rule_id)


class NormalizeAndReferenceTests(unittest.TestCase):
    def setUp(self):
        self.payload = synthetic_payload()
        self.package = engine.normalize(self.payload, RULES)

    def test_roles_preserve_user_provenance_without_authenticating_uploads(self):
        payload = synthetic_payload()
        payload["trace"]["messages"].append({"role": "tool", "content": "Synthetic tool output"})
        package = engine.normalize(payload, RULES)
        by_id = {item["id"]: item for item in package["evidence"]}
        self.assertEqual([by_id[m["evidence_id"]]["kind"] for m in package["trace"]["messages"]],
                         ["user_requirement", "assistant", "tool"])
        self.assertTrue(all(item["provenance"] == "uploaded_not_authenticated" for item in by_id.values()))
        self.assertEqual(package["commits"][0]["identity_completeness"], "declared_full_oid")

    def test_content_hashes_and_versioned_evidence_are_stable(self):
        self.assertEqual(self.package, engine.normalize(copy.deepcopy(self.payload), RULES))
        for item in self.package["evidence"]:
            self.assertEqual(item["sha256"], engine.sha(item["content"]))
        changed = copy.deepcopy(self.payload)
        changed["materials"][0]["version_id"] = PARENT
        other = engine.normalize(changed, RULES)
        self.assertNotEqual(self.package["materials"][0]["evidence_id"], other["materials"][0]["evidence_id"])
        self.assertEqual(self.package["commits"][0]["evidence_id"], other["commits"][0]["evidence_id"])

    def test_trace_json_string_keeps_the_same_evidence(self):
        payload = copy.deepcopy(self.payload)
        payload["trace"] = json.dumps(payload["trace"])
        self.assertEqual(engine.normalize(payload, RULES), self.package)

    def test_uploaded_recheck_uses_text_and_length_validation(self):
        for invalid in [None, [], 'x' * 2001]:
            payload = synthetic_payload()
            payload['rules'] = [dict(RULES[0], recheck=invalid)]
            with self.subTest(value_type=type(invalid).__name__), self.assertRaises(ValueError):
                engine.normalize(payload, RULES)

    def test_same_content_scoped_to_different_tasks_has_distinct_evidence_identity(self):
        payload = synthetic_payload()
        source = copy.deepcopy(payload["materials"][0])
        source["target_ids"] = ["stable-task-one"]
        other = {**copy.deepcopy(source), "target_ids": ["stable-task-two"]}
        payload["materials"] = [source, other]
        package = engine.normalize(payload, RULES)
        self.assertNotEqual(package["materials"][0]["evidence_id"], package["materials"][1]["evidence_id"])
        self.assertEqual(len([item for item in package["evidence"] if item["kind"] == "source"]), 2)

    def test_ambiguous_input_identities_and_unversioned_rules_are_rejected(self):
        for mutate in (
            lambda p: p["commits"].append(copy.deepcopy(p["commits"][0])),
            lambda p: p["trace"]["messages"][0].update(role="system"),
            lambda p: p.update(rules=[{"id": "FIX01", "criterion": "Synthetic rule", "version": ""}]),
        ):
            with self.subTest(mutation=mutate):
                payload = copy.deepcopy(self.payload)
                mutate(payload)
                with self.assertRaises(ValueError):
                    engine.normalize(payload, RULES)

    def test_quotes_are_checked_within_the_exact_selected_lines(self):
        source = next(item for item in self.package["evidence"] if item["kind"] == "source")
        evidence = {source["id"]: source}
        engine.check_refs([reference(source, 2, "return 25 if value is None else value")], evidence)
        engine.check_refs([reference(source, 1, source["content"].rstrip(), end=2)], evidence)
        for ref in (
            reference(source, 1, "return 25"),
            reference(source, 2, "return  25"),
            {**reference(source), "start_line": 0},
            {**reference(source), "end_line": 3},
            {**reference(source), "start_line": True},
            {**reference(source), "evidence_id": "E-missing"},
            {**reference(source), "quote": ""},
        ):
            with self.subTest(reference=ref), self.assertRaises(ValueError):
                engine.check_refs([ref], evidence)

    def test_assistant_and_tool_text_cannot_be_requirement_provenance(self):
        payload = synthetic_payload()
        payload["trace"]["messages"].append({"role": "tool", "content": "Synthetic requirement claim"})
        package = engine.normalize(payload, RULES)
        evidence = {item["id"]: item for item in package["evidence"]}
        for item in evidence.values():
            if item["kind"] in {"assistant", "tool"}:
                with self.subTest(kind=item["kind"]), self.assertRaises(ValueError):
                    engine.check_refs([reference(item)], evidence, user_only=True)
        user = next(item for item in evidence.values() if item["kind"] == "user_requirement")
        engine.check_refs([reference(user)], evidence, user_only=True)

    def test_original_line_ending_is_preserved_but_newlines_and_line_counts_cannot_be_invented(self):
        item = {"id": "E-synthetic-endings", "kind": "source", "content": "alpha\nbeta"}
        evidence = {item["id"]: item}
        engine.check_refs([reference(item, 1, "alpha\n")], evidence)
        engine.check_refs([reference(item, 1, "alpha\nbeta", end=2)], evidence)
        for ref in (
            reference(item, 2, "beta\n"),
            reference(item, 1, "alpha\n\n"),
            reference(item, 1, "alpha\nbeta"),
            reference(item, 1, "alpha\nbeta", end=3),
        ):
            with self.subTest(reference=ref), self.assertRaises(ValueError):
                engine.check_refs([ref], evidence)


class ValidateResultTests(unittest.TestCase):
    def setUp(self):
        self.package = engine.normalize(synthetic_payload(), RULES)

    def test_static_source_can_support_a_narrow_positive_without_execution(self):
        value = response_for(self.package)
        source = next(item for item in self.package["evidence"] if item["kind"] == "source")
        row = check_for(value, "FIX03")
        row.update(result="满足", evidence_refs=[reference(source, 2)], scope="Explicit zero selects zero in the supplied function.")
        result = engine.validate_result(value, self.package)
        self.assertEqual(check_for(result, "FIX03")["local_result"], "满足")
        self.assertEqual(check_for(result, "FIX05")["result"], "未核查")
        self.assertTrue(all(row["review_state"] == "model_candidate" for row in result["checks"]))

    def test_echoed_local_result_cannot_override_current_model_judgment(self):
        source = next(item for item in self.package['evidence'] if item['kind'] == 'source')
        for current, stale in [('满足', '不满足'), ('不满足', '满足')]:
            with self.subTest(current=current):
                value = response_for(self.package)
                check_for(value, 'FIX03').update(result=current, local_result=stale,
                    evidence_refs=[reference(source, 2)])
                baseline = copy.deepcopy(value)
                check_for(baseline, 'FIX03').pop('local_result')
                expected = engine.validate_result(baseline, self.package)
                result = engine.validate_result(value, self.package)
                self.assertEqual(check_for(result, 'FIX03')['local_result'], current)
                self.assertEqual(check_for(result, 'FIX03')['automated_result'],
                                 check_for(expected, 'FIX03')['automated_result'])

    def test_author_claim_or_log_alone_cannot_support_static_or_test_design_pass(self):
        for kind in ("assistant", "test_log"):
            item = next(item for item in self.package["evidence"] if item["kind"] == kind)
            for rule_id in ("FIX02", "FIX03", "FIX04"):
                with self.subTest(kind=kind, rule=rule_id):
                    value = response_for(self.package)
                    check_for(value, rule_id).update(result="满足", evidence_refs=[reference(item)])
                    with self.assertRaises(ValueError):
                        engine.validate_result(value, self.package)

    def test_wrong_version_and_same_version_uploads_never_promote_execution_or_closure(self):
        for version in (PARENT, TARGET):
            with self.subTest(version=version):
                payload = synthetic_payload()
                payload["materials"][1]["version_id"] = version
                package = engine.normalize(payload, RULES)
                value = response_for(package)
                log = next(item for item in package["evidence"] if item["kind"] == "test_log")
                for rule_id in ("FIX05", "FIX06"):
                    check_for(value, rule_id).update(result="满足", evidence_refs=[reference(log, 2)])
                result = engine.validate_result(value, package)
                self.assertEqual([check_for(result, r)["result"] for r in ("FIX05", "FIX06")],
                                 ["未核查", "未核查"])
                self.assertTrue(all(check_for(result, r)["automated_result"] == "未核查"
                                    for r in ("FIX05", "FIX06")))

    def test_claim_kind_cannot_relabel_the_fixed_rule_semantics(self):
        value = response_for(self.package)
        log = next(item for item in self.package["evidence"] if item["kind"] == "test_log")
        check_for(value, "FIX03").update(result="满足", claim_kind="execution", evidence_refs=[reference(log, 2)])
        with self.assertRaises(ValueError):
            engine.validate_result(value, self.package)
        for rule_id in ("FIX02", "FIX03", "FIX04"):
            with self.subTest(rule=rule_id):
                value = response_for(self.package)
                check_for(value, rule_id).update(result="满足", claim_kind="baseline", evidence_refs=[reference(log, 2)])
                with self.assertRaises(ValueError):
                    engine.validate_result(value, self.package)

    def test_static_positive_and_defect_need_target_bound_source_not_just_parent_or_foreign_code(self):
        for version in (PARENT, "c" * 40, ""):
            for result in ("满足", "不满足"):
                with self.subTest(version=version, result=result):
                    payload = synthetic_payload()
                    payload["materials"][0]["version_id"] = version
                    package = engine.normalize(payload, RULES)
                    source = next(item for item in package["evidence"] if item["kind"] == "source")
                    value = response_for(package)
                    check_for(value, "FIX03").update(result=result, evidence_refs=[reference(source, 2)])
                    with self.assertRaises(ValueError):
                        engine.validate_result(value, package)

    def test_declared_parent_is_valid_before_context_when_target_code_is_also_cited(self):
        for version, accepted in ((PARENT, True), ("c" * 40, False)):
            with self.subTest(version=version):
                payload = synthetic_payload()
                payload["materials"].append({"name": "before.py", "kind": "source", "version_id": version,
                                             "content": "return value or 25"})
                package = engine.normalize(payload, RULES)
                target = next(item for item in package["evidence"] if item["name"] == "limit.py")
                before = next(item for item in package["evidence"] if item["name"] == "before.py")
                value = response_for(package)
                check_for(value, "FIX03").update(result="满足", evidence_refs=[reference(target, 2)],
                                                 counter_refs=[reference(before)])
                if accepted:
                    self.assertEqual(check_for(engine.validate_result(value, package), "FIX03")["local_result"], "满足")
                else:
                    with self.assertRaises(ValueError):
                        engine.validate_result(value, package)

    def test_target_scoped_material_cannot_leak_into_another_tasks_checks_or_findings(self):
        payload = synthetic_payload(2)
        initial_package = engine.normalize(payload, RULES)
        fixed = engine.validate_result(response_for(initial_package), initial_package)["tasks"]
        payload["materials"].append({"name": "task-one-only.py", "kind": "source", "version_id": TARGET,
                                     "content": "return 0", "target_ids": [fixed[0]["id"]]})
        package = engine.normalize(payload, RULES)
        scoped = next(item for item in package["evidence"] if item["name"] == "task-one-only.py")
        for location in ("evidence_refs", "counter_refs", "finding"):
            with self.subTest(location=location):
                value = scripted_result(engine.model_input(package, fixed))
                if location == "finding":
                    value["findings"][1]["evidence_refs"] = [reference(scoped)]
                else:
                    check_for(value, "FIX03", 1)[location] = [reference(scoped)]
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package, fixed)
        selected = engine.model_input(package, [fixed[1]])
        self.assertNotIn(scoped["id"], {item["id"] for item in selected["evidence"]})
        self.assertTrue({item["id"] for item in package["evidence"] if not item.get("target_ids")} <=
                        {item["id"] for item in selected["evidence"]})
        selected = engine.model_input(package, [fixed[0]])
        self.assertIn(scoped["id"], {item["id"] for item in selected["evidence"]})
        model_scoped = next(item for item in selected["evidence"] if item["id"] == scoped["id"])
        self.assertEqual([{key: line[key] for key in ('line', 'text')} for line in model_scoped["numbered_lines"]],
                         [{"line": 1, "text": "return 0"}])
        self.assertRegex(model_scoped["numbered_lines"][0]["quote_id"], r'^Q-[0-9a-f]{16}$')
        self.assertTrue(all("numbered_lines" not in item for item in package["evidence"]))

    def test_short_target_identity_cannot_pass_baseline(self):
        payload = synthetic_payload()
        payload["commits"][0]["sha"] = TARGET[:7]
        package = engine.normalize(payload, RULES)
        self.assertEqual(package["commits"][0]["identity_completeness"], "partial_short_oid")
        value = response_for(package)
        check_for(value, "FIX01")["result"] = "满足"
        result = engine.validate_result(value, package)
        self.assertEqual(check_for(result, "FIX01")["result"], "未核查")

    def test_each_task_must_cover_exactly_the_supplied_rules(self):
        package = engine.normalize(synthetic_payload(2), RULES)
        result = engine.validate_result(response_for(package), package)
        self.assertEqual(len(result["checks"]), 2 * len(RULES))
        self.assertEqual({(row["task_id"], row["rule_id"]) for row in result["checks"]},
                         {(task["id"], rule["id"]) for task in result["tasks"] for rule in RULES})
        for change in ("missing", "duplicate", "unknown_rule", "unknown_task"):
            with self.subTest(change=change):
                value = response_for(package)
                if change == "missing":
                    value["checks"].pop()
                elif change == "duplicate":
                    value["checks"].append(copy.deepcopy(value["checks"][0]))
                else:
                    value["checks"][0]["rule_id" if change == "unknown_rule" else "task_id"] = "unknown"
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package)

    def test_unknown_applicability_cannot_hide_a_positive_or_exclusion(self):
        for applicability, result in (("待确认", "满足"), ("待确认", "不适用"), ("不适用", "未核查"), ("适用", "不适用")):
            with self.subTest(applicability=applicability, result=result):
                value = response_for(self.package)
                check_for(value, "FIX01").update(applicability=applicability, result=result)
                with self.assertRaises(ValueError):
                    engine.validate_result(value, self.package)

    def test_fixed_task_baseline_cannot_be_rewritten_or_inferred_as_user_requirement(self):
        first = engine.validate_result(response_for(self.package), self.package)
        fixed = copy.deepcopy(first["tasks"])
        value = scripted_result(engine.model_input(self.package, fixed))
        self.assertEqual(engine.validate_result(value, self.package, fixed)["tasks"], fixed)
        altered = scripted_result(engine.model_input(self.package, fixed))
        altered["tasks"][0]["goal"] += " and deploy publicly"
        with self.assertRaises(ValueError):
            engine.validate_result(altered, self.package, fixed)
        value = response_for(self.package)
        assistant = next(item for item in self.package["evidence"] if item["kind"] == "assistant")
        value["tasks"][0]["requirement_refs"] = [reference(assistant)]
        with self.assertRaises(ValueError):
            engine.validate_result(value, self.package)

    def test_missing_user_requirements_create_no_invented_task_or_checks(self):
        payload = synthetic_payload(0)
        package = engine.normalize(payload, RULES)
        result = engine.validate_result({"tasks": [], "checks": [], "findings": []}, package)
        self.assertEqual((result["tasks"], result["checks"], result["findings"]), ([], [], []))
        self.assertTrue(result["warnings"])
        invented = response_for(self.package)
        assistant = next(item for item in package["evidence"] if item["kind"] == "assistant")
        invented["tasks"][0]["requirement_refs"] = [reference(assistant)]
        with self.assertRaises(ValueError):
            engine.validate_result(invented, package)
        with self.assertRaises(ValueError):
            engine.validate_result({"tasks": [], "checks": [], "findings": []}, self.package)


class AcceptanceMappingTests(unittest.TestCase):
    def setUp(self):
        self.package = engine.normalize(synthetic_payload(), RULES)

    def test_every_explicit_point_has_one_mapping_even_when_evidence_is_unknown(self):
        result = engine.validate_result(response_for(self.package), self.package)
        self.assertEqual(len(result["acceptance_checks"]), 1)
        point = result["tasks"][0]["acceptance_points"][0]
        row = result["acceptance_checks"][0]
        self.assertEqual((row["task_id"], row["acceptance_id"]), (result["tasks"][0]["id"], point["id"]))
        self.assertEqual(row["result"], "未核查")
        self.assertEqual(row["execution_result"], "未核查")

    def test_missing_or_duplicate_acceptance_mapping_is_rejected(self):
        for change in ("missing", "duplicate", "unknown_point", "unknown_task"):
            with self.subTest(change=change):
                value = response_for(self.package)
                if change == "missing":
                    value["acceptance_checks"].clear()
                elif change == "duplicate":
                    value["acceptance_checks"].append(copy.deepcopy(value["acceptance_checks"][0]))
                else:
                    value["acceptance_checks"][0]["acceptance_id" if change == "unknown_point" else "task_id"] = "invented"
                with self.assertRaises(ValueError):
                    engine.validate_result(value, self.package)

    def test_duplicate_point_id_and_non_user_point_provenance_are_rejected(self):
        for change in ("duplicate_id", "assistant_reference", "missing_reference"):
            with self.subTest(change=change):
                value = response_for(self.package)
                point = value["tasks"][0]["acceptance_points"][0]
                if change == "duplicate_id":
                    value["tasks"][0]["acceptance_points"].append(copy.deepcopy(point))
                elif change == "assistant_reference":
                    assistant = next(item for item in self.package["evidence"] if item["kind"] == "assistant")
                    point["requirement_refs"] = [reference(assistant)]
                else:
                    point["requirement_refs"] = []
                with self.assertRaises(ValueError):
                    engine.validate_result(value, self.package)

    def test_target_commit_must_belong_to_the_task_and_uploaded_inputs(self):
        payload = synthetic_payload()
        payload["commits"].append({"sha": "c" * 40, "message": "Unrelated synthetic commit", "diff": ""})
        package = engine.normalize(payload, RULES)
        for target in ("d" * 40, "c" * 40):
            with self.subTest(target=target):
                value = response_for(package)
                value["tasks"][0]["target_commit_ids"] = [target]
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package)

    def test_invented_change_id_is_rejected_without_promoting_the_point(self):
        value = response_for(self.package)
        value["acceptance_checks"][0]["change_ids"] = ["H-invented"]
        with self.assertRaises(ValueError):
            engine.validate_result(value, self.package)

    def test_change_mapping_needs_actual_changed_line_in_the_selected_hunk(self):
        payload = synthetic_payload()
        payload["commits"][0]["diff"] += "@@ -20 +20 @@\n-return retry or 2\n+return retry\n"
        package = engine.normalize(payload, RULES)
        diff = next(item for item in package["evidence"] if item["kind"] == "commit_diff")
        first, second = package["changes"]
        for line in (1, first["start_line"], second["changed_line_numbers"][-1]):
            with self.subTest(line=line):
                value = response_for(package)
                value["acceptance_checks"][0].update(change_ids=[first["id"]],
                                                       change_refs=[reference(diff, line)])
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package)

    def test_parent_or_unbound_assertions_cannot_be_attached_to_target_point(self):
        for version in (PARENT, "", "c" * 40):
            with self.subTest(version=version):
                payload = synthetic_payload()
                payload["materials"].append({"name": "tests/test_limit.py", "kind": "source",
                                             "version_id": version,
                                             "content": "assert resolve_limit(0) == 0"})
                package = engine.normalize(payload, RULES)
                assertions = next(item for item in package["evidence"] if item["name"] == "tests/test_limit.py")
                value = response_for(package)
                value["acceptance_checks"][0]["assertion_refs"] = [reference(assertions)]
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package)


def summary_support_for(task):
    refs = task.get('requirement_refs') or task['acceptance_points'][0]['requirement_refs']
    return [{'field': field, 'supported': True, 'reason': 'Synthetic user-only summary support.',
             'fragments': [{'text': task[field], 'source_class': 'explicit_request',
                            'presentation': 'requirement', 'source_refs': copy.deepcopy(refs)}]}
            for field in ('title', 'goal')]


class FakeClient:
    """Scripted synthetic model, with no configuration or network operations."""
    model = "synthetic-offline-model"
    configured = True

    def __init__(self):
        self.calls = []
        self.failure_mode = None

    def complete(self, system, payload, directory, stage):
        self.calls.append({"payload": copy.deepcopy(payload), "stage": stage, "directory": str(directory)})
        if self.failure_mode == "transport":
            raise RuntimeError("synthetic-provider-failure")
        if stage.startswith("task-extraction-"):
            value = scripted_result({**payload, "rules": []})
            return {"tasks": value["tasks"]}
        if stage.startswith("requirement-review-"):
            # This synthetic client tests orchestration, not semantic model accuracy.
            return {"tasks": [{"task_id": task["id"], "supported": True,
                "reason": "Synthetic fixture goal copies user text.",
                "summary_checks": summary_support_for(task),
                "acceptance_points": [{"acceptance_id": point["id"], "supported": True,
                    "reason": "Synthetic fixture point copies user text.",
                    "source_class": "explicit_request", "source_refs": copy.deepcopy(point["requirement_refs"]),
                    "duplicate_of": ""}
                    for point in task["acceptance_points"]], "missing_requirements": []}
                for task in payload["candidate_tasks"]]}
        value = scripted_result(payload)
        if self.failure_mode == "invalid_schema":
            value["checks"] = []
            return value
        for item in payload["evidence"]:
            if item["kind"] != "source" or not item.get("target_ids"):
                continue
            for task in value["tasks"]:
                if task["id"] in item["target_ids"]:
                    check_for(value, "FIX03", value["tasks"].index(task)).update(
                        result="满足", evidence_refs=[reference(item)],
                        reason="Synthetic target-scoped source was added.",
                    )
        return value


class InlineThread:
    """Run the real worker synchronously so revision tests have no timing races."""
    def __init__(self, target, args=(), daemon=False):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


class AnalyzePreflightTests(unittest.TestCase):
    def test_missing_or_blank_user_requirements_return_without_any_model_call(self):
        for user_content in (None, "", " \n\t "):
            with self.subTest(user_content=user_content), tempfile.TemporaryDirectory() as directory:
                payload = synthetic_payload(0)
                if user_content is not None:
                    payload["trace"]["messages"].append({"role": "user", "content": user_content})
                package = engine.normalize(payload, RULES)
                client = FakeClient()
                result = engine.analyze(package, client, directory)
                self.assertEqual(client.calls, [])
                self.assertEqual((result["tasks"], result["checks"], result["findings"]), ([], [], []))
                self.assertTrue(result["warnings"])

    def test_one_format_error_can_retry_with_feedback_in_each_model_stage(self):
        for family in ("task-extraction", "requirement-review", "analysis", "counter-review"):
            with self.subTest(stage=family), tempfile.TemporaryDirectory() as directory:
                class FormatOnceClient(FakeClient):
                    def complete(self, system, payload, output_dir, stage):
                        if stage == family + "-1":
                            self.calls.append({"payload": copy.deepcopy(payload), "stage": stage})
                            engine.save_json(Path(output_dir) / (stage + ".response.json"),
                                             {"synthetic": True, "raw_content": "{not-valid-json"})
                            raise engine.ModelOutputError("Synthetic invalid JSON; return one object.")
                        return super().complete(system, payload, output_dir, stage)

                client = FormatOnceClient()
                result = engine.analyze(engine.normalize(synthetic_payload(), RULES), client, directory)
                self.assertEqual(len(result["tasks"]), 1)
                self.assertEqual(len(client.calls), 5)
                retry = next(call for call in client.calls if call["stage"] == family + "-2")
                self.assertTrue(retry["payload"]["validation_feedback"])
                self.assertTrue((Path(directory) / (family + "-1.response.json")).exists())
                self.assertTrue((Path(directory) / (family + "-1.validation.json")).exists())

    def test_two_format_errors_fail_without_report_and_keep_both_attempt_records(self):
        class InvalidJSONClient(FakeClient):
            def complete(self, system, payload, output_dir, stage):
                if stage.startswith("analysis-"):
                    self.calls.append({"payload": copy.deepcopy(payload), "stage": stage})
                    engine.save_json(Path(output_dir) / (stage + ".response.json"),
                                     {"synthetic": True, "raw_content": "{not-valid-json"})
                    raise engine.ModelOutputError("Synthetic invalid JSON.")
                return super().complete(system, payload, output_dir, stage)

        with tempfile.TemporaryDirectory() as directory:
            client = InvalidJSONClient()
            with self.assertRaises(ValueError):
                engine.analyze(engine.normalize(synthetic_payload(), RULES), client, directory)
            self.assertEqual([call["stage"] for call in client.calls],
                             ["task-extraction-1", "requirement-review-1", "analysis-1", "analysis-2"])
            for attempt in (1, 2):
                self.assertTrue((Path(directory) / f"analysis-{attempt}.response.json").exists())
                self.assertTrue((Path(directory) / f"analysis-{attempt}.validation.json").exists())

    def test_ordinary_provider_failure_is_not_retried_as_a_format_error(self):
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            client.failure_mode = "transport"
            with self.assertRaisesRegex(RuntimeError, "synthetic-provider-failure"):
                engine.analyze(engine.normalize(synthetic_payload(), RULES), client, directory)
            self.assertEqual(len(client.calls), 1)

    def test_analysis_can_omit_tasks_and_reuse_the_frozen_baseline(self):
        class OmitTasksClient(FakeClient):
            def complete(self, system, payload, output_dir, stage):
                value = super().complete(system, payload, output_dir, stage)
                if stage.startswith(("analysis-", "counter-review-")):
                    value.pop("tasks")
                return value

        with tempfile.TemporaryDirectory() as directory:
            client = OmitTasksClient()
            result = engine.analyze(engine.normalize(synthetic_payload(), RULES), client, directory)
            self.assertEqual(len(client.calls), 4)
            self.assertEqual(client.calls[2]["payload"]["fixed_tasks"], result["tasks"])
            self.assertEqual(client.calls[3]["payload"]["fixed_tasks"], result["tasks"])

    def test_null_reference_collection_can_be_repaired_without_escaping_validation(self):
        payload = synthetic_payload()
        payload["materials"][0]["content"] = "def resolve_limit(value):\n    return value or 25\n"
        package = engine.normalize(payload, RULES)
        source = next(item for item in package["evidence"] if item["kind"] == "source")

        class NullRefsClient(FakeClient):
            def complete(self, system, payload, output_dir, stage):
                value = super().complete(system, payload, output_dir, stage)
                if stage.startswith(("analysis-", "counter-review-")):
                    row = value["acceptance_checks"][0]
                    row.update(result="不满足", reason="The target still substitutes 25 for explicit zero.",
                        counterexample="resolve_limit(0) returns 25, while the user requires preserving 0.",
                        no_change_reason="The supplied target still uses truthiness for the default.",
                        no_change_refs=[reference(source, 2)])
                    if stage == "analysis-1":
                        row.update(change_refs=None, no_change_refs=[])
                return value

        with tempfile.TemporaryDirectory() as directory:
            client = NullRefsClient()
            result = engine.analyze(package, client, directory)
            self.assertTrue((Path(directory) / "analysis-1.validation.json").exists())
        retry = next(call["payload"] for call in client.calls if call["stage"] == "analysis-2")
        self.assertTrue(retry["validation_feedback"])
        self.assertIsNone(retry["repair_candidate"]["acceptance_checks"][0]["change_refs"])
        self.assertEqual(retry["repair_candidate"]["acceptance_checks"][0]["result"], "不满足")
        self.assertTrue(retry["reference_feedback"])
        choices = retry["reference_feedback"][0]["target_evidence"]
        self.assertIn(source["id"], {item["evidence_id"] for item in choices})
        self.assertEqual(result["acceptance_checks"][0]["result"], "不满足")
        self.assertEqual(result["acceptance_checks"][0]["no_change_refs"], [reference(source, 2)])

    def test_returning_rewritten_tasks_is_rejected_after_baseline_freeze(self):
        class RewrittenTasksClient(FakeClient):
            def complete(self, system, payload, output_dir, stage):
                value = super().complete(system, payload, output_dir, stage)
                if stage.startswith(("analysis-", "counter-review-")):
                    value["tasks"][0]["goal"] += " and deploy publicly"
                return value

        with tempfile.TemporaryDirectory() as directory:
            client = RewrittenTasksClient()
            with self.assertRaises(ValueError):
                engine.analyze(engine.normalize(synthetic_payload(), RULES), client, directory)
            self.assertEqual([call["stage"] for call in client.calls],
                             ["task-extraction-1", "requirement-review-1", "analysis-1", "analysis-2"])


class AuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trace-engine-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / "rules", self.root / "rules")
        self.real_client = patch.object(engine, "DeepSeekClient", side_effect=AssertionError("Real client must not be constructed"))
        self.real_client.start()
        self.addCleanup(self.real_client.stop)
        self.thread = patch.object(engine.threading, "Thread", InlineThread)
        self.thread.start()
        self.addCleanup(self.thread.stop)
        self.client = FakeClient()
        self.service = engine.AuditService(self.root, self.client)
        # Keep engine orchestration regressions isolated; SOP-library integration has separate tests.
        self.service.catalog = None

    def create(self, tasks=2):
        state = self.service.create(synthetic_payload(tasks))
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["revision"], 1)
        return state

    def supplement(self, task_id, name="new-source.py"):
        return {"materials": [{"name": name, "path": "supplement/limit.py", "kind": "source", "version_id": TARGET,
                               "content": "return 0 if value == 0 else value", "target_ids": [task_id]}]}

    def test_create_persists_a_candidate_with_all_tasks_and_rules_and_no_formal_pass(self):
        state = self.create()
        report = state["report"]
        self.assertEqual(report["summary"]["tasks"], 2)
        self.assertEqual(report["summary"]["checks"], 12)
        self.assertFalse(report["formal_closed"])
        self.assertFalse(report["business_tests_executed"])
        self.assertFalse(report["source_authenticated"])
        self.assertEqual(report["review_state"], "model_candidate")
        self.assertEqual(report['model_snapshot']['semantic_judgment_norm']['sha256'],
                         engine.sha((self.root / 'rules/语义审计判定规范.md').read_text()))
        self.assertEqual([call["stage"] for call in self.client.calls],
                         ["task-extraction-1", "requirement-review-1", "analysis-1", "counter-review-1"])
        self.assertEqual(self.client.calls[2]["payload"]["fixed_tasks"], report["tasks"])
        self.assertEqual(self.service.get(state["id"], 1)["report"], report)
        self.assertEqual(len(list((self.root / "data" / state["id"] / "attempts").glob("*/input.json"))), 1)

    def test_targeted_supplement_keeps_other_tasks_checks_and_findings_exactly(self):
        state = self.create()
        previous = copy.deepcopy(state["report"])
        selected, unselected = (task["id"] for task in previous["tasks"])
        first_revision = self.root / "data" / state["id"] / "revision-0001.json"
        original_bytes = first_revision.read_bytes()
        result = self.service.supplement(state["id"], self.supplement(selected))
        current = result["report"]
        self.assertEqual(result["revision"], 2)
        self.assertEqual(current["tasks"], previous["tasks"])
        for field in ("checks", "findings", "acceptance_checks"):
            self.assertEqual([row for row in current[field] if row["task_id"] == unselected],
                             [row for row in previous[field] if row["task_id"] == unselected])
        self.assertEqual(check_for(current, "FIX03")["local_result"], "满足")
        self.assertEqual(current["delta"]["affected_task_ids"], [selected])
        self.assertEqual(len(current["delta"]["unchanged"]), len(RULES) * 2 - 1)
        self.assertEqual([task["id"] for task in self.client.calls[-2]["payload"]["fixed_tasks"]], [selected])
        self.assertEqual(first_revision.read_bytes(), original_bytes)

    def test_duplicate_supplements_do_not_call_model_or_add_a_revision(self):
        state = self.create()
        target = state["report"]["tasks"][0]["id"]
        rows = self.supplement(target)["materials"]
        self.service.supplement(state["id"], {"materials": rows + copy.deepcopy(rows)})
        before = self.service.get(state["id"])
        calls = len(self.client.calls)
        result = self.service.supplement(state["id"], self.supplement(target, "renamed-same-content.py"))
        self.assertEqual(result, before)
        self.assertEqual(len(self.client.calls), calls)
        receipt_files = (self.root / "data" / state["id"] / "receipts").glob("*.json")
        receipts = [json.loads(path.read_text()) for path in receipt_files]
        self.assertIn((2, 1, 1), [(r["received"], r["accepted"], r["duplicates"]) for r in receipts])
        self.assertIn((1, 0, 1), [(r["received"], r["accepted"], r["duplicates"]) for r in receipts])
        self.assertEqual(len(list((self.root / "data" / state["id"]).glob("revision-*.json"))), 2)

    def test_same_content_for_distinct_source_paths_is_not_deduplicated(self):
        state = self.create()
        target = state["report"]["tasks"][0]["id"]
        self.service.supplement(state["id"], self.supplement(target))
        calls = len(self.client.calls)
        other = self.supplement(target)
        other["materials"][0]["path"] = "supplement/other_limit.py"
        result = self.service.supplement(state["id"], other)
        self.assertEqual(result["revision"], 3)
        self.assertEqual(len(self.client.calls), calls + 2)

    def test_failed_supplement_preserves_prior_report_input_and_revision(self):
        for failure_mode in ("transport", "invalid_schema"):
            with self.subTest(failure=failure_mode):
                self.client.failure_mode = None
                state = self.create()
                audit_dir = self.root / "data" / state["id"]
                prior_report = (audit_dir / "revision-0001.json").read_bytes()
                prior_input = (audit_dir / "input-0001.json").read_bytes()
                self.client.failure_mode = failure_mode
                result = self.service.supplement(state["id"], self.supplement(state["report"]["tasks"][0]["id"]))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["revision"], 1)
                self.assertEqual(result["report"], state["report"])
                self.assertEqual((audit_dir / "revision-0001.json").read_bytes(), prior_report)
                self.assertEqual((audit_dir / "input-0001.json").read_bytes(), prior_input)
                self.assertFalse((audit_dir / "revision-0002.json").exists())
                failures = [json.loads(path.read_text()) for path in audit_dir.glob("attempts/*/failure.json")]
                self.assertEqual(len(failures), 1)
                self.assertTrue(failures[0]["previous_report_preserved"])
                if failure_mode == "invalid_schema":
                    self.assertTrue(self.client.calls[-1]["payload"]["validation_feedback"])
                    self.assertEqual(len(list(audit_dir.glob("attempts/*/*.validation.json"))), 2)
                self.assertEqual(self.service.get(state["id"], 1)["report"], state["report"])

    def test_failed_initial_analysis_does_not_create_a_passing_report(self):
        self.client.failure_mode = "transport"
        state = self.service.create(synthetic_payload())
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["revision"], 0)
        self.assertNotIn("report", state)
        self.assertFalse(list((self.root / "data" / state["id"]).glob("revision-*.json")))

    def test_initial_attempt_input_write_failure_finishes_without_model_or_report(self):
        save = engine.save_json

        def fail_attempt_input(path, value):
            if Path(path).name == "input.json" and "attempts" in Path(path).parts:
                raise OSError("Synthetic attempt-input storage failure")
            return save(path, value)

        with patch.object(engine, "save_json", side_effect=fail_attempt_input):
            state = self.service.create(synthetic_payload())
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["revision"], 0)
        self.assertNotIn("report", state)
        self.assertFalse(self.client.calls)
        self.assertFalse(list((self.root / "data" / state["id"]).glob("revision-*.json")))
        restarted = engine.AuditService(self.root, self.client)
        self.assertEqual(restarted.get(state["id"])["status"], "failed")

    def test_publication_write_failures_keep_commit_pointer_and_allow_retry(self):
        for failure_point in ("input-0002.json", "revision-0002.json", "completed-state"):
            with self.subTest(failure_point=failure_point):
                state = self.create()
                audit_dir = self.root / "data" / state["id"]
                prior_bytes = (audit_dir / "revision-0001.json").read_bytes()
                prior_input = (audit_dir / "input-0001.json").read_bytes()
                save = engine.save_json

                def fail_publication(path, value):
                    path = Path(path)
                    final_state = (path.name == "state.json" and value.get("status") == "completed"
                                   and value.get("revision") == 2)
                    if path.parent == audit_dir and (path.name == failure_point or
                                                    failure_point == "completed-state" and final_state):
                        raise OSError("Synthetic publication storage failure")
                    return save(path, value)

                target = state["report"]["tasks"][0]["id"]
                with patch.object(engine, "save_json", side_effect=fail_publication):
                    failed = self.service.supplement(state["id"], self.supplement(target))
                self.assertEqual(failed["status"], "failed")
                self.assertEqual(failed["revision"], 1)
                self.assertEqual(failed["report"], state["report"])
                self.assertEqual((audit_dir / "revision-0001.json").read_bytes(), prior_bytes)
                self.assertEqual((audit_dir / "input-0001.json").read_bytes(), prior_input)
                with self.assertRaises(FileNotFoundError):
                    self.service.get(state["id"], 2)
                restarted = engine.AuditService(self.root, self.client)
                self.assertEqual(restarted.get(state["id"])["report"], state["report"])
                with self.assertRaises(FileNotFoundError):
                    restarted.get(state["id"], 2)
                retried = restarted.supplement(state["id"], self.supplement(target))
                self.assertEqual(retried["status"], "completed")
                self.assertEqual(retried["revision"], 2)
                self.assertEqual(restarted.get(state["id"], 2)["report"], retried["report"])
                self.assertEqual((audit_dir / "revision-0001.json").read_bytes(), prior_bytes)

    def test_assistant_only_package_has_no_invented_tasks_and_cannot_be_supplemented(self):
        state = self.create(0)
        self.assertEqual((state["report"]["tasks"], state["report"]["checks"]), ([], []))
        self.assertEqual(len(self.client.calls), 0)
        snapshot = state["report"]["model_snapshot"]
        self.assertFalse(snapshot["model_invoked"])
        self.assertEqual(snapshot["api_request_count"], 0)
        self.assertTrue(snapshot["counter_review"].startswith("not_run; deterministic"))
        self.assertTrue(snapshot["requirement_review"].startswith("not_run; deterministic"))
        with self.assertRaises(ValueError):
            self.service.supplement(state["id"], self.supplement("invented-task"))

    def test_unknown_supplement_target_is_rejected_without_changing_state(self):
        state = self.create()
        calls = len(self.client.calls)
        with self.assertRaises(ValueError):
            self.service.supplement(state["id"], self.supplement("missing-task"))
        self.assertEqual(self.service.get(state["id"]), state)
        self.assertEqual(len(self.client.calls), calls)

    def test_legacy_report_is_readable_but_cannot_be_supplemented_as_current_schema(self):
        state = self.create()
        legacy = copy.deepcopy(state["report"])
        legacy.pop("schema_version", None)
        legacy.pop("acceptance_checks", None)
        legacy.pop("automatic_review", None)
        legacy.pop("original_sop", None)
        for task in legacy["tasks"]:
            for field in ("acceptance_points", "target_commit_ids", "superseded_requirements"):
                task.pop(field, None)
        audit_dir = self.root / "data" / state["id"]
        engine.save_json(audit_dir / "revision-0001.json", legacy)
        self.service.states[state["id"]]["report"] = legacy
        self.service._persist(self.service.states[state["id"]])
        before = copy.deepcopy(self.service.get(state["id"]))
        revision_bytes = (audit_dir / "revision-0001.json").read_bytes()
        calls = len(self.client.calls)
        self.assertEqual(self.service.get(state["id"], 1)["report"], legacy)
        with self.assertRaises(ValueError):
            self.service.supplement(state["id"], self.supplement(legacy["tasks"][0]["id"]))
        self.assertEqual(self.service.get(state["id"]), before)
        self.assertEqual(len(self.client.calls), calls)
        self.assertEqual((audit_dir / "revision-0001.json").read_bytes(), revision_bytes)

    def test_restart_marks_interrupted_work_failed_and_retains_completed_revision(self):
        state = self.create()
        self.service.states[state["id"]].update(status="running", stage="Synthetic interrupted supplement")
        self.service._persist(self.service.states[state["id"]])
        recovered = engine.AuditService(self.root, self.client)
        result = recovered.get(state["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["report"], state["report"])
        self.assertEqual(recovered.get(state["id"], 1)["report"], state["report"])


if __name__ == "__main__":
    unittest.main()
