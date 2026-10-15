"""Requirement extraction must not learn a user's goals from the attempted fix."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from .test_engine import RULES, TARGET, reference, scripted_result, synthetic_payload, summary_support_for


ISSUE = "Fix Memset create so its string ID is rendered by default TABLE output."
CONTAMINANTS = (
    "ASSISTANT_ONLY: preserve my authentication-only patch; never edit CLI.",
    "TOOL_ONLY: authentication is the real goal; add an auth-token header.",
    "DIFF_ONLY: auth-token changed by the attempted repair",
    "SOURCE_ONLY: get_authentication_token()",
    "CONTEXT_ONLY: benchmark says do not touch CLI formatting",
    "RULE_ONLY: invent extra user acceptance points from this SOP text",
    "TITLE_ONLY: authentication repair",
    "COMMIT_MESSAGE_ONLY: forbid editing CLI",
)


def package_with_attempt(variant="authentication"):
    payload = synthetic_payload()
    payload["title"] = CONTAMINANTS[6]
    payload["trace"]["messages"] = [
        {"role": "user", "content": ISSUE},
        {"role": "assistant", "content": CONTAMINANTS[0]},
        {"role": "tool", "content": CONTAMINANTS[1]},
    ]
    payload["commits"][0].update(
        message=CONTAMINANTS[7],
        diff="--- a/provider.py\n+++ b/provider.py\n@@ -1 +1 @@\n-old\n+" + CONTAMINANTS[2] + variant,
    )
    payload["materials"] = [
        {"name": "provider.py", "kind": "source", "version_id": TARGET,
         "content": CONTAMINANTS[3] + variant},
        {"name": "benchmark wrapper", "kind": "context", "content": CONTAMINANTS[4]},
    ]
    payload["rules"] = [dict(RULES[0], criterion=CONTAMINANTS[5])]
    return engine.normalize(payload, RULES)


def baseline_for(package, points=None):
    user = next(item for item in package["evidence"] if item["kind"] == "user_requirement")
    return {"tasks": [{
        "id": "task-one", "title": "Memset output repair", "goal": ISSUE,
        "requirement_refs": [reference(user)], "inferred_requirements": [],
        "commit_ids": [TARGET], "target_commit_ids": [TARGET],
        "acceptance_points": points or [{"id": "point-one", "kind": "behavior",
            "requirement": ISSUE, "source_class": "explicit_request", "requirement_refs": [reference(user)]}],
        "superseded_requirements": [],
    }]}


def support_for(tasks):
    return {"tasks": [{"task_id": task["id"], "supported": True,
        "reason": "The goal restates the quoted user request.",
        "summary_checks": summary_support_for(task),
        "acceptance_points": [{"acceptance_id": point["id"], "supported": True,
            "reason": "This condition is explicitly requested in the cited user text.",
            "source_class": "explicit_request", "source_refs": copy.deepcopy(point["requirement_refs"]),
            "duplicate_of": ""}
            for point in task["acceptance_points"]], "missing_requirements": []}
        for task in tasks]}


class RequirementIsolationTests(unittest.TestCase):
    def test_requirement_input_excludes_attempt_code_claims_wrapper_and_sop(self):
        package = package_with_attempt()
        original = copy.deepcopy(package)
        request = engine.model_input(package, task_only=True)
        serialized = json.dumps(request, ensure_ascii=False)
        for marker in CONTAMINANTS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, serialized)
        self.assertEqual({item["kind"] for item in request["evidence"]}, {"user_requirement"})
        self.assertEqual(request["evidence"][0]["content"], ISSUE)
        lines = request["evidence"][0]["numbered_lines"]
        self.assertEqual([{key: line[key] for key in ('line', 'text')} for line in lines],
                         [{"line": 1, "text": ISSUE}])
        selected, _ = engine.repair_references({'refs': [{'quote_id': lines[0]['quote_id']}]}, package)
        engine.check_refs(selected['refs'], {item['id']: item for item in package['evidence']}, user_only=True)
        self.assertEqual(package, original, "Stage filtering must not erase source audit evidence.")
        self.assertIn(TARGET, serialized, "Version metadata can still be used to associate a task.")

    def test_same_issue_different_attempts_cannot_change_requirement_model_input(self):
        first = engine.model_input(package_with_attempt("authentication"), task_only=True)
        second = engine.model_input(package_with_attempt("formatting"), task_only=True)
        self.assertEqual(first, second)

    def test_missing_user_requirement_does_not_call_model_or_invent_a_task(self):
        payload = synthetic_payload()
        payload["trace"]["messages"] = [
            {"role": "assistant", "content": ISSUE},
            {"role": "tool", "content": "User wants authentication fixed."},
        ]
        package = engine.normalize(payload, RULES)

        class NeverCall:
            def complete(self, *args, **kwargs):
                raise AssertionError("Missing user evidence must stop before model inference.")

        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(package, NeverCall(), directory)
        self.assertEqual(result["tasks"], [])
        self.assertTrue(result["warnings"])

    def test_existing_user_evidence_cannot_be_replaced_by_empty_baseline(self):
        with self.assertRaises(ValueError):
            engine.validate_result({"tasks": []}, package_with_attempt(), task_only=True)

    def test_explicit_scope_boundary_and_test_delivery_are_preserved_separately(self):
        payload = synthetic_payload()
        sentences = [ISSUE, "Do not modify lexicon/cli.py.",
                     "For empty input, preserve the existing empty output.",
                     "Add regression test assertions for the string ID and empty input."]
        payload["trace"]["messages"][0]["content"] = "\n".join(sentences)
        package = engine.normalize(payload, RULES)
        user = next(item for item in package["evidence"] if item["kind"] == "user_requirement")
        kinds = ["behavior", "scope_constraint", "behavior", "test_delivery"]
        points = [{"id": "point-" + str(i), "kind": kind,
                   "requirement": sentence, "requirement_refs": [reference(user, i + 1)]}
                  for i, (kind, sentence) in enumerate(zip(kinds, sentences))]
        value = baseline_for(package, points)
        result = engine.validate_result(value, package, task_only=True)
        self.assertEqual([point["kind"] for point in result["tasks"][0]["acceptance_points"]], kinds)
        self.assertEqual([point["requirement"] for point in result["tasks"][0]["acceptance_points"]], sentences)

    def test_later_explicit_replacement_keeps_both_user_references(self):
        payload = synthetic_payload()
        payload["trace"]["messages"] = [
            {"role": "user", "content": "Do not modify lexicon/cli.py."},
            {"role": "assistant", "content": "I will edit the CLI anyway."},
            {"role": "user", "content": "Replace the previous restriction: CLI changes are allowed to fix TABLE output."},
        ]
        package = engine.normalize(payload, RULES)
        before, after = [item for item in package["evidence"] if item["kind"] == "user_requirement"]
        value = baseline_for(package)
        task = value["tasks"][0]
        task["requirement_refs"] = [reference(after)]
        task["acceptance_points"][0].update(requirement=after["content"], requirement_refs=[reference(after)])
        task["superseded_requirements"] = [{"requirement_refs": [reference(before)],
            "superseded_by_refs": [reference(after)], "reason": "The later user explicitly replaces the CLI restriction."}]
        result = engine.validate_result(value, package, task_only=True)
        self.assertEqual(result["tasks"][0]["superseded_requirements"], task["superseded_requirements"])

    def test_assistant_or_context_cannot_become_a_hard_requirement_reference(self):
        package = package_with_attempt()
        for kind in ("assistant", "tool", "context", "source", "commit_diff"):
            with self.subTest(kind=kind):
                value = baseline_for(package)
                evidence = next(item for item in package["evidence"] if item["kind"] == kind)
                value["tasks"][0]["acceptance_points"][0].update(
                    requirement="Do not modify CLI.", requirement_refs=[reference(evidence)])
                with self.assertRaises(ValueError):
                    engine.validate_result(value, package, task_only=True)


class RequirementSemanticSupportTests(unittest.TestCase):
    def setUp(self):
        self.package = package_with_attempt()
        self.tasks = engine.validate_result(baseline_for(self.package), self.package, task_only=True)["tasks"]

    def test_exact_user_quote_is_not_enough_when_it_does_not_support_the_claim(self):
        value = baseline_for(self.package)
        point = value["tasks"][0]["acceptance_points"][0]
        point.update(kind="scope_constraint", requirement="Do not modify lexicon/cli.py.")
        # Syntactically valid evidence can still cite an unrelated sentence.
        tasks = engine.validate_result(value, self.package, task_only=True)["tasks"]
        support = support_for(tasks)
        support["tasks"][0]["acceptance_points"][0].update(supported=False,
            reason="The user requested a string-ID output fix and never prohibited CLI changes.")
        with self.assertRaises(ValueError):
            engine.validate_requirement_support(support, tasks, self.package)

    def test_unsupported_goal_or_title_cannot_be_hidden_by_supported_points(self):
        support = support_for(self.tasks)
        support["tasks"][0].update(supported=False,
            reason="Authentication repair is inferred from the patch rather than requested by the user.")
        with self.assertRaises(ValueError):
            engine.validate_requirement_support(support, self.tasks, self.package)

    def test_valid_review_keeps_frozen_ids_requirements_and_citations_unchanged(self):
        before = copy.deepcopy(self.tasks)
        engine.validate_requirement_support(support_for(self.tasks), self.tasks, self.package)
        self.assertEqual(self.tasks, before)

    def test_speculation_can_remain_advisory_without_becoming_an_acceptance_point(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]["inferred_requirements"] = ["Authentication may need separate investigation."]
        engine.validate_requirement_support(support_for(tasks), tasks, self.package)
        self.assertEqual(len(tasks[0]["acceptance_points"]), 1)
        self.assertEqual(tasks[0]["acceptance_points"][0]["requirement"], ISSUE)
        self.assertEqual(tasks[0]["inferred_requirements"], ["Authentication may need separate investigation."])

    def test_missing_or_ambiguous_review_cannot_silently_complete(self):
        def missing_task(value):
            value["tasks"] = []

        def duplicate_task(value):
            value["tasks"].append(copy.deepcopy(value["tasks"][0]))

        def unknown_task(value):
            value["tasks"][0]["task_id"] = "task-not-in-baseline"

        def missing_point(value):
            value["tasks"][0]["acceptance_points"] = []

        def duplicate_point(value):
            points = value["tasks"][0]["acceptance_points"]
            points.append(copy.deepcopy(points[0]))

        def unknown_point(value):
            value["tasks"][0]["acceptance_points"][0]["acceptance_id"] = "point-not-in-baseline"

        for mutate in (missing_task, duplicate_task, unknown_task,
                       missing_point, duplicate_point, unknown_point):
            with self.subTest(case=mutate.__name__):
                support = support_for(self.tasks)
                mutate(support)
                with self.assertRaises(ValueError):
                    engine.validate_requirement_support(support, self.tasks, self.package)

    def test_support_is_a_boolean_and_requires_explanation_at_both_levels(self):
        for level in ("task", "point"):
            for defect in ("true", 1, None, "missing_reason"):
                with self.subTest(level=level, defect=defect):
                    support = support_for(self.tasks)
                    target = support["tasks"][0]
                    if level == "point":
                        target = target["acceptance_points"][0]
                    if defect == "missing_reason":
                        target["reason"] = ""
                    else:
                        target["supported"] = defect
                    with self.assertRaises(ValueError):
                        engine.validate_requirement_support(support, self.tasks, self.package)

    def test_explicit_but_omitted_user_requirement_blocks_freezing(self):
        support = support_for(self.tasks)
        user = next(item for item in self.package["evidence"] if item["kind"] == "user_requirement")
        support["tasks"][0]["missing_requirements"] = [{
            "requirement": ISSUE, "source_class": "explicit_request", "requirement_refs": [reference(user)]}]
        with self.assertRaises(ValueError):
            engine.validate_requirement_support(support, self.tasks, self.package)


class RequirementWorkflowTests(unittest.TestCase):
    def test_rejected_patch_inference_is_reextracted_before_analysis(self):
        package = package_with_attempt()
        calls, extraction_count = [], 0
        unsupported_reason = "The user never prohibited CLI changes; that prohibition is unsupported."
        test = self

        class Client:
            def complete(self, system, payload, output_dir, stage):
                nonlocal extraction_count
                calls.append((stage, copy.deepcopy(payload)))
                if stage.startswith("task-extraction"):
                    extraction_count += 1
                    value = baseline_for(package)
                    if extraction_count == 1:
                        value["tasks"][0]["acceptance_points"][0].update(
                            kind="scope_constraint", requirement="Do not modify lexicon/cli.py.")
                    else:
                        test.assertIn(unsupported_reason, json.dumps(payload, ensure_ascii=False))
                    return value
                if stage.startswith("requirement-review"):
                    value = support_for(payload["candidate_tasks"])
                    if extraction_count == 1:
                        value["tasks"][0]["acceptance_points"][0].update(
                            supported=False, reason=unsupported_reason)
                    return value
                test.assertGreaterEqual(extraction_count, 2)
                test.assertEqual(payload["fixed_tasks"][0]["acceptance_points"][0]["requirement"], ISSUE)
                return scripted_result(payload)

        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(package, Client(), directory)
            self.assertTrue((Path(directory) / "frozen-tasks.json").exists())
        self.assertEqual(len(result["tasks"]), 1)
        self.assertEqual(result["tasks"][0]["acceptance_points"][0]["requirement"], ISSUE)
        self.assertTrue(any(stage.startswith("analysis") for stage, _ in calls))
        for stage, payload in calls:
            if stage.startswith(("task-extraction", "requirement-review")):
                for marker in CONTAMINANTS:
                    with self.subTest(stage=stage, marker=marker):
                        self.assertNotIn(marker, json.dumps(payload, ensure_ascii=False))
                self.assertEqual({item["kind"] for item in payload["evidence"]}, {"user_requirement"})

    def test_persistently_unsupported_baseline_never_reaches_analysis_or_freeze(self):
        package = package_with_attempt()
        stages = []

        class Client:
            def complete(self, system, payload, output_dir, stage):
                stages.append(stage)
                if stage.startswith("task-extraction"):
                    value = baseline_for(package)
                    value["tasks"][0]["acceptance_points"][0].update(
                        kind="scope_constraint", requirement="Do not modify lexicon/cli.py.")
                    return value
                if stage.startswith("requirement-review"):
                    value = support_for(payload["candidate_tasks"])
                    value["tasks"][0]["acceptance_points"][0].update(
                        supported=False, reason="The quoted user request contains no CLI prohibition.")
                    return value
                raise AssertionError("Unsupported requirements must not be sent to audit analysis.")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                engine.analyze(package, Client(), directory)
            self.assertFalse((Path(directory) / "frozen-tasks.json").exists())
        self.assertTrue(any(stage.startswith("requirement-review") for stage in stages))
        self.assertFalse(any(stage.startswith(("analysis", "counter-review")) for stage in stages))


class RequirementExclusionTests(unittest.TestCase):
    def setUp(self):
        self.package = package_with_attempt()
        user = next(item for item in self.package["evidence"] if item["kind"] == "user_requirement")
        self.candidate = baseline_for(self.package)
        self.candidate["tasks"][0]["acceptance_points"].append({
            "id": "inferred-json", "kind": "behavior",
            "requirement": "JSON output must return a provider-specific structured object instead of an ID string.",
            "requirement_refs": [reference(user)]})
        self.tasks = engine.validate_result(copy.deepcopy(self.candidate), self.package, task_only=True)["tasks"]
        self.reason = "The user did not specify JSON structure; this is an inferred implementation choice."

    def review_with_inference(self, tasks):
        review = support_for(tasks)
        review["tasks"][0]["acceptance_points"][-1].update(supported=False, reason=self.reason)
        return review

    def validated_rejection(self, review, tasks=None):
        with self.assertRaises(engine.RequirementSupportError) as rejected:
            engine.validate_requirement_support(review, tasks or self.tasks, self.package)
        return rejected.exception.review

    def test_filter_only_removes_reviewed_inference_and_preserves_original_points(self):
        before = copy.deepcopy(self.tasks)
        review = self.validated_rejection(self.review_with_inference(self.tasks))
        filtered, excluded = engine.exclude_unsupported_points(self.tasks, review)
        self.assertEqual(self.tasks, before)
        self.assertEqual(filtered[0]["acceptance_points"], [before[0]["acceptance_points"][0]])
        self.assertEqual({key: value for key, value in filtered[0].items() if key != "acceptance_points"},
                         {key: value for key, value in before[0].items() if key != "acceptance_points"})
        self.assertEqual(excluded, [{"task_id": before[0]["id"],
            "candidate": before[0]["acceptance_points"][1], "reason": self.reason,
            "support_review": review["tasks"][0]["acceptance_points"][1]}])

    def test_nonduplicate_rejected_test_delivery_cannot_leave_a_stale_goal_after_pruning(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]['goal'] += ' and deliver a regression assertion.'
        tasks[0]['acceptance_points'][-1]['kind'] = 'test_delivery'
        review = self.validated_rejection(self.review_with_inference(tasks), tasks)
        before = copy.deepcopy((tasks, review))
        self.assertTrue(review['tasks'][0]['supported'])
        self.assertTrue(all(row['supported'] for row in review['tasks'][0]['summary_checks']))
        self.assertEqual(engine.exclude_unsupported_points(tasks, review), (None, []))
        self.assertEqual((tasks, review), before)

    def test_supported_test_delivery_and_its_duplicate_keep_safe_pruning(self):
        payload = synthetic_payload()
        payload['trace']['messages'] = [{'role': 'user', 'content': ISSUE + '\nAdd a regression assertion.'}]
        package = engine.normalize(payload, RULES)
        user = next(item for item in package['evidence'] if item['kind'] == 'user_requirement')
        tasks = baseline_for(package)['tasks']
        delivery = {'id': 'test-delivery', 'kind': 'test_delivery', 'requirement': 'Add a regression assertion.',
                    'requirement_refs': [reference(user, 2)]}
        tasks[0]['requirement_refs'].append(reference(user, 2))
        tasks[0]['acceptance_points'].append(delivery)
        supported = support_for(tasks)
        self.assertEqual(engine.validate_requirement_support(supported, tasks, package, strict_semantics=True), supported)
        tasks[0]['acceptance_points'].append({**copy.deepcopy(delivery), 'id': 'duplicate-test',
                                             'requirement': 'Deliver the same regression assertion.'})
        review = support_for(tasks)
        review['tasks'][0]['acceptance_points'][-1].update(supported=False, duplicate_of=delivery['id'],
            reason='The same test delivery obligation is restated; the explicit canonical point remains.')
        before = copy.deepcopy((tasks, review))
        with self.assertRaises(engine.RequirementSupportError) as rejected:
            engine.validate_requirement_support(review, tasks, package, strict_semantics=True)
        filtered, excluded = engine.exclude_unsupported_points(tasks, rejected.exception.review)
        self.assertEqual(filtered[0]['acceptance_points'], tasks[0]['acceptance_points'][:-1])
        self.assertEqual(filtered[0]['goal'], tasks[0]['goal'])
        self.assertEqual(excluded[0]['candidate']['id'], 'duplicate-test')
        self.assertEqual((tasks, review), before)

    def test_rejected_delivery_rebuilds_title_goal_and_points_once_or_stops_before_freeze(self):
        candidate = copy.deepcopy(self.candidate)
        candidate['tasks'][0].update(title='Fix output and deliver tests', goal=ISSUE + ' Deliver regression tests.')
        candidate['tasks'][0]['acceptance_points'][-1].update(kind='test_delivery',
            requirement='Deliver a regression assertion for the reported input.')
        before = copy.deepcopy((candidate, self.package))
        owner = self
        for persistent in (False, True):
            with self.subTest(persistent=persistent):
                calls, records = [], {}

                class Client:
                    def complete(client, system, request, directory, stage):
                        calls.append(stage)
                        if stage.startswith('task-extraction'):
                            value = copy.deepcopy(candidate)
                            if '-recheck-' in stage:
                                owner.assertIn('一并重建title、goal和验收点', request['reextraction_instruction'])
                                owner.assertIn('原候选及复核记录保留', request['reextraction_instruction'])
                                owner.assertIn('Deliver regression tests.', request['previous_unfrozen_candidate'][0]['goal'])
                                if not persistent:
                                    value['tasks'][0].update(title='Fix output', goal=ISSUE)
                                    value['tasks'][0]['acceptance_points'] = value['tasks'][0]['acceptance_points'][:1]
                        elif stage.startswith('requirement-review'):
                            value = support_for(request['candidate_tasks'])
                            if request['candidate_tasks'][0]['acceptance_points'][-1]['kind'] == 'test_delivery':
                                value['tasks'][0]['acceptance_points'][-1].update(supported=False,
                                    source_class='reported_problem', reason='The reported behavior does not require test-source delivery.')
                        else:
                            value = scripted_result(request)
                        records[stage] = copy.deepcopy(value)
                        with (Path(directory) / (stage + '.original.json')).open('x') as stream:
                            json.dump(value, stream)
                        return value

                with tempfile.TemporaryDirectory() as directory:
                    if persistent:
                        with self.assertRaisesRegex(ValueError, '无法建立受用户原话支持'):
                            engine.analyze(self.package, Client(), directory)
                        self.assertFalse((Path(directory) / 'frozen-tasks.json').exists())
                        self.assertNotIn('analysis-1', calls)
                        self.assertEqual(len(calls), 4)
                    else:
                        result = engine.analyze(self.package, Client(), directory)
                        frozen = json.loads((Path(directory) / 'frozen-tasks.json').read_text())
                        self.assertEqual(frozen['tasks'], result['tasks'])
                        self.assertEqual(frozen['tasks'][0]['title'], 'Fix output')
                        self.assertEqual(frozen['tasks'][0]['goal'], ISSUE)
                        self.assertEqual([point['kind'] for point in frozen['tasks'][0]['acceptance_points']], ['behavior'])
                        self.assertEqual(frozen['excluded_candidates'], [])
                    self.assertEqual(calls[:4], ['task-extraction-1', 'requirement-review-1',
                        'task-extraction-recheck-1', 'requirement-review-recheck-1'])
                    self.assertFalse(any('-filtered-' in stage for stage in calls))
                    self.assertTrue((Path(directory) / 'requirement-review.validation.json').exists())
                    for stage, record in records.items():
                        self.assertEqual(json.loads((Path(directory) / (stage + '.original.json')).read_text()), record)
                self.assertEqual((candidate, self.package), before)

    def test_source_repair_keeps_summary_and_delivery_rejections_in_reextraction_request(self):
        payload = synthetic_payload()
        payload['trace']['messages'] = [{'role': 'user', 'content': ISSUE + '\nExpected output is the string ID.'}]
        package = engine.normalize(payload, RULES)
        user = next(item for item in package['evidence'] if item['kind'] == 'user_requirement')
        candidate = baseline_for(package)
        candidate['tasks'][0]['goal'] += ' Deliver regression tests.'
        candidate['tasks'][0]['acceptance_points'].append({
            'id': 'inferred-delivery', 'kind': 'test_delivery',
            'requirement': 'Deliver a regression assertion.', 'requirement_refs': [reference(user, 2)]})
        before = copy.deepcopy((package, candidate))
        owner, calls, responses, recheck_requests = self, [], {}, []
        reason = 'An expected result does not request delivery of test-source assertions.'

        class Client:
            def complete(client, system, request, directory, stage):
                calls.append(stage)
                if stage.startswith('task-extraction'):
                    value = copy.deepcopy(candidate)
                    if '-recheck-' in stage:
                        recheck_requests.append(copy.deepcopy(request))
                        owner.assertIn('支持依据超出候选', request['requirement_support_feedback'][0])
                        owner.assertEqual(request['requirement_review_feedback'], responses['requirement-review-1'])
                        owner.assertIn(reason, json.dumps(request['requirement_review_feedback']))
                        value['tasks'][0]['goal'] = ISSUE
                        value['tasks'][0]['acceptance_points'] = value['tasks'][0]['acceptance_points'][:1]
                        value['tasks'][0]['requirement_refs'].append(reference(user, 2))
                        value['tasks'][0]['acceptance_points'][0]['requirement_refs'].append(reference(user, 2))
                elif stage.startswith('requirement-review'):
                    value = support_for(request['candidate_tasks'])
                    if '-recheck-' not in stage:
                        row = value['tasks'][0]
                        row['acceptance_points'][0]['source_refs'].append(reference(user, 2))
                        row['acceptance_points'][-1].update(supported=False,
                            source_class='reported_problem', reason=reason)
                        next(summary for summary in row['summary_checks'] if summary['field'] == 'goal').update(
                            supported=False, reason=reason)
                else:
                    value = scripted_result(request)
                responses[stage] = copy.deepcopy(value)
                return value

        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(package, Client(), directory)
            receipt = json.loads((Path(directory) / 'requirement-review.reextraction.json').read_text())
            self.assertEqual(receipt['support_review'], responses['requirement-review-1'])
            self.assertTrue(receipt['changes'])
            frozen = json.loads((Path(directory) / 'frozen-tasks.json').read_text())
            self.assertEqual(frozen['tasks'], result['tasks'])
            self.assertEqual(frozen['tasks'][0]['goal'], ISSUE)
            self.assertEqual([point['kind'] for point in frozen['tasks'][0]['acceptance_points']], ['behavior'])
            self.assertEqual(frozen['excluded_candidates'], [])
        self.assertEqual(calls[:4], ['task-extraction-1', 'requirement-review-1',
                                    'task-extraction-recheck-1', 'requirement-review-recheck-1'])
        self.assertEqual(sum(stage.startswith('task-extraction') for stage in calls), 2)
        self.assertEqual(len(recheck_requests), 1)
        self.assertEqual((package, candidate), before)

    def test_source_reextraction_receives_program_rejections_even_when_raw_review_says_supported(self):
        for defect in ('summary', 'test_delivery', 'both_no_gap'):
            with self.subTest(defect=defect):
                summary_bad = defect in ('summary', 'both_no_gap')
                delivery_bad = defect in ('test_delivery', 'both_no_gap')
                expected_kinds = ({'summary'} if summary_bad else set()) | ({'test_delivery'} if delivery_bad else set())
                payload = synthetic_payload()
                payload['trace']['messages'] = [{'role': 'user', 'content': ISSUE +
                    '\nExpected output is the string ID.\nI think the output is a string.'}]
                package = engine.normalize(payload, RULES)
                user = next(item for item in package['evidence'] if item['kind'] == 'user_requirement')
                candidate = baseline_for(package)
                task = candidate['tasks'][0]
                task['goal'] += ' The output is a string.' if summary_bad else ' Deliver regression tests.'
                task['requirement_refs'].append(reference(user, 3))
                if delivery_bad:
                    task['acceptance_points'].append({'id': 'inferred-delivery', 'kind': 'test_delivery',
                        'requirement': 'Deliver regression assertions.', 'requirement_refs': [reference(user, 2)]})
                before = copy.deepcopy((package, candidate))
                owner, calls, responses = self, [], {}

                class Client:
                    def complete(client, system, request, directory, stage):
                        calls.append(stage)
                        if stage.startswith('task-extraction'):
                            value = copy.deepcopy(candidate)
                            if '-recheck-' in stage:
                                if defect != 'both_no_gap':
                                    owner.assertEqual(request['requirement_review_feedback'], responses['requirement-review-1'])
                                else:
                                    owner.assertTrue(responses['requirement-review-1']['tasks'][0]['summary_checks'][1]['supported'])
                                    owner.assertFalse(request['requirement_review_feedback']['tasks'][0]['summary_checks'][1]['supported'])
                                    owner.assertTrue(request['requirement_review_feedback']['tasks'][0]['acceptance_points'][-1]['supported'])
                                owner.assertTrue(expected_kinds <= {issue['kind'] for issue in request['program_rejections']})
                                owner.assertIn('supported=true不能覆盖', request['reextraction_instruction'])
                                value['tasks'][0]['goal'] = ISSUE
                                value['tasks'][0]['acceptance_points'] = value['tasks'][0]['acceptance_points'][:1]
                                value['tasks'][0]['acceptance_points'][0]['requirement_refs'].append(reference(user, 2))
                        elif stage.startswith('requirement-review'):
                            value = support_for(request['candidate_tasks'])
                            if '-recheck-' not in stage:
                                row = value['tasks'][0]
                                if defect != 'both_no_gap':
                                    row['acceptance_points'][0]['source_refs'].append(reference(user, 2))
                                if delivery_bad:
                                    row['acceptance_points'][-1]['source_class'] = 'reported_problem'
                                if summary_bad:
                                    row['summary_checks'][1]['fragments'] = [
                                        {'text': ISSUE + ' ', 'source_class': 'explicit_request',
                                         'presentation': 'requirement', 'source_refs': [reference(user)]},
                                        {'text': 'The output is a string.', 'source_class': 'diagnostic_hypothesis',
                                         'presentation': 'asserted_fact', 'source_refs': [reference(user, 3)]}]
                        else:
                            value = scripted_result(request)
                        responses[stage] = copy.deepcopy(value)
                        return value

                with tempfile.TemporaryDirectory() as directory:
                    result = engine.analyze(package, Client(), directory)
                    receipt_path = Path(directory) / 'requirement-review.reextraction.json'
                    if defect != 'both_no_gap':
                        receipt = json.loads(receipt_path.read_text())
                        self.assertEqual(receipt['support_review'], responses['requirement-review-1'])
                        self.assertTrue(expected_kinds <= {issue['kind'] for issue in receipt['program_rejections']})
                    else:
                        self.assertFalse(receipt_path.exists())
                    self.assertEqual(result['tasks'][0]['goal'], ISSUE)
                    self.assertEqual([point['kind'] for point in result['tasks'][0]['acceptance_points']], ['behavior'])
                self.assertEqual(sum(stage.startswith('task-extraction') for stage in calls), 2)
                self.assertFalse(any('-filtered-' in stage for stage in calls))
                self.assertEqual((package, candidate), before)

    def test_filter_rejects_unsupported_goal_omissions_or_removing_all_points(self):
        for defect in ("goal", "omission", "all_points"):
            with self.subTest(defect=defect):
                review = self.review_with_inference(self.tasks)
                if defect == "goal":
                    review["tasks"][0].update(supported=False, reason="The task goal is not requested by the user.")
                elif defect == "omission":
                    user = next(item for item in self.package["evidence"] if item["kind"] == "user_requirement")
                    review["tasks"][0]["missing_requirements"] = [{
                        "requirement": ISSUE, "source_class": "explicit_request", "requirement_refs": [reference(user)]}]
                else:
                    review["tasks"][0]["acceptance_points"][0].update(
                        supported=False, reason="This point is also unsupported.")
                reviewed = self.validated_rejection(review)
                self.assertEqual(engine.exclude_unsupported_points(self.tasks, reviewed), (None, []))

    def test_partial_exclusion_requires_complete_user_review_before_freezing(self):
        calls = []
        original = copy.deepcopy(self.package)
        test = self

        class Client:
            def complete(self, system, payload, output_dir, stage):
                calls.append((stage, copy.deepcopy(payload)))
                if stage.startswith("task-extraction"):
                    return copy.deepcopy(test.candidate)
                if stage == "requirement-review-1":
                    return test.review_with_inference(payload["candidate_tasks"])
                if stage == "requirement-review-filtered-1":
                    test.assertFalse((Path(output_dir) / "frozen-tasks.json").exists())
                    test.assertEqual(payload["candidate_tasks"][0]["acceptance_points"],
                                     [test.tasks[0]["acceptance_points"][0]])
                    test.assertEqual([item["content"] for item in payload["evidence"]], [ISSUE])
                    return support_for(payload["candidate_tasks"])
                test.assertEqual(payload["fixed_tasks"][0]["acceptance_points"],
                                 [test.tasks[0]["acceptance_points"][0]])
                return scripted_result(payload)

        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(self.package, Client(), directory)
            exclusions = json.loads((Path(directory) / "requirement-exclusions.json").read_text())
            frozen = json.loads((Path(directory) / "frozen-tasks.json").read_text())
        self.assertEqual(self.package, original)
        self.assertEqual([stage for stage, _ in calls], ["task-extraction-1", "requirement-review-1",
                         "requirement-review-filtered-1", "analysis-1", "counter-review-1"])
        self.assertEqual(result["tasks"][0]["acceptance_points"], [self.tasks[0]["acceptance_points"][0]])
        self.assertEqual(exclusions["excluded_candidates"][0]["candidate"], self.tasks[0]["acceptance_points"][1])
        self.assertEqual(frozen["excluded_candidates"], exclusions["excluded_candidates"])

    def test_filtered_review_detecting_an_omission_never_freezes_or_starts_analysis(self):
        stages = []
        test = self

        class Client:
            def complete(self, system, payload, output_dir, stage):
                stages.append(stage)
                if stage.startswith("task-extraction"):
                    return copy.deepcopy(test.candidate)
                if stage.startswith("requirement-review"):
                    review = support_for(payload["candidate_tasks"])
                    if "-filtered-" in stage:
                        user = next(item for item in payload["evidence"] if item["kind"] == "user_requirement")
                        review["tasks"][0]["missing_requirements"] = [{
                            "requirement": ISSUE, "source_class": "explicit_request", "requirement_refs": [reference(user)]}]
                    else:
                        review = test.review_with_inference(payload["candidate_tasks"])
                    return review
                raise AssertionError("An incomplete filtered baseline cannot enter audit analysis.")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                engine.analyze(self.package, Client(), directory)
            self.assertFalse((Path(directory) / "frozen-tasks.json").exists())
            self.assertTrue((Path(directory) / "requirement-exclusions.json").exists())
        self.assertTrue(any("-filtered-" in stage for stage in stages))
        self.assertFalse(any(stage.startswith(("analysis", "counter-review")) for stage in stages))


if __name__ == "__main__":
    unittest.main()
