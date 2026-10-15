"""Exercise the failure review's actual raw-to-canonical retry boundary offline."""
import copy
import unittest

from ..reference_repair import _quote_choices, attach_quote_ids, repair_references
from .test_engine_quote_retry import select_refs
from ..sop_failures import review_failures
from ..sop_judgments import UNKNOWN
from . import test_sop_failures as failure_fixtures


class FailureRetryReasonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        failure_fixtures.SopFailureReviewTests.setUpClass()

    def setUp(self):
        self.fixture = failure_fixtures.SopFailureReviewTests()
        self.fixture.setUp()
        self.entries = [self.fixture.entry('TC06.C01'), self.fixture.entry('TC09.C02')]
        self.calls, self.raw_checks = [], []

    def review(self, *, withdraw=False, inexact_retry=False):
        fixture = self.fixture
        good = fixture.answer(self.entries[0], obligation='U', contrary='PLAN')
        bad = fixture.answer(self.entries[1], obligation='AUTH', contrary='ACTION',
                             reason='The request uses DEMO_SECRET.')
        bad['counterexample_refs'][0]['quote'] = "requests.post('DEMO_SECRET', data=payload)"
        quote_id = next(oid for oid, ref in _quote_choices(fixture.package).items()
                        if ref['evidence_id'] == 'ACTION')

        def call(stage, system, payload, validator, **kwargs):
            self.calls.append(copy.deepcopy(payload))
            self.assertEqual(kwargs['attempts'], 1)
            self.assertFalse(kwargs['final_failure'])
            if len(self.calls) == 1:
                value = {'reviews': [copy.deepcopy(good), copy.deepcopy(bad)], 'root_causes': []}
            else:
                retry = copy.deepcopy(bad)
                retry['relation'] = 'evidence_insufficient'
                retry['counterexample_refs'] = [{'quote_id': quote_id}]
                if withdraw:
                    retry.update(reason='The claimed fact lacks visible support; keep the item unknown.',
                                 counterexample_refs=[])
                if inexact_retry:
                    retry['counterexample_refs'] = [fixture.ref('ACTION')]
                    retry['counterexample_refs'][0].update(start_line=2, end_line=2)
                value = {'reviews': [retry], 'root_causes': []}
                if not inexact_retry:
                    value = select_refs(value, attach_quote_ids(payload, fixture.package))
                self.assertTrue(payload['citation_retry']['selector_only'])
            self.raw_checks.append(copy.deepcopy(value))
            kwargs['before_repair'](value)
            canonical, _ = repair_references(value, fixture.package, [fixture.task],
                available_evidence_ids={item['id'] for item in payload['evidence']})
            return validator(canonical), None, False

        failures = []
        rows = [entry[0] for entry in self.entries]
        request = {'task': copy.deepcopy(fixture.task), 'evidence': copy.deepcopy(fixture.package['evidence'])}
        review_failures(rows, fixture.task, fixture.package, request, call, 'retry-boundary', failures)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.raw_checks), 2)
        self.assertEqual([candidate['id'] for candidate in self.calls[1]['candidates']],
                         [self.entries[1][2]['id']])
        anchors = self.calls[1]['reference_feedback'][0]['references'][0]['rejected_reason_anchors']
        self.assertIn('DEMO_SECRET', anchors)
        sibling = self.entries[0][1]['failure_review']
        self.assertEqual(sibling['status'], 'completed')
        self.assertEqual(sibling['reason'], good['reason'])
        self.assertEqual(sibling['relation'], 'direct_counterexample')
        return self.entries[1][1], failures

    def test_valid_replacement_quote_cannot_keep_rejected_literal_reason(self):
        check, failures = self.review()
        self.assertEqual(check['failure_review']['status'], 'failed')
        self.assertEqual(check['result'], UNKNOWN)
        self.assertEqual(len(failures), 1)
        self.assertIn('旧字面事实', failures[0]['reason'])

    def test_withdrawn_literal_is_accepted_as_unknown_without_filler_quote(self):
        check, failures = self.review(withdraw=True)
        self.assertEqual(check['failure_review']['status'], 'completed')
        self.assertEqual(check['failure_review']['relation'], 'evidence_insufficient')
        self.assertEqual(check['failure_review']['counterexample_refs'], [])
        self.assertEqual(check['result'], UNKNOWN)
        self.assertEqual(failures, [])

    def test_raw_retry_rejects_inexact_coordinates_before_automatic_repair(self):
        check, failures = self.review(withdraw=True, inexact_retry=True)
        self.assertEqual(check['failure_review']['status'], 'failed')
        self.assertEqual(check['result'], UNKNOWN)
        self.assertEqual(len(failures), 1)
        self.assertIn('不自动纠错', failures[0]['reason'])


if __name__ == '__main__':
    unittest.main()
