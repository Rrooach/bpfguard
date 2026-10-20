"""Offline multi-trial budget continuity; no provider or real credentials."""
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from test_model_budget_v2 import B, registration, pricing
import codex_response_budget as C


class RollforwardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def first(self, *, settle=True, prompt=100, output=10):
        ledger = B.Ledger(self.root/'first', registration(), pricing())
        label = 'model-swe-c2-00'
        reservation = ledger.reserve(b'{}', 1024, label, label+'-step-0')
        if settle: ledger.settle(reservation, {'prompt_tokens': prompt, 'completion_tokens': output})
        return ledger

    def following(self, name='next', prior='first', **kwargs):
        ledger = B.Ledger(self.root/name, dict(registration(), campaign_id=name), pricing(),
            prior_ledger=self.root/prior/'budget-ledger.jsonl', **kwargs)
        self.addCleanup(ledger.close)
        return ledger

    def test_closed_prior_replayed_bound_added_and_lock_held(self):
        first = self.first(); before = first.summary(); first.close()
        ledger = self.following()
        self.assertEqual(Decimal(ledger.summary()['historical_bound_rmb']),
            Decimal(before['combined_bound_rmb']))
        self.assertEqual(ledger.config['prior_budget_evidence']['requests'], 1)
        with self.assertRaisesRegex(B.BudgetError, 'retired'):
            B.Ledger(self.root/'first', registration(), pricing())

    def test_active_prior_rejected(self):
        first = self.first(); self.addCleanup(first.close)
        with self.assertRaisesRegex(B.BudgetError, 'prior broker is still active'):
            self.following()

    def test_pending_prior_reservation_retained_in_full(self):
        first = self.first(settle=False); expected = first.summary()['combined_bound_rmb']; first.close()
        ledger = self.following()
        self.assertEqual(ledger.summary()['historical_bound_rmb'], expected)
        self.assertEqual(ledger.config['prior_budget_evidence']['outstanding_or_unknown_requests'], 1)

    def test_combined_five_cny_cap_cannot_be_reset(self):
        first = self.first(prompt=8000, output=1024)
        first.close()
        second = self.following()
        second.close()
        third = self.following('third', 'next')
        self.assertEqual(third.summary()['historical_bound_rmb'], second.summary()['historical_bound_rmb'])
        third.close()
        path = self.root/'first'/'budget-ledger.jsonl'
        # Existing historical amount is part of the CONFIGURED digest; tamper
        # is rejected rather than allowing a new trial to erase cost.
        rows = path.read_bytes().splitlines()
        configured = json.loads(rows[0]); configured['config']['historical_bound_rmb'] = '0'
        rows[0] = B.canonical(configured); path.write_bytes(b'\n'.join(rows)+b'\n')
        with self.assertRaisesRegex(B.BudgetError, 'digest|retired'):
            self.following('tampered')

    def test_costly_prior_requires_smaller_new_limit(self):
        first = B.Ledger(self.root/'first', registration(), pricing())
        for index in range(8):
            label = f'model-swe-c2-{index:02d}'
            item = first.reserve(b'x'*20000, 1024, label, label+'-step-0')
            first.settle(item, {'prompt_tokens': 26000, 'completion_tokens': 1024})
        self.assertGreater(Decimal(first.summary()['combined_bound_rmb'])+Decimal('4.2'), Decimal(5))
        first.close()
        with self.assertRaisesRegex(B.BudgetError, 'exceeds five'):
            self.following()
        self.assertLessEqual(Decimal(self.following('smaller', limit='4.0').summary()['historical_bound_rmb'])
            +Decimal('4.0'), Decimal(5))

    def test_truncated_prior_never_opens_next_budget(self):
        first = self.first(); first.close()
        path = self.root/'first'/'budget-ledger.jsonl'
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaisesRegex(B.BudgetError, 'truncated'):
            self.following()

    def test_prior_cannot_branch_or_restart_even_after_successor_exits(self):
        first = self.first(); first.close()
        second = self.following(); second.close()
        with self.assertRaisesRegex(B.BudgetError, 'different successor'): self.following('branch')
        with self.assertRaisesRegex(B.BudgetError, 'retired'):
            B.Ledger(self.root/'first', registration(), pricing())
        third = self.following('third', 'next'); third.close()
        with self.assertRaisesRegex(B.BudgetError, 'retired'):
            B.Ledger(self.root/'first', registration(), pricing())
        # Only the current generation may restart with the exact prior binding.
        self.following('third', 'next')

    def test_verified_opaque_context_is_reserved_per_occurrence(self):
        ledger = B.Ledger(self.root/'extra', registration(), pricing())
        self.addCleanup(ledger.close)
        label = 'model-swe-c2-00'
        item = ledger.reserve(b'{}', 1024, label, label+'-step-0', extra_input_tokens=2048)
        self.assertEqual(item['input_tokens_bound'], 2+8192+2048)
        self.assertEqual(item['extra_input_tokens_bound'], 2048)
        self.assertEqual(Decimal(item['cost_rmb_bound']), B.token_cost(2+8192+2048, 1024))

    def test_codex_demo_rolls_to_terminal32_without_resetting_spent_cost(self):
        demo = B.Ledger(self.root/'demo', C.registration('demo'), pricing(), '.4', provider_endpoint=C.ENDPOINT)
        for index in range(2):
            item = demo.reserve(b'{}', 1024, C.LABEL, C.LABEL+'-step-'+str(index))
            demo.settle(item, {'prompt_tokens': 100, 'completion_tokens': 10})
        demo_total = demo.summary()['combined_bound_rmb']; demo.close()
        path = self.root/'demo'/'budget-ledger.jsonl'
        campaign = C.registration('terminal', 'terminal')
        terminal = B.Ledger(self.root/'terminal', campaign, pricing(), '4.0', path, provider_endpoint=C.ENDPOINT)
        self.assertEqual(terminal.summary()['historical_bound_rmb'], demo_total)
        self.assertEqual(terminal.config['prior_budget_evidence']['requests'], 2)
        self.assertEqual(len(terminal.labels), 32)
        self.assertLessEqual(Decimal(demo_total) + Decimal('4.0'), Decimal(5))
        terminal.close()
        with self.assertRaisesRegex(B.BudgetError, 'retired'):
            B.Ledger(self.root/'demo', C.registration('demo'), pricing(), '.4', provider_endpoint=C.ENDPOINT)
        restarted = B.Ledger(self.root/'terminal', campaign, pricing(), '4.0', path, provider_endpoint=C.ENDPOINT)
        restarted.close()

    def test_codex_terminal_registry_and_ledger_cap_must_be_identical(self):
        for limit in ('3.9', '4.2'):
            with self.subTest(limit=limit), self.assertRaisesRegex(B.BudgetError, 'cap must match'):
                B.Ledger(self.root/limit, C.registration('terminal', 'terminal'), pricing(), limit,
                    provider_endpoint=C.ENDPOINT)

    def test_terminal_v1_to_v2_keeps_exact_calibration_cost_and_new4096_contract(self):
        first = B.Ledger(self.root/'terminal-v1', C.registration('calibration', 'terminal'), pricing(), '4.0', provider_endpoint=C.ENDPOINT)
        label = 'codex-terminal-c2-00'
        item = first.reserve(b'x' * 50000, 1024, label, label+'-step-0')
        first.settle(item, {'prompt_tokens': 57001, 'completion_tokens': 1001})
        expected = first.summary()['combined_bound_rmb']; first.close()
        path = self.root/'terminal-v1'/'budget-ledger.jsonl'
        v2 = B.Ledger(self.root/'terminal-v2', C.registration('formal-v2', 'terminal-v2'), pricing(), '4.0', path,
            provider_endpoint=C.ENDPOINT)
        self.addCleanup(v2.close)
        self.assertEqual(v2.summary()['historical_bound_rmb'], expected)
        self.assertEqual(Decimal(v2.config['prior_budget_evidence']['accounted_cost_rmb_upper_bound']), Decimal('0.122010'))
        self.assertEqual(v2.config['max_output_tokens'], 4096)
        self.assertEqual(v2.config['reasoning_effort'], 'none')
        item = v2.reserve(b'{}', 4096, label, label+'-step-0')
        v2.settle(item, {'prompt_tokens': 100, 'completion_tokens': 4096})
        v2_total = v2.summary()['combined_bound_rmb']; v2.close()
        next_v2 = B.Ledger(self.root/'next-v2', C.registration('next-v2', 'terminal-v2'), pricing(), '4.0',
            self.root/'terminal-v2'/'budget-ledger.jsonl', provider_endpoint=C.ENDPOINT)
        self.assertEqual(next_v2.summary()['historical_bound_rmb'], v2_total); next_v2.close()
        with self.assertRaisesRegex(B.BudgetError, 'retired'):
            B.Ledger(self.root/'terminal-v1', C.registration('calibration', 'terminal'), pricing(), '4.0', provider_endpoint=C.ENDPOINT)


if __name__ == '__main__': unittest.main()
