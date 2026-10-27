"""Same report and secret guards, without repeated nested redaction."""
import copy
import unittest
from unittest.mock import patch
from app.models.report import AddressReport, Transaction, validated_report_copy
from app.utils.security import portable_observation

class ReportValidationBoundary(unittest.TestCase):
    def report(self):
        # Mutation after construction tests that this boundary still protects
        # observations supplied by untrusted collectors or resumed snapshots.
        report = AddressReport(target_address="0x" + "1"*40)
        report.transactions = [Transaction(chain="eth", tx_hash="0x"+"2"*64, source="fixture", asset="ETH", amount=1)]
        report.transactions[0].raw = {"Authorization":"Bearer never_publish", "nested":{"api_key":"never_publish", "amount":19}, "url":"https://example.com/?api_key=never_publish"}
        return report

    def test_exact_same_guarded_model_and_detached_sources(self):
        report=self.report(); before=copy.deepcopy(report.model_dump())
        expected=AddressReport.model_validate(report.model_dump()).model_dump()
        actual=validated_report_copy(report)
        self.assertEqual(actual.model_dump(),expected)
        self.assertEqual(report.model_dump(),before)
        self.assertNotIn("never_publish",actual.model_dump_json())
        actual.transactions[0].raw["nested"]["amount"]=20
        self.assertEqual(report.transactions[0].raw["nested"]["amount"],19)

    def test_guard_runs_once_and_does_not_trust_provider_marker(self):
        report=self.report(); report.transactions[0].raw["_PROTECTED_REPORT_TREE"]=True
        with patch("app.models.report.portable_observation",wraps=portable_observation) as guard:
            result=validated_report_copy(report)
        self.assertEqual(guard.call_count,1)
        self.assertNotIn("never_publish",result.model_dump_json())
        report.transactions[0].raw["nested"]["api_key"]="changed_secret"
        self.assertNotIn("changed_secret",validated_report_copy(report).model_dump_json())

    def test_other_field_validators_are_not_skipped(self):
        report=self.report(); report.transactions[0].direction="invalid_direction"
        with self.assertRaises(ValueError):validated_report_copy(report)

    def test_exclusion_is_exact_and_original_remains_present(self):
        report=self.report();report.nft_intelligence={"owner_analysis_snapshot":{"private_duplicate":True},"events":[{"id":"retained"}]}
        result=validated_report_copy(report,exclude={"nft_intelligence":{"owner_analysis_snapshot"}})
        self.assertEqual(result.nft_intelligence,{"events":[{"id":"retained"}]})
        self.assertIn("owner_analysis_snapshot",report.nft_intelligence)

if __name__=="__main__":unittest.main()
