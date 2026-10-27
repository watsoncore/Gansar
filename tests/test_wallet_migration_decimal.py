"""Large legitimate token quantities must remain exact and displayable."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import unittest

from app.aggregator.analyzer import _build_wallet_migration
from app.models.report import AddressReport, Transaction


class WalletMigrationDecimalTests(unittest.TestCase):
    def test_uint256_quantity_and_fraction_sum_without_quantize_failure(self):
        target = "TCiRCBNFrL6bFKWL94yWQi5hNMGNp1Nu27"
        quantity = Decimal(2**256-1)
        values = [quantity, Decimal("0.000000001"), Decimal("0.1"), Decimal("0.2"), Decimal("1")]
        stamp = datetime(2026, 10, 16, tzinfo=timezone.utc)
        report = AddressReport(target_address=target, detected_chains=["tron"], transactions=[
            Transaction(chain="tron", tx_hash=str(index), from_address=target,
                to_address="TYASr5UV6HEcXatwdFQfmLVUqQQQMUxHLS", amount_decimal=value,
                amount=float(value), asset="FIXTURE", source="fixture", success=True,
                direction="out", timestamp=stamp+timedelta(seconds=index),
                raw={"contract": "fixture-token", "type": "trc20_transfer"})
            for index, value in enumerate(values)])
        with localcontext() as context:
            context.prec = 28
            result = _build_wallet_migration(report)
            self.assertEqual(context.prec, 28)
        with localcontext() as context:
            context.prec = 100
            expected = format(sum(values), ".6f")
        self.assertTrue(result.facts["transferred_value"][0].endswith(": "+expected))
        self.assertEqual(result.raw["largest_outgoing_by_asset"][next(iter(result.raw["largest_outgoing_by_asset"]))], str(quantity))

    def test_small_decimal_display_and_failed_transfer_filter_preserved(self):
        stamp = datetime(2026, 10, 16, tzinfo=timezone.utc)
        report = AddressReport(target_address="0:"+"11"*32, transactions=[
            Transaction(chain="ton", tx_hash=str(index), from_address="0:"+"11"*32,
                to_address="0:"+"22"*32, amount_decimal=Decimal("0.1"), amount=.1,
                asset="TON", source="fixture", success=index != 4, direction="out",
                timestamp=stamp+timedelta(seconds=index)) for index in range(5)])
        result = _build_wallet_migration(report)
        self.assertTrue(result.facts["transferred_value"][0].endswith(": 0.400000"))


if __name__ == "__main__":
    unittest.main()
