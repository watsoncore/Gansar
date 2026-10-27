"""Addressed replay/boundary controls, separate from actual live validation."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.sources.eas_public import EasAttestationSource, _query, _checksum

TARGET = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
CAPTURE = json.loads(Path(__file__).with_name("fixtures").joinpath("eas_public_vitalik.json").read_text(encoding="utf8"))
META = {"retrieved_at": CAPTURE["captured_at"], "cache_hit": False,
        "transport_requests": 1, "response_bytes": 1, "response_sha256": "unit-boundary-control"}


class EasPublicTests(unittest.IsolatedAsyncioTestCase):
    async def fetch(self, data):
        source = EasAttestationSource()
        with patch.object(source, "_request", AsyncMock(return_value=(data, META))):
            report = await source.fetch(TARGET)
        self.assertFalse(report.transactions)
        self.assertFalse(report.labels)
        self.assertFalse(report.risk_flags)
        self.assertEqual(report.risk_score, 0)
        return report.public_address_context["outcomes"][0]

    def test_case_sensitive_api_query_has_exact_lower_and_checksum_target(self):
        self.assertEqual(_checksum(TARGET), "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        query = _query(TARGET)
        self.assertEqual(query["variables"]["addresses"], [TARGET, _checksum(TARGET)])
        self.assertIn("isOffchain: {equals: false}", query["query"])
        self.assertEqual(query["variables"]["take"], 9)

    async def test_actual_capture_preserves_uid_roles_schema_and_reported_status(self):
        response = copy.deepcopy(CAPTURE["response"])
        before = copy.deepcopy(response)
        outcome = await self.fetch(response)
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(len(outcome["claims"]), 4)
        self.assertEqual(response, before)
        self.assertEqual(outcome["evidence"]["response"], response)
        for claim, row in zip(outcome["claims"], response["data"]["attestations"]):
            self.assertEqual(claim["claim_status"], "provider_reported")
            self.assertEqual(claim["value"]["uid"], row["id"])
            self.assertEqual(claim["value"]["schema_uid"], row["schemaId"])
            self.assertEqual(claim["value"]["target_role"], "recipient")
            self.assertFalse(claim["value"]["independently_verified_onchain"])

    async def test_offchain_and_wrong_subject_never_become_address_links(self):
        data = copy.deepcopy(CAPTURE["response"])
        rows = data["data"]["attestations"]
        rows[0]["isOffchain"] = True
        rows[1]["recipient"] = rows[1]["attester"]
        outcome = await self.fetch(data)
        self.assertEqual(outcome["status"], "partial")
        self.assertEqual(len(outcome["claims"]), 2)
        self.assertEqual(len(outcome["coverage"]["rejected_records"]), 2)

    async def test_revoked_and_expired_assertions_are_not_shown_as_current(self):
        data = copy.deepcopy(CAPTURE["response"])
        rows = data["data"]["attestations"]
        rows[0]["revoked"] = True
        rows[1]["expirationTime"] = 1
        outcome = await self.fetch(data)
        states = [claim["value"]["temporal_status"] for claim in outcome["claims"]]
        self.assertEqual(states[:2], ["revoked", "expired"])
        self.assertTrue(all(claim["claim_status"] == "provider_reported" for claim in outcome["claims"]))

    async def test_limited_page_keeps_full_raw_and_marks_more_available(self):
        with patch("app.sources.eas_public.MAX_RECORDS", 1):
            outcome = await self.fetch(copy.deepcopy(CAPTURE["response"]))
        self.assertEqual(len(outcome["claims"]), 1)
        self.assertEqual(outcome["status"], "partial")
        self.assertTrue(outcome["coverage"]["more_available"])
        self.assertFalse(outcome["coverage"]["history_complete"])
        self.assertEqual(len(outcome["evidence"]["response"]["data"]["attestations"]), 4)

    async def test_schema_mismatch_is_retained_only_as_rejected_raw(self):
        data = copy.deepcopy(CAPTURE["response"])
        data["data"]["attestations"][0]["schema"]["id"] = "mismatched-unit-control"
        outcome = await self.fetch(data)
        self.assertEqual(len(outcome["claims"]), 3)
        self.assertEqual(outcome["status"], "partial")

    async def test_provider_rate_limit_is_honest_outcome_not_pipeline_exception(self):
        source = EasAttestationSource()
        request = httpx.Request("POST", "https://easscan.org/graphql")
        error = httpx.HTTPStatusError("rate limited", request=request, response=httpx.Response(429, request=request))
        with patch.object(source, "_request", AsyncMock(side_effect=error)):
            result = await source.fetch(TARGET)
        self.assertEqual(result.public_address_context["outcomes"][0]["status"], "rate_limited")
        self.assertEqual(result.public_address_context["outcomes"][0]["claims"], [])

    async def test_empty_lookup_is_empty_without_synthetic_identity(self):
        outcome = await self.fetch({"data": {"attestations": []}})
        self.assertEqual(outcome["status"], "empty")
        self.assertEqual(outcome["claims"], [])


if __name__ == "__main__":
    unittest.main()
