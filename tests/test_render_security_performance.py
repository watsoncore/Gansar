"""Rendering guard parity while sanitizing the graph tree only once."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from decimal import Decimal
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from app.exporters import render_security
from app.utils.security import sanitize_observation


def _previous_guard(value):
    """Reference behavior before removing redundant subtree sanitization."""
    clean = sanitize_observation(value)
    if isinstance(clean, dict):
        result = {}
        for key, item in clean.items():
            if key in {"image_url", "image", "avatar_image", "fallback_url"} and isinstance(item, str):
                result[key] = render_security.safe_image_url(item, allow_local=False)
            elif key in {"url", "external_url", "evidence_url", "explorer_url", "href"} and isinstance(item, str):
                result[key] = render_security.safe_href(item)
            else:
                result[key] = _previous_guard(item)
        return result
    if isinstance(clean, list):
        return [_previous_guard(item) for item in clean]
    return clean


class RenderSecurityTreeTests(unittest.TestCase):
    def test_render_model_guard_redacts_post_validation_mutations_and_preserves_deep_public_raw(self):
        from app.models.report import AddressReport, Transaction
        from app.exporters.html_exporter import export_html_report
        from app.graph.builder import build_graph_payload
        address='0:'+'1'*64
        report=AddressReport(target_address=address,detected_chains=['ton'],transactions=[
            Transaction(chain='ton',tx_hash='2'*64,source='synthetic_security_fixture',asset='TON')])
        deep={'public_marker':'DEEP_PUBLIC_FIXTURE_VALUE','private_key':'mutated_deep_secret'}
        for _ in range(60):deep={'child':deep}
        # Deliberately bypass normal construction: the exporter must still
        # protect every public boundary even after a caller mutates a model.
        report.transactions[0].raw={'api_key':'mutated_raw_secret','public_deep':deep,
            'text':'Bearer mutated_bearer_secret'}
        report.input_resolution={'owner_account_evidence':{'authorization':'mutated_resolution_secret'},
            'public_note':'Public observation survives'}
        report.attribution_intelligence={'evidence':[{'evidence_id':'fixture:mutation',
            'source':'synthetic_security_fixture','facts':{'access_token':'mutated_proof_secret',
                'public_note':'Public observation survives','public_deep':deep}}]}
        with tempfile.TemporaryDirectory() as directory:
            html=export_html_report(report,build_graph_payload(report),Path(directory)).output_path.read_text(encoding='utf-8')
        for secret in ('mutated_raw_secret','mutated_bearer_secret','mutated_deep_secret',
                'mutated_resolution_secret','mutated_proof_secret'):
            self.assertFalse(secret in html,'Post-validation secret leaked: '+secret)
        self.assertTrue('DEEP_PUBLIC_FIXTURE_VALUE' in html,'Deep public evidence was lost')
        self.assertTrue('Public observation survives' in html,'Public evidence note was lost')
        self.assertTrue('json_deep_provider_tail' in html,'Deep evidence codec was lost')
        self.assertEqual(report.transactions[0].raw['api_key'],'mutated_raw_secret')

    def test_nested_graph_matches_previous_guards_and_secret_redaction(self):
        value = {"nodes": [{"id": "wallet", "image_url": "https://cdn.tonapi.io/a.png?api_key=fixture_secret",
            "fallback_url": "logo/local.png", "evidence": [{"url": "https://user:password@example.com/proof?api_key=fixture_secret&page=2",
                "authorization": "fixture_secret", "text": "Bearer fixture_token password=fixture_password"}],
            "metadata": {"avatar_image": "https://unapproved.example.com/avatar.png", "image": "javascript:alert(1)",
                "external_url": "http://127.0.0.1/private", "explorer_url": "https://tonviewer.com/a",
                "href": "#proof", "nested": ({"href": "graph.json", "private_key": "fixture_secret"},)}}],
            "edges": [{"url": "http://0177.0.0.1/", "href": "file:///private", "amount": Decimal("1.234"),
                "observed_at": datetime(2026, 10, 16, tzinfo=timezone.utc)}], 12: "number_key"}
        actual = render_security.safe_graph_payload(value)
        self.assertEqual(actual, _previous_guard(value))
        node = actual["nodes"][0]
        self.assertIn("REDACTED", node["image_url"])
        self.assertEqual(node["fallback_url"], "")
        self.assertEqual(node["metadata"]["avatar_image"], "")
        self.assertEqual(node["metadata"]["image"], "")
        self.assertEqual(node["metadata"]["external_url"], "")
        self.assertEqual(actual["edges"][0]["url"], "")
        self.assertEqual(actual["edges"][0]["href"], "")
        self.assertEqual(node["evidence"][0]["authorization"], "[REDACTED]")
        self.assertNotIn("fixture_token", node["evidence"][0]["text"])
        self.assertEqual(node["metadata"]["nested"][0]["href"], "graph.json")

    def test_guard_returns_independent_containers_without_mutating_caller(self):
        shared = {"url": "https://example.com/proof?access_token=fixture_secret", "api_key": "fixture_secret"}
        original = {"a": shared, "b": [shared], "tuple": (shared,)}
        before = copy.deepcopy(original)
        clean = render_security.safe_graph_payload(original)
        self.assertEqual(original, before)
        self.assertIs(original["a"], original["b"][0])
        self.assertIsInstance(clean["tuple"], list)
        clean["a"]["url"] = "changed"
        self.assertNotEqual(clean["b"][0]["url"], "changed")
        self.assertEqual(original, before)

    def test_canonical_sanitizer_runs_once_for_entire_large_tree(self):
        graph = {"nodes": [{"id": str(index), "properties": {"proof": {"url": "https://example.com/proof",
            "raw": {"api_key": "fixture_secret", "value": "Bearer fixture_token"}}}} for index in range(1000)]}
        with patch.object(render_security, "sanitize_observation", wraps=sanitize_observation) as sanitize:
            clean = render_security.safe_graph_payload(graph)
        self.assertEqual(sanitize.call_count, 1)
        self.assertEqual(len(clean["nodes"]), 1000)
        self.assertEqual(clean["nodes"][-1]["properties"]["proof"]["raw"]["api_key"], "[REDACTED]")

    def test_approved_renderer_icons_and_unsafe_svg_retain_previous_policy(self):
        import base64
        safe = "data:image/svg+xml;base64," + base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>').decode()
        unsafe = "data:image/svg+xml;base64," + base64.b64encode(b'<svg><script>alert(1)</script></svg>').decode()
        value = {"nested": [{"image": safe}, {"image_url": unsafe}, {"avatar_image": "https://localhost/a"},
            {"fallback_url": "https://raw.githubusercontent.com/example/logo.png"}]}
        clean = render_security.safe_graph_payload(value)
        self.assertEqual(clean, _previous_guard(value))
        self.assertEqual(clean["nested"][0]["image"], safe)
        self.assertEqual(clean["nested"][1]["image_url"], "")
        self.assertEqual(clean["nested"][2]["avatar_image"], "")


if __name__ == "__main__":
    unittest.main()
