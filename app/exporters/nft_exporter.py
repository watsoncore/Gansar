"""Compatibility wrappers for the original Gansar HTML and opt-in technical exports."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any


from app.graph.nft_builder import build_nft_graph, record, records
from app.utils.security import sanitize_observation
from app.exporters.render_security import safe_graph_payload


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, indent=2)


def _write(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _csv_cell(value: Any) -> str:
    text = _json(value) if isinstance(value, (dict, list)) else str(value if value is not None else "")
    # Prevent a provider-controlled string from becoming a spreadsheet formula.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def _csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({key: _csv_cell(row.get(key)) for key in fields} for row in rows)
    os.replace(temporary, path)


def ownership_rows(result: Any) -> list[dict]:
    data = record(result)
    rows: list[dict] = []
    for asset in records(data.get("assets")):
        assertions = records(asset.get("ownership"))
        for index, assertion in enumerate(assertions):
            current = (index == len(assertions) - 1
                       and asset.get("current_owner_status") == "verified_onchain"
                       and assertion.get("status") == "verified_onchain"
                       and assertion.get("owner_address") == asset.get("current_owner"))
            rows.append({"asset_address": asset.get("address"), "owner_address": assertion.get("owner_address"),
                "role": "current_assertion" if current else "state_observation_at_timestamp", "status": assertion.get("status"), "timestamp": assertion.get("observed_at"),
                "logical_time": assertion.get("logical_time"), "method": assertion.get("method"), "evidence_ids": assertion.get("evidence_ids") or [],
                "block_reference": assertion.get("block_reference"), "raw": assertion})
        for historical in records(asset.get("historical_owners")):
            rows.append({"asset_address": asset.get("address"), "owner_address": historical.get("address") or historical.get("owner_address") or historical.get("owner"),
                "role": "historical_observation", "status": historical.get("verification") or historical.get("status") or "provider_reported",
                "timestamp": historical.get("timestamp") or historical.get("first_seen"), "logical_time": historical.get("logical_time"),
                "transaction_hash": historical.get("transaction_hash"), "event_id": historical.get("event_id"),
                "evidence_ids": historical.get("evidence_ids") or [], "raw": historical})
    return rows


def render_nft_dossier(result: Any, graph: dict | None = None, language: str = "ru") -> str:
    """Compatibility helper: the original HTML renderer is the only renderer."""
    from tempfile import TemporaryDirectory
    from app.exporters.html_exporter import render_html_report
    from app.graph.builder import build_graph_payload
    from app.ton_nft.models import NFTIntelligenceReport
    from app.ton_nft.service import report_to_address_report
    report = _address_dossier(NFTIntelligenceReport.model_validate(sanitize_observation(record(result))))
    with TemporaryDirectory() as directory:
        original_graph = graph if graph and graph.get("target") else build_graph_payload(report)
        return render_html_report(report, original_graph, Path(directory), language=language)


def export_nft_dossier(result: Any, output_dir: Path, language: str = "ru", graph: dict | None = None,
                       *, machine_exports: bool = False) -> dict[str, Path]:
    """Use original HTML; machine data files require explicit opt-in."""
    from app.exporters.html_exporter import export_html_report
    from app.graph.builder import build_graph_payload
    from app.ton_nft.models import NFTIntelligenceReport
    from app.ton_nft.service import report_to_address_report
    output_dir = Path(output_dir)
    data = sanitize_observation(record(result))
    intelligence = NFTIntelligenceReport.model_validate(data)
    report = _address_dossier(intelligence)
    original_graph = graph if graph and graph.get("target") else build_graph_payload(report)
    html_result = export_html_report(report, original_graph, output_dir, language=language)
    paths = {"html": html_result.output_path}
    if not machine_exports:
        return paths
    paths.update(export_nft_machine_data(data, output_dir, graph))
    return paths


def _address_dossier(intelligence):
    """Restore the ordinary owner dossier saved with this NFT investigation."""
    from app.models.report import AddressReport
    from app.ton_nft.service import report_to_address_report, attach_nft_intelligence
    from app.utils.ton_normalize import ton_canonical_address
    saved = getattr(intelligence, "owner_analysis_snapshot", None)
    resolution = getattr(intelligence, "input_resolution", {}) or {}
    if isinstance(saved, dict) and saved.get("target_address"):
        expected = resolution.get("owner_analysis_address") or resolution.get("normalized_query")
        if (ton_canonical_address(saved["target_address"])
                and ton_canonical_address(saved["target_address"]) == ton_canonical_address(expected)):
            report = AddressReport.model_validate(saved)
            attach_nft_intelligence(report, intelligence)
            return report
    return report_to_address_report(intelligence)


def export_nft_machine_data(result: Any, output_dir: Path, graph: dict | None = None) -> dict[str, Path]:
    """Optional technical exports, independent of the original wallet HTML."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    data = sanitize_observation(record(result))
    supplied_graph = graph.get("nft_intelligence_graph") if graph else None
    if graph and "ownership_timelines" in graph:
        supplied_graph = graph
    graph_data = safe_graph_payload(supplied_graph or build_nft_graph(data))
    paths = {"json": output_dir / "report.json", "events": output_dir / "events.jsonl",
        "ownership": output_dir / "ownership.csv", "transactions": output_dir / "transactions.csv", "graph": output_dir / "graph.json"}
    _write(paths["json"], _json(data))
    _write(paths["graph"], _json(graph_data))
    temporary = paths["events"].with_suffix(".jsonl.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for event in records(data.get("events")):
            stream.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    os.replace(temporary, paths["events"])
    _csv(paths["ownership"], ["asset_address", "owner_address", "role", "status", "timestamp", "logical_time", "transaction_hash", "event_id", "method", "evidence_ids", "block_reference", "raw"], ownership_rows(data))
    _csv(paths["transactions"], ["event_id", "asset_address", "event_type", "status", "verification", "timestamp", "transaction_hash", "logical_time", "action_index", "message_hash", "from_address", "to_address", "money", "fee", "marketplace", "marketplace_address", "evidence_ids", "observation_ids", "provider_event_ids", "raw"], records(data.get("events")))
    return paths


async def export_nft_pdf(html_path: Path, pdf_path: Path) -> Path:
    from app.exporters.pdf_exporter import export_pdf_report_from_html
    result = await export_pdf_report_from_html(Path(html_path), Path(pdf_path).parent, filename=Path(pdf_path).name)
    if not result.rendered:
        raise RuntimeError(f"PDF rendering unavailable ({result.error}); fallback notice saved at {result.output_path}. HTML and machine exports remain available.")
    return result.output_path
