"""Evidence-bearing directed relationships for TON NFT investigations.

No graph traversal invents ownership. Every transition is tied to an event and
the full graph remains available even when the dossier displays a small page.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from app.utils.security import safe_public_url, sanitize_observation
from app.utils.ton_normalize import ton_canonical_address


def record(value: Any) -> dict:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return dict(value) if isinstance(value, dict) else {}


def records(value: Any) -> list[dict]:
    if isinstance(value, dict):
        value = value.values()
    return [record(item) for item in (value or [])]


def _key(value: Any) -> str:
    text = str(value or "")
    return ton_canonical_address(text) or text


def _id(kind: str, value: Any) -> str:
    return f"{kind}:ton:{_key(value)}"


def _sanitize_graph(value: Any) -> Any:
    """Apply the shared sanitizer once per distinct string/key in this graph.

    Graph provenance repeats the same URLs, addresses and metadata many times.
    Cache only immutable sanitized strings, while copying each container as the
    shared sanitizer does. No cross-request cache or redaction rule is added.
    """
    strings: dict[str, str] = {}
    secret_keys: dict[str, bool] = {}
    def clean(item: Any) -> Any:
        if isinstance(item, dict):
            result = {}
            for key, nested in item.items():
                key = str(key)
                if key not in secret_keys:
                    secret_keys[key] = sanitize_observation({key: None})[key] == "[REDACTED]"
                result[key] = "[REDACTED]" if secret_keys[key] else clean(nested)
            return result
        if isinstance(item, (list, tuple)):
            return [clean(nested) for nested in item]
        if isinstance(item, str):
            if item not in strings:
                strings[item] = sanitize_observation(item)
            return strings[item]
        return item
    return clean(value)


def build_nft_graph(report: Any) -> dict:
    data = record(report)
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    key_cache: dict[str, str] = {}
    url_cache: dict[str, str | None] = {}
    contract_nodes: dict[str, str] = {}
    def address_key(value: Any) -> str:
        text = str(value or "")
        if text not in key_cache:
            key_cache[text] = _key(text)
        return key_cache[text]
    def public_url(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        if value not in url_cache:
            url_cache[value] = safe_public_url(value)
        return url_cache[value]
    evidence_by_id = {str(e.get("evidence_id") or e.get("id")): e for e in records(data.get("evidence"))}

    def node(kind: str, value: Any, label: Any = None, **extra: Any) -> str:
        if not value:
            return ""
        node_id = f"{kind}:ton:{address_key(value)}"
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, "chain": "ton", "label": str(label or value), "address": str(value), **extra})
        if kind in {"marketplace", "smart_contract"}:
            contract_nodes.setdefault(address_key(value), node_id)
        return node_id

    def relation(src: str, dst: str, kind: str, fact: dict, explanation: str, **extra: Any) -> None:
        if not src or not dst:
            return
        refs = list(dict.fromkeys(str(x) for x in (fact.get("evidence_ids") or fact.get("evidence_refs") or []) if x))
        identity = str(fact.get("event_id") or fact.get("listing_id") or fact.get("assertion_id") or fact.get("id") or "")
        edge_id = "nftedge:" + hashlib.sha256((src + "|" + dst + "|" + kind + "|" + identity + "|" + "|".join(refs)).encode()).hexdigest()[:32]
        ev = [evidence_by_id[r] for r in refs if r in evidence_by_id]
        source = fact.get("source") or ", ".join(dict.fromkeys(str(e.get("source") or "") for e in ev))
        url = public_url(fact.get("evidence_url") or fact.get("url")) or next((public_url(e.get("url") or e.get("evidence_url")) for e in ev if public_url(e.get("url") or e.get("evidence_url"))), "")
        edges[edge_id] = {"id": edge_id, "from": src, "to": dst, "type": kind, "source": source, "evidence_ids": refs,
            "observation_ids": fact.get("observation_ids") or [], "evidence_url": url, "tx_hash": fact.get("transaction_hash") or fact.get("tx_hash") or "", "lt": fact.get("logical_time") or fact.get("lt"),
            "timestamp": fact.get("timestamp") or fact.get("observed_at"), "confirmation": fact.get("verification") or fact.get("confirmation") or fact.get("status") or "unverified",
            "confidence": fact.get("confidence") or next((e.get("confidence") for e in ev if e.get("confidence")), "unknown"), "explanation": explanation, "event_id": identity, **extra}
        for ref in refs:
            evidence = evidence_by_id.get(ref, {})
            evnode = node("evidence_source", ref, evidence.get("source") or ref, evidence_url=public_url(evidence.get("url") or evidence.get("evidence_url")) or "", upstream=evidence.get("upstream"))
            verify_id = "verified:" + edge_id + ":" + ref
            edges[verify_id] = {"id": verify_id, "from": dst, "to": evnode, "type": "VERIFIED_BY", "source": evidence.get("source") or source,
                "evidence_ids": [ref], "evidence_url": nodes[evnode]["evidence_url"], "confirmation": evidence.get("status") or evidence.get("confirmation") or "observation",
                "confidence": evidence.get("confidence") or "unknown", "explanation": "Observation supporting the relationship", "relationship_id": edge_id,
                "observation_ids": [evidence["observation_id"]] if evidence.get("observation_id") else [], "timestamp": evidence.get("collected_at"),
                "tx_hash": evidence.get("transaction_hash") or "", "lt": evidence.get("logical_time")}

    assets = records(data.get("assets"))
    asset_by_address = {address_key(a.get("address")): a for a in assets}
    collections = records(data.get("collections"))
    collection_by_address = {address_key(c.get("address")): c for c in collections}
    first_collection_by_address = {}
    for collection in collections:
        first_collection_by_address.setdefault(address_key(collection.get("address")), collection)

    def account_node(address: Any) -> str:
        """NFTs can be owned by contracts; an address is not necessarily a wallet."""
        key = address_key(address)
        known_asset = asset_by_address.get(key)
        if known_asset:
            kind = {"domain": "ton_domain_nft", "username": "telegram_collectible_username", "gift": "telegram_gift"}.get(known_asset.get("kind"), "nft_item")
            return node(kind, address, known_asset.get("name"), raw=known_asset)
        known_collection = collection_by_address.get(key)
        if known_collection:
            return node("nft_collection", address, known_collection.get("name"), raw=known_collection)
        if key in contract_nodes:
            return contract_nodes[key]
        # Explicit verified account classification can be attached by collectors.
        account = record(data.get("account_classifications", {}).get(key))
        is_wallet = account.get("wallet_verified") is True
        return node("ton_wallet" if is_wallet else "ton_address", address, address, account_type="verified_wallet" if is_wallet else "owner_or_participant_account_unknown", classification_evidence_ids=account.get("evidence_ids") or [])

    events = records(data.get("events"))
    events_by_asset: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        events_by_asset[address_key(event.get("asset_address"))].append(event)
    for collection in collections:
        node("nft_collection", collection.get("address") or collection.get("collection_address"), collection.get("name"), raw=collection)
    for asset in assets:
        address = asset.get("address") or asset.get("item_address") or asset.get("asset_id")
        kind = {"domain": "ton_domain_nft", "username": "telegram_collectible_username", "gift": "telegram_gift"}.get(asset.get("kind") or asset.get("type"), "nft_item")
        item = node(kind, address, asset.get("name") or asset.get("title"), raw=asset)
        if not item:
            continue
        collection_data = record(asset.get("collection"))
        collection_addr = asset.get("collection_address") or collection_data.get("address")
        if collection_addr:
            collection = node("nft_collection", collection_addr, asset.get("collection_name"))
            fact = {**asset, "id": str(address) + ":collection", "status": asset.get("collection_status")}
            relation(item, collection, "BELONGS_TO_COLLECTION", fact, "Collection membership observation; see on-chain verification status", verified=asset.get("collection_status") == "verified_onchain")
            known_collection = first_collection_by_address.get(address_key(collection_addr), {})
            if known_collection.get("known_registry_kind") and asset.get("collection_status") == "verified_onchain":
                relation(item, collection, "REGISTERED_IN", fact, "Verified membership in a publicly documented collectible registry collection", registry_kind=known_collection["known_registry_kind"])
        assertion = next((a for a in reversed(records(asset.get("ownership"))) if a.get("owner_address") == asset.get("current_owner")), {})
        owner = asset.get("current_owner")
        verified = asset.get("current_owner_status") == "verified_onchain" and assertion.get("status") == "verified_onchain"
        if owner:
            owner_node = account_node(owner)
            relation(owner_node, item, "OWNS" if verified else "ASSOCIATED_WITH", assertion or asset, "Current ownership assertion verified on chain" if verified else "Unverified owner observation; not confirmed ownership", current=True)
        for listing in records(asset.get("listings")):
            if listing.get("status") not in {"active", "listed", "open"}:
                continue
            market = node("marketplace", listing.get("marketplace_address") or listing.get("sale_contract") or listing.get("marketplace") or listing.get("marketplace_name"))
            relation(item, market, "LISTED_ON", listing, "Active listing observation; not a completed sale", price=listing.get("price"), currency=listing.get("currency"))
            if listing.get("sale_contract"):
                contract = node("smart_contract", listing["sale_contract"])
                relation(item, contract, "INTERACTED_WITH", listing, "Sale/listing contract explicitly reported by the source")
        collectible = record(asset.get("telegram") or asset.get("collectible"))
        if collectible.get("assigned_entity"):
            association = {"id": str(address) + ":assignment", "status": collectible.get("assignment_status"), "evidence_ids": collectible.get("assignment_evidence_ids") or []}
            public = node("telegram_public_entity", collectible["assigned_entity"])
            relation(item, public, "ASSOCIATED_WITH", association, "Public assignment/display association; does not establish wallet controller identity")
        for reference in collectible.get("metadata_associations") or []:
            association = {"id": str(address) + ":metadata:" + reference, "status": "unverified", "evidence_ids": asset.get("evidence_ids") or []}
            public = node("telegram_public_entity", reference)
            relation(item, public, "ASSOCIATED_WITH", association, "Unverified public metadata association; neither assignment nor personal identity is established")

    asset_nodes = {address_key(n["address"]): n["id"] for n in nodes.values() if n["kind"] in {"nft_item", "ton_domain_nft", "telegram_collectible_username", "telegram_gift"}}
    for event in events:
        address = event.get("item_address") or event.get("asset_address") or event.get("nft_address")
        item = asset_nodes.get(address_key(address)) or node("nft_item", address)
        event_id = event.get("event_id") or event.get("id")
        transaction = node("transaction", event_id or event.get("transaction_hash"), event.get("transaction_hash") or event_id, raw=event)
        relation(transaction, item, "INTERACTED_WITH", event, "NFT action in transaction")
        success = event.get("status") == "success"
        kind = str(event.get("event_type") or event.get("kind") or event.get("type") or "unknown").lower()
        sender = event.get("from_address") or event.get("seller_address") or event.get("seller")
        receiver = event.get("to_address") or event.get("buyer_address") or event.get("buyer")
        if not success:
            continue
        if sender and receiver and kind in {"transfer", "ownership_change", "sale", "purchase", "mint"}:
            src = account_node(sender); dst = account_node(receiver)
            verified_transition = event.get("verification") == "verified_onchain"
            relation(src, dst, "TRANSFERRED" if verified_transition else "NFT_TRANSITION_OBSERVATION", event,
                "Verified directed NFT ownership transition" if verified_transition else "Provider-reported transition observation; excluded from verified ownership tracing", item_address=address)
            relation(src, item, "PREVIOUSLY_OWNED", event, "Sender in historical NFT transition; original ownership is not inferred")
            confirmed_sale = kind in {"sale", "purchase"} and event.get("verification") in {"verified_onchain", "provider_reported"}
            if confirmed_sale:
                relation(src, item, "SOLD", event, "Completed sale asserted by explicit sale evidence", price=event.get("money"), currency=event.get("currency"))
                relation(dst, item, "PURCHASED", event, "Buyer in confirmed completed sale", price=event.get("money"), currency=event.get("currency"))
        marketplace = event.get("marketplace_address") or event.get("marketplace") or event.get("marketplace_name")
        if marketplace:
            market = node("marketplace", marketplace)
            relation(item, market, "INTERACTED_WITH", event, "Historical marketplace interaction; not proof of a current listing")
    timelines = []
    coverage_rows = records(data.get("coverage"))
    for asset in assets:
        address = asset.get("address")
        transitions = [e for e in events_by_asset[address_key(address)] if e.get("status") == "success" and e.get("verification") == "verified_onchain" and e.get("event_type") in {"transfer", "sale", "mint"} and e.get("from_address") and e.get("to_address")]
        transitions.sort(key=lambda e: (e.get("logical_time") is None, int(e.get("logical_time") or 0), int(e.get("action_index") or 0), str(e.get("timestamp") or ""), e.get("event_id") or ""))
        segments = []
        previous = None
        for e in transitions:
            continuity = "first_observed" if previous is None else "continuous" if address_key(previous.get("to_address")) == address_key(e.get("from_address")) else "gap_or_conflict"
            segments.append({"event_id": e.get("event_id"), "from_address": e.get("from_address"), "to_address": e.get("to_address"), "timestamp": e.get("timestamp"), "logical_time": e.get("logical_time"), "action_index": e.get("action_index"), "transaction_hash": e.get("transaction_hash"), "verification": e.get("verification"), "evidence_ids": e.get("evidence_ids") or [], "continuity": continuity})
            previous = e
        observations = [{"event_id": e.get("event_id"), "from_address": e.get("from_address"), "to_address": e.get("to_address"), "logical_time": e.get("logical_time"), "timestamp": e.get("timestamp"), "verification": e.get("verification"), "evidence_ids": e.get("evidence_ids") or []} for e in events_by_asset[address_key(address)] if e.get("status") == "success" and e.get("verification") != "verified_onchain" and e.get("event_type") in {"transfer", "sale", "mint"}]
        # Keep provider coverage order exactly, while avoiding repeated record
        # copies of the same stream metadata for every NFT.
        coverage = [row for row in coverage_rows if "history" in str(row.get("scope") or "") or address in str(row.get("scope") or "")]
        timelines.append({"asset_address": address, "segments": segments, "unverified_transition_observations": observations, "first_owner_status": "first_observed_only", "coverage": coverage})
    return _sanitize_graph({"schema_version": "1.0", "directed": True, "nodes": list(nodes.values()), "edges": list(edges.values()), "ownership_timelines": timelines,
        "stats": {"nodes": len(nodes), "edges": len(edges), "events": len(events)}, "coverage": data.get("coverage") or {},
        "tracing": "Each directed TRANSFERRED edge belongs to one NFT event; no common-owner or causal funding attribution is inferred."})
