from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Awaitable, Callable
from urllib.parse import unquote, urlsplit

from app.utils.ton_normalize import ton_canonical_address

from .models import DiscoveryCandidate, DiscoveryResult, VerificationStatus
from .providers import BudgetExceeded, Payload, ProviderError, TonAPIProvider, ToncenterProvider
from .protocol import nft_data, stack_address, ton_dns_item_index


REGISTRY_SOURCE = "https://github.com/tonkeeper/ton-assets"
# Mainnet contracts independently published by Tonkeeper's maintained asset
# registry. They are trust anchors, not inferred from an NFT's display name.
KNOWN_COLLECTIONS = {
    "domain": {"address": "EQC3dNlesgVD8YbAazcauIrXBPfiVhMMr5YYk2in0Mtsz0Bz", "name": ".ton DNS", "source": REGISTRY_SOURCE},
    "username": {"address": "EQCA14o1-VWhS2efqoh_9M1b_A9DtKTuoqfmkn83AbJzwnPi", "name": "Telegram usernames", "source": REGISTRY_SOURCE},
    "gift:lolpops": {"address": "EQC6zjid8vJNEWqcXk10XjsdDLRKbcPZzbHusuEW6FokOWIm", "name": "Lol Pops", "source": REGISTRY_SOURCE},
    "gift:instantramens": {"address": "EQBIj0uF-qIASqv6qIvcTif2wKSdt4WQc4mcoBywNp5GntuG", "name": "Instant Ramens", "source": REGISTRY_SOURCE},
    "gift:deskcalendars": {"address": "EQBMcfMAZlMUr1W3X8kdEw3fJMUAaWH4-XcmE5R5RfFIY0E2", "name": "Desk Calendars", "source": REGISTRY_SOURCE},
    "gift:icecreams": {"address": "EQBUvskEvmWdp_V6HX-2Tyfp4mFSzMzdg9TaUz6zKVz6Ov3f", "name": "Ice Creams", "source": REGISTRY_SOURCE},
    "gift:gingercookies": {"address": "EQBCe75G0AhjqC64B7H_BHP0wgfONX_x98rszmsEwndDVAjG", "name": "Ginger Cookies", "source": REGISTRY_SOURCE},
    "gift:jesterhats": {"address": "EQCBK_JBASAA5XVz1D17Pn--kQaMWm0b9wReVtsEdRO4Tgy9", "name": "Jester Hats", "source": REGISTRY_SOURCE},
}
GIFT_SLUG_ALIASES = {"lolpop": "lolpops"}  # Exact public Telegram slug (t.me/nft/LolPop-N).


@dataclass(frozen=True)
class NormalizedQuery:
    original: str
    value: str
    kind: str
    scope: str = "auto"
    public_url: str | None = None
    gift_slug: str | None = None
    gift_number: str | None = None


def normalize_nft_query(query: str) -> NormalizedQuery:
    text = query.strip()
    if not text or len(text) > 2048:
        raise ValueError("NFT query must contain 1..2048 characters")
    raw = ton_canonical_address(text)
    if raw:
        return NormalizedQuery(query, raw, "address")
    if text.startswith(("http://", "https://")) or re.match(r"^(?:www\.)?(?:t\.me|fragment\.com|getgems\.io|tonviewer\.com|tonscan\.org|gram\.org)/", text, re.I):
        parsed = urlsplit(text if "://" in text else "https://" + text)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if parsed.scheme not in {"https", "http"} or parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            raise ValueError("unsupported asset URL")
        if host not in {"t.me", "fragment.com", "getgems.io", "tonviewer.com", "tonscan.org", "gram.org"}:
            raise ValueError("unsupported asset URL host")
        parts = [unquote(p) for p in parsed.path.split("/") if p]
        public = "https://" + host + parsed.path
        if host == "gram.org":
            if len(parts) != 2 or parts[0].lower() != "address" or not ton_canonical_address(parts[1]):
                raise ValueError("gram.org URL must expose one valid TON address in /address/<address>")
            # An explorer address page can describe an NFT, collection, wallet,
            # or another contract. Resolve the type from providers/get methods.
            return NormalizedQuery(query, ton_canonical_address(parts[1]), "address", "auto", public)
        if host == "t.me" and len(parts) == 2 and parts[0].lower() == "nft":
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)-(\d+)", parts[1])
            if not match:
                raise ValueError("unsupported collectible gift identifier")
            return NormalizedQuery(query, parts[1], "gift", public_url=public,
                                   gift_slug=match[1].lower(), gift_number=match[2])
        if host == "fragment.com" and len(parts) == 2 and parts[0].lower() == "username":
            text = "@" + parts[1]
        elif host == "t.me" and len(parts) == 1:
            text = "@" + parts[0]
        else:
            addresses = [a for p in parts if (a := ton_canonical_address(p))]
            if len(addresses) == 1:
                return NormalizedQuery(query, addresses[0], "address", "collection" if "collection" in parts else "item", public)
            if len(addresses) == 2 and host == "getgems.io":
                return NormalizedQuery(query, addresses[-1], "address", "item", public)
            raise ValueError("URL does not expose a verifiable NFT contract; provide item address")
    if text.lower().endswith(".ton"):
        domain = text.lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.ton", domain):
            raise ValueError("unsupported TON domain syntax")
        return NormalizedQuery(query, domain, "domain", "item")
    if text.startswith("@") or text.lower().endswith(".t.me"):
        username = text[1:] if text.startswith("@") else text[:-5]
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", username):
            raise ValueError("unsupported Telegram username syntax")
        return NormalizedQuery(query, username.lower() + ".t.me", "username", "item")
    gift = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)-(\d+)", text)
    if gift:
        return NormalizedQuery(query, text, "gift", "item", "https://t.me/nft/" + text,
                               gift[1].lower(), gift[2])
    if re.match(r"^-?\d+:|^[EUek][Qf][A-Za-z0-9_+/=-]{35,}$", text):
        raise ValueError("invalid TON address or checksum")
    return NormalizedQuery(query, text, "name", "item")


def is_nft_query(query: str) -> bool:
    try:
        return normalize_nft_query(query).kind in {"domain", "username", "gift"} or "://" in query or query.startswith(("t.me/", "fragment.com/", "getgems.io/"))
    except ValueError:
        return False


def registry_entry(address: str | None, registry: dict | None = None) -> tuple[str, dict] | None:
    address = ton_canonical_address(address)
    if not address:
        return None
    for kind, data in (registry or KNOWN_COLLECTIONS).items():
        if ton_canonical_address(data["address"]) == address:
            return kind, data
    return None


async def discover_named_asset(query: NormalizedQuery, toncenter: ToncenterProvider,
                               tonapi: TonAPIProvider, evidence: Callable[[Payload, str, str], str],
                               *, registry: dict | None = None, max_pages: int = 8,
                               page_size: int = 100,
                               get_method: Callable[..., Awaitable[Payload | None]] | None = None) -> DiscoveryResult:
    result = DiscoveryResult(normalized_query=query.value, query_kind=query.kind)
    read_method = get_method or toncenter.get_method
    candidates: dict[str, DiscoveryCandidate] = {}
    predicted_only = False
    uniqueness_unproven = False
    if query.kind in {"domain", "username"}:
        for provider in (toncenter, tonapi):
            try:
                payload = await provider.domain(query.value)
                if provider is toncenter:
                    rows = payload.data.get("records", [])
                    for row in rows:
                        # A wallet DNS record is not an item address.
                        if str(row.get("domain", "")).lower() != query.value:
                            continue
                        address = ton_canonical_address(row.get("nft_item_address"))
                        if address:
                            eid = evidence(payload, "exact_domain_to_nft", "Indexer exact domain record identifies NFT item; wallet DNS is separate")
                            previous = candidates.get(address)
                            if previous:
                                previous.evidence_ids.append(eid)
                            else:
                                candidates[address] = DiscoveryCandidate(address=address, reason="exact indexed domain match", evidence_ids=[eid])
                else:
                    row = payload.data.get("item") or {}
                    if str(payload.data.get("name", "")).lower() == query.value:
                        address = ton_canonical_address(row.get("address"))
                        if address:
                            eid = evidence(payload, "exact_domain_to_nft", "TonAPI DomainInfo item; not resolved wallet address")
                            if address in candidates:
                                candidates[address].evidence_ids.append(eid)
                            else:
                                candidates[address] = DiscoveryCandidate(address=address,
                                    collection_address=ton_canonical_address((row.get("collection") or {}).get("address")),
                                    reason="exact provider DomainInfo item", evidence_ids=[eid])
            except ProviderError as exc:
                result.warnings.append(str(exc))
            except BudgetExceeded:
                raise
        if not candidates:
            result.status = "unresolved"
            result.warnings.append("No indexed collectible found. This does not establish nonexistence or prove this is an ordinary username.")
            if query.kind == "domain":
                try:
                    index = ton_dns_item_index(query.value)
                    collection = ton_canonical_address((registry or KNOWN_COLLECTIONS)["domain"]["address"])
                    derived = await read_method(collection, "get_nft_address_by_index", [["num", str(index)]])
                    if derived is None:
                        raise ValueError("DNS collection getter unavailable")
                    address = stack_address(derived.data["stack"][0])
                    eid = evidence(derived, "specialized_dns_candidate", "Official dns-contract slice_hash(label) index resolves a predicted address; activation must be verified")
                    if address:
                        candidate = DiscoveryCandidate(address=address, collection_address=collection, index=index,
                            reason="Official .ton collection deterministic cell-hash index; not proof of deployment", evidence_ids=[eid])
                        candidates[address] = candidate
                        predicted_only = True
                        try:
                            getter = await read_method(address, "get_nft_data")
                            if getter is None:
                                raise ValueError("NFT getter unavailable")
                            state = nft_data(getter.data)
                            if state["initialized"] and state["collection_address"] == collection and state["index"] == index:
                                candidate.verification = VerificationStatus.VERIFIED_ONCHAIN
                                predicted_only = False
                            else:
                                result.warnings.append("Predicted DNS item is not initialized or does not match official collection/index")
                        except (ProviderError, ValueError, IndexError):
                            result.warnings.append("Predicted DNS item is not verified active; no current owner or NFT existence asserted")
                except (ValueError, ProviderError, KeyError, IndexError):
                    result.warnings.append("Specialized .ton deterministic resolution unavailable; raw observations retained")
    elif query.kind == "gift":
        registry = registry or KNOWN_COLLECTIONS
        entry = registry.get("gift:" + (query.gift_slug or ""))
        if not entry:
            entry = registry.get("gift:" + GIFT_SLUG_ALIASES.get(query.gift_slug or "", ""))
        if not entry:
            result.status = "unsupported"
            result.warnings.append("Gift collection is not in the verified registry. Provide its NFT item address; no arbitrary name match is selected.")
            return result
        collection = ton_canonical_address(entry["address"])
        exact_name = entry["name"] + " #" + (query.gift_number or "")
        # Search only inside a trusted exact collection; every match is still
        # checked against get_nft_address_by_index by the investigation service.
        exhausted = False
        stop_reason = "page budget"
        for page in range(max_pages):
            try:
                payload = await tonapi.items(collection, scope="collection", offset=page * page_size, limit=page_size)
            except ProviderError as exc:
                result.warnings.append(str(exc))
                stop_reason = "provider failure"
                break
            rows = payload.data.get("nft_items", [])
            for row in rows:
                meta = row.get("metadata") or {}
                urls = {str(meta.get(k, "")).rstrip("/").lower() for k in ("external_url", "external_link", "url")}
                if str(meta.get("name", "")).casefold() != exact_name.casefold() and (query.public_url or "").lower() not in urls:
                    continue
                address = ton_canonical_address(row.get("address"))
                if address and ton_canonical_address((row.get("collection") or {}).get("address")) == collection:
                    eid = evidence(payload, "exact_collectible_identifier", "Exact collectible number/name or public gift URL inside trusted collection")
                    candidates[address] = DiscoveryCandidate(address=address, collection_address=collection,
                            reason="exact collectible identifier in trusted collection", evidence_ids=[eid])
            if len(rows) < page_size:
                exhausted = True
                break
        if not exhausted:
            uniqueness_unproven = True
            result.warnings.append(f"Gift name search stopped at {stop_reason}; more exact candidates may exist")
        if not candidates:
            result.status = "unresolved"
    else:
        result.status = "unsupported"
        result.warnings.append("Global NFT name search has no trustworthy public exact index. Supply domain, collectible username, gift URL, or contract address.")
    result.candidates = list(candidates.values())
    if candidates:
        if len(candidates) == 1 and (predicted_only or uniqueness_unproven):
            result.status = "unresolved"
        else:
            result.status = "resolved" if len(candidates) == 1 else "ambiguous"
    return result
