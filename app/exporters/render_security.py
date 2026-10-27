"""Rendering guards shared by wallet and NFT dossiers."""
from __future__ import annotations

import re
import base64
from collections.abc import Iterable, Iterator
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.utils.security import safe_public_url, sanitize_observation, sanitize_url

# Local media copied by this application, never arbitrary filesystem URLs.
_LOCAL = re.compile(r"^(?:fon|logo)/[A-Za-z0-9_. -]+$")
_IMAGE_HOSTS = {"tonapi.io", "tonviewer.com", "getgems.io", "fragment.com", "ipfs.io", "gateway.pinata.cloud", "cloudflare-ipfs.com", "nftstatic.com", "i.toncdn.org", "cdn.tonapi.io", "ethplorer.io", "etherscan.io", "bscscan.com", "tronscan.org", "static.tronscan.org", "assets.coingecko.com", "coin-images.coingecko.com", "cdn.jsdelivr.net", "raw.githubusercontent.com", "ton.org"}


def safe_href(value: object) -> str:
    text = str(value or "")
    if text in {"report.json", "events.jsonl", "ownership.csv", "transactions.csv", "graph.json"}:
        return text
    if re.fullmatch(r"#[A-Za-z0-9_-]+", text):
        return text
    public = safe_public_url(text)
    return sanitize_url(public) if public else ""


def safe_image_url(value: object, *, allow_local: bool = True) -> str:
    text = str(value or "")
    if allow_local and _LOCAL.fullmatch(text):
        return text
    # Only renderer-owned SVG icons and a fixed transparent placeholder use data.
    if text.startswith("data:image/svg+xml;base64,") and len(text) < 100000:
        try:
            svg = base64.b64decode(text.split(",", 1)[1], validate=True).decode("utf-8")
            if re.search(r"<\s*(?:script|foreignObject|image)\b|\bon\w+\s*=|\b(?:href|src)\s*=|url\s*\(", svg, re.I):
                return ""
            return text if "<svg" in svg else ""
        except (ValueError, UnicodeError):
            return ""
    if text == "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==":
        return text
    if text.startswith("data:image/png;base64,") and len(text) <= 180000:
        try:
            payload = base64.b64decode(text.split(",", 1)[1], validate=True)
            if payload.startswith(b"\x89PNG\r\n\x1a\n") and len(payload) >= 24:
                return text
        except ValueError:
            pass
        return ""
    public = safe_public_url(text)
    if not public:
        return ""
    host = (urlsplit(public).hostname or "").lower().rstrip(".")
    if any(host == approved or host.endswith("." + approved) for approved in _IMAGE_HOSTS):
        return sanitize_url(public)
    return ""


def safe_graph_payload(value: object) -> object:
    # Redact the entire incoming tree once. Recursively redacting each already
    # clean subtree repeats URL parsing and secret matching for every ancestor.
    def guard(clean: object) -> object:
        if isinstance(clean, dict):
            result = {}
            for key, item in clean.items():
                if key in {"image_url", "image", "avatar_image", "fallback_url"} and isinstance(item, str):
                    result[key] = safe_image_url(item, allow_local=False)
                elif key in {"url", "external_url", "evidence_url", "explorer_url", "href"} and isinstance(item, str):
                    result[key] = safe_href(item)
                else:
                    result[key] = guard(item)
            return result
        if isinstance(clean, list):
            return [guard(item) for item in clean]
        return clean

    return guard(sanitize_observation(value))


class _RenderedGuard(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        from html import escape
        clean = []
        for key, value in attrs:
            if key == "href" and value and value != "data:,":
                value = safe_href(value)
            elif key in {"src", "data-src", "data-fallback-src", "poster"} and value:
                value = safe_image_url(value)
            clean.append(key if value is None else f'{key}="{escape(value, quote=True)}"')
        self.parts.append("<" + tag + (" " + " ".join(clean) if clean else "") + ">")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.parts[-1] = self.parts[-1][:-1] + "/>"

    def handle_endtag(self, tag: str) -> None:
        self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_entityref(self, name: str) -> None:
        self.parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.parts.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        self.parts.append("<!--" + data + "-->")

    def handle_decl(self, decl: str) -> None:
        self.parts.append("<!" + decl + ">")


def guard_rendered_html(html: str) -> str:
    guard = _RenderedGuard()
    guard.feed(html)
    guard.close()
    return "".join(guard.parts)


def guard_rendered_chunks(chunks: Iterable[str]) -> Iterator[str]:
    """Apply the same HTML parser guard without joining the entire document.

    Keep parser state across template fragments, including split attributes and
    script bodies. Drain only after feed/close: a self-closing tag handler must
    still be able to amend its most recently appended part.
    """
    guard = _RenderedGuard()
    for chunk in chunks:
        # Jinja yields Markup subclasses for autoescaped expressions. The
        # parser concatenates its pending prefix with this fragment; Markup's
        # overloaded addition would escape that already-rendered prefix.
        guard.feed(str(chunk))
        yield from guard.parts
        guard.parts.clear()
    guard.close()
    yield from guard.parts
    guard.parts.clear()
