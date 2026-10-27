from __future__ import annotations

import re
from typing import Iterable

from selectolax.parser import HTMLParser


def normalize_html(html: str | bytes | None) -> str:
    if html is None:
        return ""
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="ignore")
    html = html.replace("\x00", "")
    return re.sub(r"[\t\r\f]+", " ", html)


def text(node) -> str:
    if node is None:
        return ""
    try:
        return re.sub(r"\s+", " ", node.text(strip=True)).strip()
    except Exception:
        return ""


def parse_html(html: str) -> HTMLParser:
    return HTMLParser(normalize_html(html))


def first(doc, selectors: Iterable[str]):
    for selector in selectors:
        try:
            node = doc.css_first(selector)
        except Exception:
            node = None
        if node is not None:
            return node
    return None


def first_text(doc, selectors: Iterable[str]) -> str:
    for selector in selectors:
        value = text(first(doc, [selector]))
        if value:
            return value
    return ""


def attr(node, name: str) -> str:
    if node is None:
        return ""
    try:
        return (node.attributes.get(name) or "").strip()
    except Exception:
        return ""


def meta_content(doc, names: Iterable[str]) -> str:
    for name in names:
        selectors = (
            f'meta[property="{name}"]',
            f'meta[name="{name}"]',
            f'meta[itemprop="{name}"]',
        )
        node = first(doc, selectors)
        value = attr(node, "content")
        if value:
            return re.sub(r"\s+", " ", value).strip()
    return ""


def all_texts(doc, selectors: Iterable[str], limit: int = 50) -> list[str]:
    values = []
    for selector in selectors:
        try:
            nodes = doc.css(selector)
        except Exception:
            nodes = []
        for node in nodes[:limit]:
            value = text(node)
            if value and value not in values:
                values.append(value)
    return values[:limit]


def hrefs(doc, selectors: Iterable[str], limit: int = 80) -> list[str]:
    values = []
    for selector in selectors:
        try:
            nodes = doc.css(selector)
        except Exception:
            nodes = []
        for node in nodes[:limit]:
            value = attr(node, "href")
            if value and value not in values:
                values.append(value)
    return values[:limit]

