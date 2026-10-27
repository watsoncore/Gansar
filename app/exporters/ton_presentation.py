"""Per-report TON address presentation; canonical analysis data stays intact."""
from __future__ import annotations

import base64
import binascii
import re
from collections import OrderedDict
from urllib.parse import unquote, urlsplit, urlunsplit

from app.utils.ton_normalize import parse_ton_address
from app.exporters.render_security import safe_href

_ADDRESS = re.compile(r"(?<![A-Za-z0-9_])(?:(?:wallet:ton:|ton:)?-?\d+:[0-9A-Fa-f]{64}|[A-Za-z0-9_+/-]{48})(?![A-Za-z0-9_])")
_EXPLORERS = {'tonviewer.com', 'tonscan.org', 'tonscan.com', 'ton.cx', 'gram.org', 'getgems.io', 'tonapi.io'}


def _plain(value):
    text = str(value or '')
    for prefix in ('wallet:ton:', 'ton:'):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def friendly_address(value, *, bounceable=None, test_only=None):
    parsed = parse_ton_address(_plain(value))
    if not parsed or not -128 <= parsed['workchain'] <= 127:
        return None
    # Representation policy for raw-only mainnet observations: non-bounceable.
    # These flags express a presentation choice, never a wallet/owner claim.
    bounceable = parsed['bounceable'] if bounceable is None and parsed['bounceable'] is not None else bool(bounceable)
    test_only = parsed['test_only'] if test_only is None and parsed['test_only'] is not None else bool(test_only)
    body = bytes([(0x11 if bounceable else 0x51) | (0x80 if test_only else 0), parsed['workchain'] & 255]) + bytes.fromhex(parsed['hash'])
    return base64.urlsafe_b64encode(body + binascii.crc_hqx(body, 0).to_bytes(2, 'big')).decode('ascii')


class TonPresentation:
    def __init__(self, report, graph=None):
        self.mapping = {}
        self._priorities = {}
        self._aliases = {}
        resolution = getattr(report, 'input_resolution', None) or {}
        for value in (resolution.get('query'), resolution.get('original_query'), getattr(report, 'target_address', None)):
            self._register_text(value, 300)
        seen = set()
        text_seen = OrderedDict()
        key_seen = OrderedDict()
        def first_visit(text, cache):
            # Repeated immutable schema strings have identical presentation.
            # Bound this per-construction cache; never retain report text globally.
            if len(text) > 16384:
                return True
            if text in cache:
                cache.move_to_end(text)
                return False
            if len(cache) >= 8192:
                cache.popitem(last=False)
            cache[text] = True
            return True
        stack = [report, graph or {}]
        while stack:
            value = stack.pop()
            if isinstance(value, str):
                if first_visit(value, text_seen):
                    self._register_text(value, 100)
            elif isinstance(value, (dict, list, tuple)) or hasattr(type(value), 'model_fields'):
                if id(value) in seen:
                    continue
                seen.add(id(value))
                if isinstance(value, dict):
                    stack.extend(value.values())
                    # Qualified canonical address keys can appear without a
                    # duplicate address property in compact source projections.
                    for key in value:
                        if isinstance(key, str) and first_visit(key, key_seen):
                            self._register(key, 0)
                elif isinstance(value, (list, tuple)):
                    stack.extend(value)
                else:
                    stack.extend(value.__dict__.values())
        for raw, aliases in self._aliases.items():
            for alias in aliases:
                self.mapping[alias] = self.mapping[raw]

    def _register_text(self, value, priority):
        if not isinstance(value, str):
            return
        if _ADDRESS.fullmatch(value) and parse_ton_address(_plain(value)):
            self._register(value, priority)
        elif len(value) < 16384:
            for match in _ADDRESS.finditer(value):
                self._register(match.group(), priority)

    def _register(self, value, priority):
        if not _ADDRESS.fullmatch(value):
            return
        parsed = parse_ton_address(_plain(value))
        if not parsed:
            return
        raw = parsed['raw']
        self._aliases.setdefault(raw, set()).add(value)
        explicit = parsed['bounceable'] is not None
        priority = priority if explicit else 0
        if raw not in self.mapping or priority > self._priorities[raw]:
            result = friendly_address(value)
            self.mapping[raw] = result or 'UNKNOWN (friendly workchain unsupported)'
            self._priorities[raw] = priority

    def address(self, value):
        if value is None:
            return ''
        parsed = parse_ton_address(_plain(value))
        return self.mapping.get(parsed['raw'], friendly_address(value) or 'UNKNOWN') if parsed else str(value)

    def text(self, value):
        if value is None:
            return ''
        text = str(value)
        if parse_ton_address(_plain(text)):
            return self.address(text)
        return _ADDRESS.sub(lambda match: self.address(match.group()), text)

    def short(self, value, head=10, tail=7):
        text = self.text(value)
        return text[:head] + '…' + text[-tail:] if len(text) > head + tail + 3 else text

    def label(self, value, prior=''):
        return self.short(value) if parse_ton_address(_plain(value)) else prior or value or ''

    def href(self, value):
        original = safe_href(value)
        if not original:
            return ''
        parsed = urlsplit(original)
        host = (parsed.hostname or '').lower().removeprefix('www.')
        # Do not rewrite provider API paths, publications, TX hashes or query
        # parameters. Only a full address path segment of a known explorer.
        if host not in _EXPLORERS or parsed.path.startswith('/v2/'):
            return original
        parts = parsed.path.split('/')
        parts = [self.address(unquote(part)) if parse_ton_address(unquote(part)) else part for part in parts]
        return urlunsplit((parsed.scheme, parsed.netloc, '/'.join(parts), parsed.query, parsed.fragment))
