"""Redaction-equivalent per-call memoization; no provider/network access."""
from datetime import datetime, timezone
from decimal import Decimal
import json
import re
import sys
import unittest
from unittest.mock import patch

from app.utils import security

KEYS = re.compile(r'(?:api[_-]?key|authorization|access[_-]?token|auth[_-]?token|authClientToken|password|passwd|private[_-]?key|secret|seed[_-]?phrase|mnemonic)', re.I)
TEXT = re.compile(r'''(?i)(\b(?:api[_-]?key|access[_-]?token|authorization|authClientToken|password|secret)\s*[=:]\s*)([^\s&,;"']+)''')


def reference(value):
    """Exact sanitizer before the per-call memo change, retained for parity."""
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if KEYS.search(str(k)) else reference(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [reference(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', value)
        value = TEXT.sub(r'\1[REDACTED]', value)
        return re.sub(r'''https?://[^\s<>"']+''', lambda match: security.sanitize_url(match.group()), value)
    return value


class CallMemoTests(unittest.TestCase):
    def test_recent_strings_replace_old_entries_and_repeat_secret_redaction_after_eviction(self):
        first = 'password=first-secret'
        second = 'https://user:password@example.com/path?password=second-secret'
        third = 'Bearer third-secret'
        source = [first, second, first, third, first, second]
        regex = security._SECRET_TEXT
        class CountingRegex:
            calls = 0
            def sub(self, *args, **kwargs):
                self.calls += 1
                return regex.sub(*args, **kwargs)
        counted = CountingRegex()
        with patch.object(security, '_TEXT_CACHE_ENTRIES', 2), patch.object(security, '_SECRET_TEXT', counted):
            result = security.sanitize_observation(source)
        self.assertEqual(result, reference(source))
        self.assertEqual(counted.calls, 4)
        self.assertTrue(all('first-secret' not in value and 'second-secret' not in value and 'third-secret' not in value for value in result))

    def test_exact_nested_reference_equivalence_and_types(self):
        now, number = datetime.now(timezone.utc), Decimal('0.000000000000000001')
        value = {'root': [{'apiKey': 'do-not-disclose', 'public': 'Bearer foo.bar== API_KEY=foo',
            'url': 'https://user:pass@example.com:443/tx?a=1&access_token=foo#hash',
            'unicode': 'Привет 👋', 'empty': '', 'ordinary': 'plain'}] * 3,
            14: (None, True, False, 2**256, number, now), 'private-key': {'nested': 'hidden'},
            'malformed': 'https://example.com:bad/tx', 'bytes': b'unchanged'}
        result = security.sanitize_observation(value)
        self.assertEqual(result, reference(value))
        self.assertEqual(json.dumps(result, default=str, ensure_ascii=False), json.dumps(reference(value), default=str, ensure_ascii=False))
        self.assertIs(result['14'][4], number)
        self.assertIs(result['14'][5], now)
        self.assertIsInstance(result['14'], list)
        self.assertEqual(value['root'][0]['apiKey'], 'do-not-disclose')

    def test_deep_tail_and_long_repeated_string_still_redacted(self):
        value = {'url': 'x' * 5000 + ' https://user:pass@example.com/x?password=tail', 'seed_phrase': 'deep-secret'}
        for _ in range(90):
            value = {'prev': value, 'ordinary': 'repeated'}
        self.assertEqual(security.sanitize_observation(value), reference(value))
        self.assertNotIn('deep-secret', str(security.portable_observation(value)))

    def test_caches_are_bounded_and_cleared_after_return(self):
        value = [{f'key{i}': f'public-{i}'} for i in range(3000)]
        value += [{'authorization': 'secret-after-key-limit', 'long': 'z' * 4097}]
        sizes, caches = [0, 0], {}

        def profile(frame, event, arg):
            if frame.f_code.co_filename == security.__file__ and frame.f_code.co_name == 'visit':
                for index, name in enumerate(('key_checks', 'text_results')):
                    cache = frame.f_locals.get(name)
                    if cache is not None:
                        sizes[index] = max(sizes[index], len(cache))
                        caches[name] = cache

        old_profile = sys.getprofile()
        try:
            sys.setprofile(profile)
            result = security.sanitize_observation(value)
        finally:
            sys.setprofile(old_profile)
        self.assertEqual(result, reference(value))
        self.assertEqual(sizes, [512, 2048])
        self.assertEqual(caches, {'key_checks': {}, 'text_results': {}})

    def test_caches_clear_on_exception_and_do_not_leak_across_calls(self):
        caches = {}
        class BrokenKey:
            def __str__(self):
                raise ValueError('intentional key failure')

        def profile(frame, event, arg):
            if frame.f_code.co_filename == security.__file__ and frame.f_code.co_name == 'visit':
                for name in ('key_checks', 'text_results'):
                    if name in frame.f_locals:
                        caches[name] = frame.f_locals[name]

        old_profile = sys.getprofile()
        try:
            sys.setprofile(profile)
            with self.assertRaisesRegex(ValueError, 'intentional key failure'):
                security.sanitize_observation({'public': 'password=hidden', BrokenKey(): 'value'})
        finally:
            sys.setprofile(old_profile)
        self.assertEqual(caches, {'key_checks': {}, 'text_results': {}})
        source = {'a': [{'password': 'first', 'safe': 'same'}]}
        first = security.sanitize_observation(source)
        first['a'][0]['safe'] = 'mutated output'
        source['a'][0]['password'] = 'second'
        self.assertEqual(security.sanitize_observation(source), {'a': [{'password': '[REDACTED]', 'safe': 'same'}]})


if __name__ == '__main__':
    unittest.main()
