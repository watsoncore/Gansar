"""Offline replay of one recorded public response; not a live API test."""
import base64
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import httpx

from app.models.report import AddressReport
from app.sources.ton_toncenter import TonCenterSource

ADDRESS = '0:455024810caef5d106159c1a1c7decc336f3bbc7198bac97409cb13cc1c88c17'
RECORDED = Path(__file__).parent / 'fixtures' / 'toncenter_invalid_utf8_20261017.bin'


def response(content):
    return httpx.Response(200, content=content, request=httpx.Request('GET', 'https://toncenter.com/api/v2/getTransactions'))


class BinaryPayloadParserTests(unittest.TestCase):
    def test_recorded_live_bytes_preserve_all_accounts_and_binary_exactly(self):
        raw = RECORDED.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'b63c93d93a2cbb86fe286bcf36360c71a41b6c4b9a1857ae4039ab56d5f79382')
        with self.assertRaises(UnicodeDecodeError):
            response(raw).json()
        source = TonCenterSource(1)
        data = source._decode_page(response(raw))
        original = json.loads(raw.decode('utf-8', errors='surrogateescape'))
        self.assertEqual(len(data['result']), 100)
        self.assertEqual(len(data['_gansar_binary_payloads']['fields']), 28)
        for path in data['_gansar_binary_payloads']['fields']:
            before, after = original, data
            for key in path:
                before, after = before[key], after[key]
            self.assertEqual(base64.b64decode(after['data']), before.encode('utf-8', errors='surrogateescape'))
            self.assertTrue(after['binary_payload'])
        out = AddressReport(target_address=ADDRESS)
        source._parse_transactions(ADDRESS, out, data['result'])
        input_rows = [row for row in out.transactions if row.raw.get('message_index') == 'in']
        self.assertEqual(len(input_rows), 100)
        self.assertEqual({row.tx_hash for row in input_rows}, {row['transaction_id']['hash'] for row in original['result']})
        self.assertTrue(any(row.raw['transaction']['in_msg']['message'].get('binary_payload')
            for row in input_rows if isinstance(row.raw['transaction']['in_msg'].get('message'), dict)))
        self.assertFalse(any(row.raw.get('comment') for row in input_rows
            if row.raw['transaction']['in_msg'].get('msg_data', {}).get('@type') == 'msg.dataEncryptedText'))
        self.assertEqual(out.errors, [])

    def test_valid_unicode_is_unchanged_and_text_comment_is_decoded(self):
        original = {'result': [{'in_msg': {'message': 'Привет 👋',
            'msg_data': {'@type': 'msg.dataText', 'text': base64.b64encode('Привет 👋'.encode()).decode()}}}]}
        source = TonCenterSource(1)
        parsed = source._decode_page(response(json.dumps(original, ensure_ascii=False).encode()))
        self.assertEqual(parsed, original)
        self.assertEqual(source._message_text(parsed['result'][0]['in_msg']), 'Привет 👋')
        self.assertIsNone(source._message_text({'msg_data': {'@type': 'msg.dataText', 'text': '/w=='}}))

    def test_invalid_identifiers_unknown_fields_and_syntax_fail(self):
        source = TonCenterSource(1)
        for raw in (b'{"result":[{"hash":"\xff"}]}', b'{"result":[{"in_msg":{"other":"\xff"}}]}',
                b'{"result":[{"in_msg":{"message":"\xff"}}]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                source._decode_page(response(raw))


class BinaryPayloadFetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_replay_keeps_page_cursor_warning_and_later_error(self):
        raw = RECORDED.read_bytes()
        requests = []

        class Client:
            async def get(self, url, *, params, headers):
                requests.append(params)
                return response(raw if len(requests) == 1 else b'{"result":[{"hash":"\xff"}]}')

        @asynccontextmanager
        async def shared(*args, **kwargs):
            yield Client()

        source = TonCenterSource(1)
        with patch('app.sources.ton_toncenter.shared_async_client', shared):
            report = await source.fetch(ADDRESS)
        self.assertEqual(len([row for row in report.transactions if row.raw.get('message_index') == 'in']), 100)
        state = report.collection_audit['streams']['toncenter']['account_transactions']
        self.assertEqual(state['pages'], 1)
        self.assertEqual(state['raw_records'], 100)
        self.assertEqual(requests[1]['lt'], state['next_cursor']['lt'])
        self.assertEqual(requests[1]['hash'], state['next_cursor']['hash'])
        self.assertFalse(state['exhausted'])
        self.assertEqual(state['stop_reason'], 'provider_error')
        self.assertTrue(any('binary_payload_warning: 28' in row for row in report.errors))
        self.assertTrue(any('Invalid UTF-8 outside a message payload' in row for row in report.errors))


if __name__ == '__main__':
    unittest.main()
