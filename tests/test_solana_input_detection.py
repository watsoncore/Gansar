"""Regression for a real public counterparty rejected by prefix heuristics."""
import unittest

from app.utils.detect import (detect_candidates, is_bitcoin_address,
                              is_solana_address, looks_like_solana_address)


class SolanaInputDetectionTests(unittest.TestCase):
    def test_real_solana_key_starting_with_one(self):
        address = "13Ma7KdfbBrF8NmDBnVTkwny7tjrZxYHCfn6a3FFbRUa"
        self.assertEqual(len(address), 44)
        self.assertTrue(looks_like_solana_address(address))
        self.assertTrue(is_solana_address(address))
        self.assertEqual(detect_candidates(address), ["solana"])

    def test_valid_bitcoin_checksum_still_routes_only_to_bitcoin(self):
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        self.assertTrue(is_bitcoin_address(address))
        self.assertFalse(is_solana_address(address))
        self.assertEqual(detect_candidates(address), ["btc"])

    def test_invalid_bitcoin_is_not_accepted_as_solana(self):
        address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyU"
        self.assertFalse(is_bitcoin_address(address))
        self.assertFalse(is_solana_address(address))
        self.assertEqual(detect_candidates(address), [])

    def test_base58_syntax_without_32_decoded_bytes_is_not_solana(self):
        for address in ("a" * 31, "z" * 44, "1" * 31, "0" * 43, "random-input"):
            with self.subTest(address=address):
                self.assertFalse(is_solana_address(address))
                self.assertNotIn("solana", detect_candidates(address))

    def test_system_program_key_is_not_rejected_by_bitcoin_prefix(self):
        self.assertEqual(detect_candidates("11111111111111111111111111111111"), ["solana"])
