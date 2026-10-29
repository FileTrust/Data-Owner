import os
import unittest
from pathlib import Path
from unittest import mock

os.environ["DO_CONFIG_PATH"] = str(Path(__file__).with_name("config.test.json"))

from core.do_rpc import ResilientHTTPProvider
from core import do_chain


class ResilientRPCProviderTests(unittest.TestCase):
    def test_null_receipt_reaches_web3_as_transaction_not_found(self):
        from web3 import Web3
        from web3.exceptions import TransactionNotFound
        provider = ResilientHTTPProvider('http://127.0.0.1:1', attempts=3, backoff_initial_seconds=0)
        with mock.patch('core.do_rpc.HTTPProvider.make_request', return_value={
                'jsonrpc': '2.0', 'id': 1, 'result': None}) as request:
            with self.assertRaises(TransactionNotFound):
                Web3(provider).eth.get_transaction_receipt('0x'+'12'*32)
        self.assertEqual(request.call_count, 1)

    def test_null_transaction_lookup_is_valid_but_null_contract_result_is_not(self):
        provider = ResilientHTTPProvider('http://127.0.0.1:1', attempts=2, backoff_initial_seconds=0)
        with mock.patch('core.do_rpc.HTTPProvider.make_request', return_value={
                'jsonrpc': '2.0', 'id': 1, 'result': None}):
            self.assertIsNone(provider.make_request('eth_getTransactionByHash', [])['result'])
            with self.assertRaises(ConnectionError): provider.make_request('eth_call', [])

    def test_read_retries_then_succeeds(self):
        provider = ResilientHTTPProvider(
            "http://127.0.0.1:1", attempts=3, backoff_initial_seconds=0
        )
        with mock.patch(
            "core.do_rpc.HTTPProvider.make_request",
            side_effect=[
                ConnectionError("closed"),
                {"jsonrpc": "2.0", "id": 1},
                {"jsonrpc": "2.0", "id": 1, "result": "0x01"},
            ],
        ) as request:
            result = provider.make_request("eth_call", [])
        self.assertEqual("0x01", result["result"])
        self.assertEqual(3, request.call_count)

    def test_transaction_submission_is_never_retried(self):
        provider = ResilientHTTPProvider(
            "http://127.0.0.1:1", attempts=4, backoff_initial_seconds=0
        )
        with mock.patch(
            "core.do_rpc.HTTPProvider.make_request",
            side_effect=ConnectionError("response lost"),
        ) as request:
            with self.assertRaises(ConnectionError):
                provider.make_request("eth_sendRawTransaction", ["0x01"])
        self.assertEqual(1, request.call_count)

    def test_lost_submission_response_reconciles_local_transaction_hash(self):
        eth = mock.Mock()
        eth.send_raw_transaction.side_effect = ConnectionError("response lost")
        receipt = mock.Mock(status=1)
        eth.wait_for_transaction_receipt.return_value = receipt
        w3 = mock.Mock()
        w3.eth = eth
        w3.keccak.return_value = b"local-transaction-hash"
        with mock.patch.object(do_chain.C, "w3", w3):
            tx_hash, found = do_chain._broadcast_and_wait_signed(b"signed")
        self.assertEqual(b"local-transaction-hash", tx_hash)
        self.assertIs(receipt, found)
        eth.send_raw_transaction.assert_called_once_with(b"signed")
        eth.wait_for_transaction_receipt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
