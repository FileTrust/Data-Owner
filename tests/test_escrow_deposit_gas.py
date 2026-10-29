"""Normal single-escrow gas estimation and recovery regressions."""
import os
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ['DO_CONFIG_PATH'] = str(Path(__file__).with_name('config.test.json'))

from hexbytes import HexBytes
from web3 import Web3
from core import do_vaultmesh as VM


class EscrowDepositGasTests(unittest.TestCase):
    def setUp(self):
        self.owner = Web3.to_checksum_address('0x' + '12' * 20)
        self.quote = dict(paymentCommitment='0x' + '23' * 32,
            sizeCommitment='0x' + '34' * 32, linkCommitment='0x' + '45' * 32,
            priceWei=1000, serviceEnd=5000, transferDeadline=2000, quoteValidUntil=300)
        self.fn = Mock()
        self.fn.estimate_gas.return_value = 201595
        self.fn.build_transaction.side_effect = lambda fields: fields
        self.escrow = Mock(address='0x' + '56' * 20)
        self.escrow.functions.maxRegistrationTimeoutSeconds.return_value.call.return_value = 3600
        self.escrow.functions.escrows.return_value.call.return_value = (0,) * 14
        self.escrow.functions.depositEscrowV2.return_value = self.fn
        self.escrow.functions.depositEscrowBondV2.return_value = self.fn
        self.w3 = Mock()
        self.w3.to_checksum_address = Web3.to_checksum_address
        self.w3.eth.send_raw_transaction.return_value = HexBytes(b'\xaa' * 32)
        self.w3.eth.wait_for_transaction_receipt.return_value = SimpleNamespace(status=1)
        self.account = Mock()
        self.account.sign_transaction.return_value = SimpleNamespace(raw_transaction=b'unit-signed')
        patches = [
            patch.multiple(VM.C, w3=self.w3, vk_escrow=self.escrow, DO=self.owner,
                DO_ACCOUNT=self.account, gas_price_wei=Mock(return_value=1000000)),
            patch.object(VM, 'latest_chain_timestamp', return_value=100),
            patch.object(VM, '_hybrid_bond_wei', return_value=123),
            patch.object(VM.TM, 'account_transaction_lock', return_value=nullcontext()),
            patch.object(VM.TM, 'pending_nonce', return_value=2),
            patch.multiple(VM.TX, log_eth_call=Mock(), log_contract_transaction=Mock(),
                log_contract_transaction_attempt=Mock()),
            patch.object(VM.L, 'log'),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_full_deposit_estimates_exact_value_before_signing(self):
        with patch.object(VM, '_hybrid_escrow_enabled', return_value=False):
            item = {}
            result = VM._deposit_escrow_from_quote_info(item, self.quote)
        self.assertEqual(result, self.quote['paymentCommitment'])
        self.fn.estimate_gas.assert_called_once_with({'from': self.owner, 'value': 1000})
        signed = self.account.sign_transaction.call_args.args[0]
        self.assertEqual(signed['gas'], 281595)
        self.assertEqual(signed['value'], 1000)
        self.assertEqual(signed['nonce'], 2)
        self.assertEqual(item['escrowDepositWei'], 1000)

    def test_bond_deposit_estimates_only_the_existing_bond_value(self):
        with patch.object(VM, '_hybrid_escrow_enabled', return_value=True):
            item = {}
            self.assertEqual(VM._deposit_escrow_from_quote_info(item, self.quote), self.quote['paymentCommitment'])
        self.fn.estimate_gas.assert_called_once_with({'from': self.owner, 'value': 123})
        self.assertEqual(self.account.sign_transaction.call_args.args[0]['gas'], 281595)
        self.assertEqual(item['escrowExpectedTotalWei'], 1000)
        self.assertTrue(item['escrowPendingFinalize'])

    def test_failed_estimation_does_not_sign_or_broadcast(self):
        self.fn.estimate_gas.side_effect = ConnectionError('RPC unavailable')
        with patch.object(VM, '_hybrid_escrow_enabled', return_value=False):
            item = {}
            self.assertEqual(VM._deposit_escrow_from_quote_info(item, self.quote), '')
        self.fn.build_transaction.assert_not_called()
        self.account.sign_transaction.assert_not_called()
        self.w3.eth.send_raw_transaction.assert_not_called()
        self.assertIn('RPC unavailable', item['escrowDepositError'])

    def test_existing_matching_deposit_is_recovered_without_a_new_transaction(self):
        self.escrow.functions.escrows.return_value.call.return_value = (
            1000, 100, 5000, bytes.fromhex('34' * 32), bytes.fromhex('45' * 32),
            True, 0, 0, '0x' + '00' * 20, self.owner, 2000, 0, 0, 0)
        with patch.object(VM, '_hybrid_escrow_enabled', return_value=False):
            item = {}
            self.assertEqual(VM._deposit_escrow_from_quote_info(item, self.quote), self.quote['paymentCommitment'])
        self.fn.estimate_gas.assert_not_called()
        self.account.sign_transaction.assert_not_called()
        self.w3.eth.send_raw_transaction.assert_not_called()
        self.assertTrue(item['escrowRecoveredOnChain'])


if __name__ == '__main__':
    unittest.main()
