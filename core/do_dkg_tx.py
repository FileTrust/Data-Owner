"""Budgeted DKG sends using DO's common process-safe wallet transaction lane.

Persist signed bytes before broadcast. Uncertainty retains the nonce and gross
debit reservation. Restart recovery can only resend the same signed transaction.
"""
import json

from web3 import Web3
from web3.exceptions import TransactionNotFound

from .do_dkg_paths import wallet_journal_path
from .do_tx_manager import account_transaction_lock


class RecoveryTransactionPending(RuntimeError):
    pass


class RecoverySender:
    def __init__(self, w3, account, journal, *, allowed_targets, max_gas_price_wei,
                 max_gas=10_000_000, receipt_timeout=30):
        if journal.path.absolute() != wallet_journal_path(account.address).absolute():
            raise RuntimeError('Recovery must use the shared account journal, outside the source clone')
        if not 21000 <= max_gas <= 16_777_216 or type(max_gas_price_wei) is not int or max_gas_price_wei <= 0:
            raise ValueError('Configure bounded recovery transaction fees')
        self.w3, self.account, self.journal = w3, account, journal
        self.targets = {Web3.to_checksum_address(a).lower() for a in allowed_targets}
        self.max_price, self.max_gas, self.timeout = max_gas_price_wei, max_gas, receipt_timeout

    def _binding(self, operation, binding):
        op = self.journal.snapshot(operation)
        network = op['binding']
        approved = {a.lower() for a in op['intent']['allowed_contracts']}
        if (network['owner'] != self.account.address.lower() or network['chain_id'] != self.w3.eth.chain_id or
                binding['chainId'] != network['chain_id'] or binding['from'] != network['owner'] or
                binding['to'].lower() not in approved):
            raise RuntimeError('Recovery transaction belongs to a different wallet, network or approved contract')

    def _receipt(self, row):
        binding = json.loads(row['binding'])
        self._binding(row['operation'], binding)
        if row['status'] == 'reserved':
            # No broadcast can have happened without an attached envelope.
            # Recheck still-valid calldata before signing an interrupted intent.
            call = {k: binding[k] for k in ('from', 'to', 'data', 'value', 'gas', 'gasPrice')}
            call['from'], call['to'] = self.account.address, Web3.to_checksum_address(binding['to'])
            if binding['gasPrice'] > self.max_price or binding['gas'] > self.max_gas:
                raise RuntimeError('Unsigned recovery transaction exceeds the current operator fee limits')
            self.w3.eth.call(call)
            if self.w3.eth.get_transaction_count(self.account.address, 'pending') != binding['nonce']:
                raise RuntimeError('Unsigned recovery nonce changed outside this journal; review before continuing')
            signed = self.account.sign_transaction({**binding, 'from': self.account.address, 'to': call['to']})
            raw = bytes(signed.raw_transaction if hasattr(signed, 'raw_transaction') else signed.rawTransaction)
            self.journal.attach_signed(row['operation'], row['id'], raw)
            row = self.journal.action(row['operation'], row['id'])
        expected = row['hash']
        try:
            receipt = self.w3.eth.get_transaction_receipt(expected)
        except TransactionNotFound:
            try:
                actual = self.w3.eth.send_raw_transaction(bytes.fromhex(row['raw']))
                if Web3.to_hex(actual).lower() != expected:
                    raise RuntimeError('RPC returned an unexpected signed transaction hash')
            except Exception as error:
                if not any(value in str(error).lower() for value in ('already known', 'known transaction')):
                    raise RecoveryTransactionPending('Recovery broadcast is uncertain; signed bytes and spending reservation kept') from None
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(expected, timeout=self.timeout)
            except Exception:
                raise RecoveryTransactionPending('Recovery confirmation is uncertain; signed bytes and spending reservation kept') from None
        self.journal.confirm(row['operation'], row['id'], transaction_hash=Web3.to_hex(receipt['transactionHash']),
            status=int(receipt['status']), gas_used=int(receipt['gasUsed']),
            effective_gas_price=int(receipt.get('effectiveGasPrice', binding['gasPrice'])),
            block_hash=Web3.to_hex(receipt['blockHash']), block_number=int(receipt['blockNumber']))
        return receipt

    def recover(self, *, signed_only=False):
        with account_transaction_lock(self.account.address, allow_recovery=True):
            return [self._receipt(row) for row in self.journal.pending_actions()
                    if not signed_only or row['status']=='signed']

    def submit(self, operation, attempt, action, fn, *, value=0):
        with account_transaction_lock(self.account.address, allow_recovery=True):
            previous = self.journal.action(operation, action)
            if previous:
                binding = json.loads(previous['binding'])
                self._binding(operation, binding)
                transaction = fn.build_transaction({'from': self.account.address,
                    'chainId': binding['chainId'], 'nonce': binding['nonce'],
                    'gas': binding['gas'], 'gasPrice': binding['gasPrice'], 'value': value})
                if (previous['attempt'] != attempt or value != binding['value'] or
                        transaction['to'].lower() != binding['to'] or transaction['data'].lower() != binding['data']):
                    raise RuntimeError('Cannot change the intent of an existing recovery action')
            self.recover()
            previous = self.journal.action(operation, action)
            if previous:
                if previous['status'] == 'confirmed':
                    return json.loads(previous['receipt'])
                raise RuntimeError('The recovery action already has a reserved or abandoned intent')
            price = int(self.w3.eth.gas_price)
            if not 0 < price <= self.max_price:
                raise RuntimeError('Recovery gas price exceeds the operator limit')
            fields = {'from': self.account.address, 'gas': self.max_gas, 'value': value, 'gasPrice': price}
            fn.call(fields)
            try:
                gas = min(self.max_gas, (int(fn.estimate_gas(fields))*6+4)//5)
            except Exception:
                gas = self.max_gas
            transaction = fn.build_transaction({**fields, 'gas': gas, 'chainId': self.w3.eth.chain_id,
                'nonce': self.w3.eth.get_transaction_count(self.account.address, 'pending')})
            binding = {key: transaction[key] for key in ('chainId', 'from', 'to', 'data', 'value', 'gas', 'gasPrice', 'nonce')}
            binding['from'], binding['to'] = binding['from'].lower(), binding['to'].lower()
            self._binding(operation, binding)
            if binding['to'] not in self.targets:
                raise RuntimeError('The recovery action is outside the selected contract deployment')
            if self.w3.eth.get_balance(self.account.address) < value + gas*price:
                raise RuntimeError('Insufficient wallet balance for the bounded recovery transaction')
            self.journal.reserve_action(operation, attempt, action, to=binding['to'], data=binding['data'],
                value=value, gas=gas, gas_price=price, nonce=binding['nonce'])
            return self._receipt(self.journal.action(operation, action))
