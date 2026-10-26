"""Durable, bounded DKG recovery accounting, independent of GUI/config.

The budget covers gross native debits: escrow funding plus transaction fees.
Refunds/compensation are reported separately by the chain client; an expected
refund never becomes permission to spend again. Amounts use decimal strings
because native-coin wei values routinely exceed SQLite's signed 64-bit range.
No wallet secret, DKG coefficient, key share or private proof input belongs here.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3


class RecoveryLimit(RuntimeError):
    pass


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'Invalid DKG recovery {name}')
    return value


def _hex(value, size):
    value = str(value).lower().removeprefix('0x')
    if len(value) != size * 2 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Invalid DKG recovery chain identifier')
    return '0x' + value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class RecoveryJournal:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise PermissionError('DKG recovery journal cannot be a symlink')
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.path, flags, 0o600)
        os.close(fd)
        if os.name != 'nt':
            info = self.path.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise PermissionError('DKG recovery journal requires owner-only permissions')
        with self._transaction() as db:
            schema = '''
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, binding TEXT NOT NULL, intent TEXT NOT NULL,
                    max_attempts INTEGER NOT NULL, max_debit TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running', message TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS attempts (
                    operation TEXT NOT NULL REFERENCES operations(id), number INTEGER NOT NULL,
                    intent TEXT NOT NULL, material TEXT, context TEXT,
                    outcome TEXT NOT NULL DEFAULT 'pending',
                    PRIMARY KEY(operation, number), UNIQUE(operation, material));
                CREATE TABLE IF NOT EXISTS actions (
                    operation TEXT NOT NULL, attempt INTEGER NOT NULL, id TEXT NOT NULL,
                    binding TEXT NOT NULL, reservation TEXT NOT NULL,
                    raw TEXT, hash TEXT, receipt TEXT, actual_debit TEXT,
                    status TEXT NOT NULL DEFAULT 'reserved',
                    PRIMARY KEY(operation, id),
                    FOREIGN KEY(operation, attempt) REFERENCES attempts(operation, number));
                CREATE TABLE IF NOT EXISTS wallet_nonces (
                    chain_id TEXT NOT NULL, owner TEXT NOT NULL, nonce TEXT NOT NULL,
                    operation TEXT NOT NULL, action TEXT NOT NULL,
                    PRIMARY KEY(chain_id, owner, nonce));
                CREATE TABLE IF NOT EXISTS stages (
                    operation TEXT NOT NULL, attempt INTEGER NOT NULL, name TEXT NOT NULL,
                    value TEXT NOT NULL, PRIMARY KEY(operation,attempt,name),
                    FOREIGN KEY(operation,attempt) REFERENCES attempts(operation,number));
            '''
            for statement in schema.split(';'):
                if statement.strip():
                    db.execute(statement)
            # Additive journal migration: existing limits, reservations and
            # signed bytes remain authoritative when this component upgrades.
            columns = {row['name'] for row in db.execute('PRAGMA table_info(operations)')}
            if 'message' not in columns:
                db.execute("ALTER TABLE operations ADD COLUMN message TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=15000')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _operation(db, operation):
        row = db.execute('SELECT * FROM operations WHERE id=?', (operation,)).fetchone()
        if row is None:
            raise KeyError('Unknown DKG recovery operation')
        return row

    def create(self, operation, *, chain_id, coordinator, owner, file_id, kind,
               intent, max_attempts, max_debit_wei):
        if not isinstance(operation, str) or not 1 <= len(operation) <= 128 or kind not in ('fresh', 'refresh', 'withdrawal'):
            raise ValueError('Invalid DKG recovery operation')
        _integer(chain_id, 'chain ID', 1)
        _integer(max_attempts, 'attempt limit', 1)
        _integer(max_debit_wei, 'spending limit', 1)
        binding = _json({'chain_id': chain_id, 'coordinator': _hex(coordinator, 20),
                         'owner': _hex(owner, 20), 'file_id': _hex(file_id, 32), 'kind': kind})
        values = (binding, _json(intent), max_attempts, str(max_debit_wei))
        with self._transaction() as db:
            old = db.execute('SELECT * FROM operations WHERE id=?', (operation,)).fetchone()
            if old:
                if tuple(old[k] for k in ('binding', 'intent', 'max_attempts', 'max_debit')) != values:
                    raise RuntimeError('Recovery intent or limits changed; explicit new approval is required')
            else:
                scope = json.loads(binding)
                for active in db.execute("SELECT binding FROM operations WHERE status IN ('running','needs_action')"):
                    previous = json.loads(active['binding'])
                    if all(previous[key] == scope[key] for key in ('chain_id', 'coordinator', 'owner', 'file_id')):
                        raise RuntimeError('This wallet already has an unfinished recovery operation for the file; resume it')
                db.execute('INSERT INTO operations(id,binding,intent,max_attempts,max_debit) VALUES(?,?,?,?,?)',
                           (operation, *values))

    def begin_attempt(self, operation, number, intent):
        _integer(number, 'attempt number', 1)
        encoded = _json(intent)
        with self._transaction() as db:
            op = self._operation(db, operation)
            old = db.execute('SELECT intent FROM attempts WHERE operation=? AND number=?', (operation, number)).fetchone()
            if old:
                if old['intent'] != encoded:
                    raise RuntimeError('Cannot change an existing recovery attempt')
                return
            if op['status'] != 'running' or number > op['max_attempts']:
                raise RecoveryLimit('DKG recovery attempt limit reached or operation finished')
            previous = db.execute('SELECT number,outcome FROM attempts WHERE operation=? ORDER BY number DESC LIMIT 1',
                                  (operation,)).fetchone()
            if (previous is None and number != 1) or (previous is not None and
                    (number != previous['number']+1 or previous['outcome'] == 'pending')):
                raise RuntimeError('Resolve the current attempt before creating another')
            db.execute('INSERT INTO attempts(operation,number,intent) VALUES(?,?,?)', (operation, number, encoded))

    def bind_material(self, operation, number, material_id, context_hash=None):
        material = _hex(material_id, 32)
        context = None if context_hash is None else _hex(context_hash, 32)
        with self._transaction() as db:
            row = db.execute('SELECT * FROM attempts WHERE operation=? AND number=?', (operation, number)).fetchone()
            if row is None:
                raise KeyError('Unknown DKG recovery attempt')
            if (row['material'] is not None and row['material'] != material) or (
                    row['context'] is not None and context is not None and row['context'] != context):
                raise RuntimeError('A recovery attempt cannot switch its material context')
            if row['material'] is None and row['outcome'] != 'pending':
                raise RuntimeError('Cannot bind new material to a terminal recovery attempt')
            context = row['context'] if context is None else context
            if row['outcome'] != 'pending' and (row['material'], row['context']) != (material, context):
                raise RuntimeError('Cannot change material binding on a terminal recovery attempt')
            db.execute('UPDATE attempts SET material=?,context=? WHERE operation=? AND number=?',
                       (material, context, operation, number))

    def stage_value(self, operation, number, name, value=None):
        """Freeze derived stage parameters once, before their transaction.

        In particular, an open/acceptance deadline must not move forward on
        every poll or change after a lost transaction receipt.
        """
        with self._transaction() as db:
            row = db.execute('SELECT value FROM stages WHERE operation=? AND attempt=? AND name=?',
                             (operation, number, name)).fetchone()
            if row:
                if value is not None and row['value'] != _json(value):
                    raise RuntimeError('Recovery stage parameters cannot change after being saved')
                return json.loads(row['value'])
            if value is not None:
                db.execute('INSERT INTO stages VALUES(?,?,?,?)', (operation, number, name, _json(value)))
            return value

    def set_status(self, operation, status, message=None):
        if status not in ('running', 'needs_action', 'stopped'):
            raise ValueError('Invalid recovery operation status')
        with self._transaction() as db:
            op = self._operation(db, operation)
            if op['status'] == 'succeeded':
                raise RuntimeError('A completed key operation cannot be restarted')
            if status == 'stopped' and db.execute("SELECT 1 FROM actions WHERE operation=? AND status IN ('reserved','signed')", (operation,)).fetchone():
                raise RuntimeError('Resolve pending recovery transactions before stopping the operation')
            if status == 'stopped' and db.execute("SELECT 1 FROM attempts WHERE operation=? AND outcome='pending'", (operation,)).fetchone():
                raise RuntimeError('Close the active chain attempt before stopping its recovery operation')
            db.execute('UPDATE operations SET status=?,message=? WHERE id=?',
                       (status, op['message'] if message is None else str(message), operation))

    @staticmethod
    def _used(db, operation):
        rows = db.execute('SELECT reservation,actual_debit FROM actions WHERE operation=?', (operation,))
        return sum(int(row['actual_debit'] if row['actual_debit'] is not None else row['reservation']) for row in rows)

    def reserve_action(self, operation, attempt, action, *, to, data, value, gas, gas_price, nonce):
        for field, amount, minimum in [('value', value, 0), ('gas', gas, 21000),
                                       ('gas price', gas_price, 1), ('nonce', nonce, 0)]:
            _integer(amount, field, minimum)
        if gas > 16_777_216 or not isinstance(action, str) or not 1 <= len(action) <= 128:
            raise ValueError('Invalid DKG recovery transaction limits')
        if not isinstance(data, str) or not data.startswith('0x'):
            raise ValueError('Invalid DKG recovery transaction data')
        payload = bytes.fromhex(data[2:])
        reservation = value + gas * gas_price
        with self._transaction() as db:
            op = self._operation(db, operation)
            network = json.loads(op['binding'])
            binding = _json({'chainId': network['chain_id'], 'from': network['owner'],
                'to': _hex(to, 20), 'data': '0x'+payload.hex(), 'value': value,
                'gas': gas, 'gasPrice': gas_price, 'nonce': nonce})
            old = db.execute('SELECT * FROM actions WHERE operation=? AND id=?', (operation, action)).fetchone()
            if old:
                if old['binding'] != binding or old['attempt'] != attempt:
                    raise RuntimeError('Cannot replace a reserved recovery transaction')
                return
            current = db.execute('SELECT outcome FROM attempts WHERE operation=? AND number=?', (operation, attempt)).fetchone()
            if op['status'] != 'running' or current is None or current['outcome'] != 'pending':
                raise RuntimeError('Recovery attempt is not open for a new transaction')
            if self._used(db, operation) + reservation > int(op['max_debit']):
                raise RecoveryLimit('DKG recovery spending limit would be exceeded')
            try:
                db.execute('INSERT INTO wallet_nonces VALUES(?,?,?,?,?)',
                    (str(network['chain_id']), network['owner'], str(nonce), operation, action))
            except sqlite3.IntegrityError:
                raise RuntimeError('Wallet nonce is already reserved by another recovery transaction') from None
            db.execute('INSERT INTO actions(operation,attempt,id,binding,reservation) VALUES(?,?,?,?,?)',
                       (operation, attempt, action, binding, str(reservation)))

    def attach_signed(self, operation, action, raw):
        # Recovery deliberately uses EIP-155 gasPrice transactions so the
        # native-debit cap is exact and portable to the target Cosmos EVM.
        from eth_account import Account
        from eth_account._utils.legacy_transactions import Transaction
        from web3 import Web3
        raw = bytes(raw)
        tx = Transaction.from_bytes(raw).as_dict()
        if tx['v'] < 35:
            raise ValueError('Recovery requires a chain-bound transaction')
        decoded = {'chainId': (tx['v']-35)//2, 'from': Account.recover_transaction(raw).lower(),
            'to': '0x'+tx['to'].hex(), 'data': '0x'+tx['data'].hex(), 'value': tx['value'],
            'gas': tx['gas'], 'gasPrice': tx['gasPrice'], 'nonce': tx['nonce']}
        with self._transaction() as db:
            row = db.execute('SELECT * FROM actions WHERE operation=? AND id=?', (operation, action)).fetchone()
            if row is None or row['status'] not in ('reserved', 'signed'):
                raise RuntimeError('Recovery transaction was not reserved for signing')
            if decoded != json.loads(row['binding']):
                raise RuntimeError('Signed transaction differs from the approved recovery reservation')
            if row['raw'] is not None and row['raw'] != raw.hex():
                raise RuntimeError('Cannot replace an uncertain signed recovery transaction')
            db.execute("UPDATE actions SET raw=?,hash=?,status='signed' WHERE operation=? AND id=?",
                       (raw.hex(), Web3.to_hex(Web3.keccak(raw)), operation, action))

    def confirm(self, operation, action, *, transaction_hash, status, gas_used, effective_gas_price, block_hash, block_number):
        _integer(status, 'receipt status')
        _integer(gas_used, 'receipt gas')
        _integer(effective_gas_price, 'receipt gas price')
        _integer(block_number, 'receipt block')
        receipt = {'transactionHash': _hex(transaction_hash, 32), 'status': status, 'gasUsed': gas_used,
                   'effectiveGasPrice': effective_gas_price, 'blockHash': _hex(block_hash, 32), 'blockNumber': block_number}
        with self._transaction() as db:
            row = db.execute('SELECT * FROM actions WHERE operation=? AND id=?', (operation, action)).fetchone()
            if row is None or row['hash'] != receipt['transactionHash'] or status not in (0, 1):
                raise RuntimeError('Receipt does not identify the reserved recovery transaction')
            binding = json.loads(row['binding'])
            if gas_used > binding['gas'] or effective_gas_price > binding['gasPrice']:
                raise RuntimeError('Receipt exceeds the signed recovery transaction limits')
            encoded = _json(receipt)
            if row['receipt'] is not None and row['receipt'] != encoded:
                raise RuntimeError('Recovery receipt changed; check chain finality before continuing')
            actual = gas_used * effective_gas_price + (binding['value'] if status else 0)
            db.execute("UPDATE actions SET receipt=?,actual_debit=?,status='confirmed' WHERE operation=? AND id=?",
                       (encoded, str(actual), operation, action))

    def abandon_unsigned(self, operation, action):
        with self._transaction() as db:
            row = db.execute('SELECT raw FROM actions WHERE operation=? AND id=?', (operation, action)).fetchone()
            if row is None or row['raw'] is not None:
                raise RuntimeError('An uncertain signed transaction cannot be discarded')
            db.execute("UPDATE actions SET actual_debit='0',status='abandoned' WHERE operation=? AND id=?", (operation, action))
            db.execute('DELETE FROM wallet_nonces WHERE operation=? AND action=?', (operation, action))

    def finish_attempt(self, operation, number, outcome):
        if outcome not in ('succeeded', 'failed', 'cancelled', 'unactivated'):
            raise ValueError('Invalid terminal DKG outcome')
        with self._transaction() as db:
            row = db.execute('SELECT outcome FROM attempts WHERE operation=? AND number=?', (operation, number)).fetchone()
            if row is None:
                raise KeyError('Unknown DKG recovery attempt')
            if row['outcome'] not in ('pending', outcome):
                raise RuntimeError('A terminal recovery attempt cannot change its outcome')
            if db.execute("SELECT 1 FROM actions WHERE operation=? AND attempt=? AND status IN ('reserved','signed')",
                          (operation, number)).fetchone():
                raise RuntimeError('Resolve all reserved transactions before closing the attempt')
            db.execute('UPDATE attempts SET outcome=? WHERE operation=? AND number=?', (outcome, operation, number))
            if outcome == 'succeeded':
                db.execute("UPDATE operations SET status='succeeded' WHERE id=?", (operation,))

    def snapshot(self, operation):
        with self._transaction() as db:
            op = dict(self._operation(db, operation))
            op['binding'], op['intent'] = json.loads(op['binding']), json.loads(op['intent'])
            op['committed_debit_wei'] = self._used(db, operation)
            op['remaining_debit_wei'] = int(op['max_debit']) - op['committed_debit_wei']
            op['attempts'] = [dict(row) for row in db.execute('SELECT * FROM attempts WHERE operation=? ORDER BY number', (operation,))]
            # Raw envelopes are retrieved only by the sender, never UI reports.
            op['actions'] = [dict(row) for row in db.execute('SELECT id,attempt,binding,reservation,hash,receipt,actual_debit,status FROM actions WHERE operation=?', (operation,))]
            return op

    def pending_envelope(self, operation, action):
        with self._transaction() as db:
            row = db.execute('SELECT raw,hash FROM actions WHERE operation=? AND id=? AND status=?', (operation, action, 'signed')).fetchone()
            return None if row is None else (bytes.fromhex(row['raw']), row['hash'])

    def action(self, operation, action):
        """Private sender record; do not pass its raw envelope to UI logging."""
        with self._transaction() as db:
            row = db.execute('SELECT * FROM actions WHERE operation=? AND id=?', (operation, action)).fetchone()
            return None if row is None else dict(row)

    def pending_actions(self):
        with self._transaction() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM actions WHERE status IN ('reserved','signed')")]
            return sorted(rows, key=lambda row: (json.loads(row['binding'])['chainId'], json.loads(row['binding'])['nonce']))

    def operations(self):
        with self._transaction() as db:
            return [dict(row) for row in db.execute('SELECT id,status,binding,intent,message FROM operations ORDER BY rowid')]
