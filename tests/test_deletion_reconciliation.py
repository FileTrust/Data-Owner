import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ["DO_CONFIG_PATH"] = str(Path(__file__).with_name("config.test.json"))

from core import do_actions as actions
from core import do_chain as chain
from core import do_piece_journal as journal


FILE_ID = "11" * 32
FILE_REGISTRATION = "0x" + "99" * 20


def _journal_piece(*, state="pending"):
    commitment = "0x" + "33" * 32
    return {
        "fileId": FILE_ID,
        "chainId": 31337,
        "fileRegistrationContract": FILE_REGISTRATION,
        "pieceIndex": 1,
        "pieceRoot": "0x" + "22" * 32,
        "commitmentHash": commitment,
        "logicalJobId": "logical-piece-1",
        "deletionStatus": state,
        "commitmentNonce": "0x" + "44" * 32,
        "deletionAuthSecret": "0x" + "55" * 32,
        "privateReceipt": {
            "pieceRoot": "0x" + "22" * 32,
            "commitmentHash": commitment,
        },
    }


class DeletionReconciliationTests(unittest.TestCase):
    def test_vk_acceptance_returns_pending_without_waiting_for_confirmation(self):
        response = (
            '{"ok":true,"accepted":true,"pending":true,'
            '"phase":"declared","deletionId":"0x' + "11" * 32 + '"}'
        )
        with mock.patch(
            "core.do_vaultmesh.run_vaultmesh_cmd", return_value=response
        ), mock.patch.object(
            chain,
            "verify_deletion_onchain",
            return_value={"declared": True, "confirmed": False, "ok": False, "error": ""},
        ) as verify, mock.patch.object(chain, "reconcile_deletion_onchain") as slow_reconcile:
            ok, summary = chain.request_file_deletion(
                "peer", "0x" + "11" * 32
            )
        self.assertFalse(ok)
        self.assertIn("accepted id=", summary)
        verify.assert_called_once()
        slow_reconcile.assert_not_called()

    def test_initial_request_failure_never_submits_dispute_before_deadline(self):
        item = _journal_piece(state="requested")
        item["peerId"] = "peer"
        with mock.patch.object(
            actions, "_vk_peer_for_delete_item", return_value="peer"
        ), mock.patch.object(
            actions.CH, "request_file_deletion", return_value=(False, "deletion rejected")
        ), mock.patch.object(
            actions, "_auto_dispute_deletion_failure"
        ) as dispute, mock.patch.object(actions.L, "log"), mock.patch.object(
            actions.L, "set_status"
        ):
            ok, summary = actions._delete_vk_piece_item(item)
        self.assertFalse(ok)
        self.assertEqual("deletion rejected", summary)
        dispute.assert_not_called()

    def test_restart_recreates_monitor_from_durable_pending_journal(self):
        fake_thread = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            actions.C, "BASE_DIR", tmp
        ), mock.patch.object(
            actions.threading, "Thread", return_value=fake_thread
        ) as thread_factory:
            piece = _journal_piece(state="pending")
            journal.record_registration(tmp, piece, source="restart-monitor-test")
            actions._PENDING_DELETION_MONITOR_RUNNING = False
            actions._schedule_pending_deletion_reconciliation()
            self.assertTrue(actions._PENDING_DELETION_MONITOR_RUNNING)
            thread_factory.assert_called_once()
            fake_thread.start.assert_called_once()
            actions._PENDING_DELETION_MONITOR_RUNNING = False

    def test_recent_confirmation_events_are_observed(self):
        commitment = bytes.fromhex("22" * 32)
        event_reader = mock.Mock()
        event_reader.get_logs.return_value = [
            {"args": {"commitmentHash": commitment}}
        ]
        contract = SimpleNamespace(
            events=SimpleNamespace(
                FileDeletionConfirmed=lambda: event_reader
            )
        )
        web3 = SimpleNamespace(eth=SimpleNamespace(block_number=12345))
        with mock.patch.object(chain.C, "file_registration_sc", contract), mock.patch.object(
            chain.C, "w3", web3
        ):
            observed = chain.recent_deletion_confirmation_events()
        self.assertEqual({"0x" + "22" * 32}, observed)
        self.assertEqual([mock.call(from_block=2345, to_block=11344),
                          mock.call(from_block=11345, to_block=12345)],
                         event_reader.get_logs.call_args_list)

    def test_confirmation_pagination_covers_the_entire_configured_history(self):
        event = mock.Mock()
        def logs(*, from_block, to_block):
            self.assertLessEqual(to_block - from_block, 8999)
            return [{'args': {'commitmentHash': value.to_bytes(32, 'big')}}
                    for value in (100, 9200, 18200) if from_block <= value <= to_block]
        event.get_logs.side_effect = logs
        contract = SimpleNamespace(events=SimpleNamespace(FileDeletionConfirmed=lambda: event))
        with mock.patch.object(chain.C, 'file_registration_sc', contract), \
                mock.patch.object(chain.C, 'w3', SimpleNamespace(eth=SimpleNamespace(block_number=20000))), \
                mock.patch.object(chain.C.config, 'DO_DELETION_EVENT_LOOKBACK_BLOCKS', 25000, create=True):
            observed = chain.recent_deletion_confirmation_events()
        self.assertEqual({'0x'+value.to_bytes(32, 'big').hex() for value in (100, 9200, 18200)}, observed)
        self.assertEqual([mock.call(from_block=0, to_block=8999),
                          mock.call(from_block=9000, to_block=17999),
                          mock.call(from_block=18000, to_block=20000)], event.get_logs.call_args_list)

    def test_partial_scan_failure_never_returns_incomplete_confirmation_set(self):
        event = mock.Mock()
        event.get_logs.side_effect = [[{'args': {'commitmentHash': bytes.fromhex('11'*32)}}],
                                      ConnectionError('temporary RPC failure')]
        contract = SimpleNamespace(events=SimpleNamespace(FileDeletionConfirmed=lambda: event))
        with mock.patch.object(chain.C, 'file_registration_sc', contract), \
                mock.patch.object(chain.C, 'w3', SimpleNamespace(eth=SimpleNamespace(block_number=20000))), \
                mock.patch.object(chain.L, 'log'):
            self.assertEqual(set(), chain.recent_deletion_confirmation_events())

    def test_deletion_dispute_uses_stable_contract_identity_and_is_idempotent(self):
        commitment_hash = bytes.fromhex("aa" * 32)
        dispute_id = bytes.fromhex("bb" * 32)
        submit = mock.Mock(return_value=object())
        filed = mock.Mock(return_value=object())
        contract = SimpleNamespace(
            address="0x" + "88" * 20,
            functions=SimpleNamespace(
                submitDeletionFailureDispute=submit,
                deletionDisputeFiled=filed,
            ),
        )
        web3 = SimpleNamespace(
            to_checksum_address=lambda value: value,
            keccak=lambda _value: commitment_hash,
            solidity_keccak=lambda _types, _values: dispute_id,
        )
        receipt = {
            "vkSignature": "0x" + "99" * 65,
            "receiptVersion": 1,
            "receiptNonce": "0x" + "01" * 32,
            "vkAddress": "0x" + "77" * 20,
            "pieceRoot": "0x" + "02" * 32,
            "pieceSize": 10,
            "sectorId": "sector-a",
            "sectorRoot": "0x" + "03" * 32,
            "deadlineIndex": 1,
            "partitionIndex": 2,
            "partitionRoot": "0x" + "04" * 32,
            "serviceEnd": 100,
            "timestamp": 50,
            "chainId": 31337,
            "storageProofContract": "0x" + "66" * 20,
        }
        with mock.patch.object(chain.C, "storage_receipt_dispute", contract), mock.patch.object(
            chain.C, "w3", web3
        ), mock.patch.object(chain.C, "DO_ACCOUNT", object()), mock.patch.object(
            chain.TX, "call", return_value=True
        ), mock.patch.object(chain, "send_signed_tx_receipt") as send:
            ok, summary = chain.submit_deletion_failure_dispute(
                receipt, "0x" + "05" * 32
            )
        self.assertTrue(ok)
        self.assertIn("already filed", summary)
        filed.assert_called_once_with(dispute_id)
        submit.assert_not_called()
        send.assert_not_called()

        tx_receipt = SimpleNamespace(
            status=1,
            transactionHash=bytes.fromhex("cc" * 32),
            blockNumber=9,
        )
        with mock.patch.object(chain.C, "storage_receipt_dispute", contract), mock.patch.object(
            chain.C, "w3", web3
        ), mock.patch.object(chain.C, "DO_ACCOUNT", object()), mock.patch.object(
            chain.TX, "call", return_value=False
        ), mock.patch.object(
            chain, "send_signed_tx_receipt", return_value=tx_receipt
        ):
            ok, _summary = chain.submit_deletion_failure_dispute(
                receipt, "0x" + "05" * 32
            )
        self.assertTrue(ok)
        args = submit.call_args.args
        self.assertEqual(17, len(args))
        self.assertEqual(commitment_hash, args[0])
        self.assertEqual(bytes.fromhex("05" * 32), args[1])

    def test_deletion_grace_uses_block_time_not_host_time(self):
        marker = object()
        functions = SimpleNamespace(
            isDeletionDeclared=lambda _commitment: marker,
            isDeletionConfirmed=lambda _commitment: marker,
            getDeletionRecord=lambda _commitment: marker,
        )
        contract = SimpleNamespace(
            address="0x" + "99" * 20,
            functions=functions,
        )
        web3 = SimpleNamespace(
            eth=SimpleNamespace(get_block=lambda _which: {"timestamp": 149})
        )
        with mock.patch.object(chain.C, "file_registration_sc", contract), mock.patch.object(
            chain.C, "w3", web3
        ), mock.patch.object(
            chain.TX, "call", side_effect=[True, False, (100, 50, False)]
        ), mock.patch.object(chain.time, "time", return_value=9_999_999_999):
            status = chain.verify_deletion_onchain("0x" + "10" * 32)
        self.assertEqual(149, status["chain_timestamp"])
        self.assertFalse(status["grace_expired"])

    def test_vk_error_with_declared_deletion_is_pending_not_failed(self):
        response = '{"ok":false,"error":"content already proven"}'
        with mock.patch("core.do_vaultmesh.run_vaultmesh_cmd", return_value=response), mock.patch.object(
            chain,
            "reconcile_deletion_onchain",
            return_value={"declared": True, "confirmed": False, "grace_expired": False, "ok": False},
        ):
            ok, summary = chain.request_file_deletion("peer", "0x" + "11" * 32)
        self.assertFalse(ok)
        self.assertTrue(summary.startswith("deletion pending:"), summary)

    def test_vk_durable_pending_survives_rpc_verification_outage(self):
        response = '{"ok":false,"pending":true,"phase":"partition_synced","error":"rpc EOF"}'
        with mock.patch("core.do_vaultmesh.run_vaultmesh_cmd", return_value=response), mock.patch.object(
            chain,
            "reconcile_deletion_onchain",
            return_value={"declared": False, "confirmed": False, "ok": False, "error": "rpc EOF"},
        ):
            ok, summary = chain.request_file_deletion("peer", "0x" + "66" * 32)
        self.assertFalse(ok)
        self.assertIn("phase=partition_synced", summary)

    def test_interrupted_delete_and_rpc_outage_remain_pending(self):
        with mock.patch(
            "core.do_vaultmesh.run_vaultmesh_cmd",
            side_effect=RuntimeError("delete client retries exhausted"),
        ), mock.patch.object(
            chain,
            "reconcile_deletion_onchain",
            return_value={
                "declared": False,
                "confirmed": False,
                "ok": False,
                "error": "rpc EOF",
            },
        ):
            ok, summary = chain.request_file_deletion(
                "peer", "0x" + "77" * 32
            )
        self.assertFalse(ok)
        self.assertTrue(summary.startswith("deletion pending:"), summary)

    def test_pending_manifest_piece_becomes_confirmed(self):
        status = {
            "declared": True, "confirmed": True, "ok": True,
            "confirmed_at": 123, "declared_at": 100, "grace_seconds": 10,
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            actions.C, "BASE_DIR", tmp
        ), mock.patch.object(
            actions.CH, "verify_deletion_onchain", return_value=status
        ), mock.patch.object(
            actions,
            "_current_registration_namespace",
            return_value=(31337, FILE_REGISTRATION),
        ), mock.patch.object(
            actions.VM.XFER, "settle_piece_job_after_confirmed_deletion"
        ) as settle:
            piece = _journal_piece()
            journal.record_registration(tmp, piece, source="test")
            updates = actions.reconcile_pending_piece_deletions()
            saved = journal.get_by_commitment(tmp, piece["commitmentHash"])
        self.assertEqual("confirmed", updates[0]["state"])
        self.assertTrue(saved["deleted"])
        settle.assert_called_once_with(
            tmp,
            commitment_hash=piece["commitmentHash"],
            transfer_id="",
            winning_peer_id="",
            logical_job_id="logical-piece-1",
        )

    def test_expired_pending_deletion_submits_dispute_once(self):
        status = {
            "declared": True, "confirmed": False, "ok": False,
            "grace_expired": True, "declared_at": 100, "grace_seconds": 10,
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            actions.C, "BASE_DIR", tmp
        ), mock.patch.object(
            actions.CH, "verify_deletion_onchain", return_value=status
        ), mock.patch.object(
            actions,
            "_current_registration_namespace",
            return_value=(31337, FILE_REGISTRATION),
        ), mock.patch.object(
            actions, "_auto_dispute_deletion_failure", return_value=(True, "submitted")
        ) as dispute:
            piece = _journal_piece()
            journal.record_registration(tmp, piece, source="test")
            updates = actions.reconcile_pending_piece_deletions()
            saved = journal.get_by_commitment(tmp, piece["commitmentHash"])
            # A second pass must not submit the same dispute again.
            actions.reconcile_pending_piece_deletions()
        self.assertEqual("disputed", updates[0]["state"])
        self.assertTrue(saved["deletionDisputeSubmitted"])
        self.assertEqual("disputed", saved["deletionStatus"])
        dispute.assert_called_once()

    def test_rpc_outage_cannot_turn_pending_deletion_into_success(self):
        status = {
            "declared": False,
            "confirmed": False,
            "ok": False,
            "grace_expired": False,
            "error": "RPC EOF",
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            actions.C, "BASE_DIR", tmp
        ), mock.patch.object(
            actions.CH, "verify_deletion_onchain", return_value=status
        ), mock.patch.object(
            actions,
            "_current_registration_namespace",
            return_value=(31337, FILE_REGISTRATION),
        ):
            piece = _journal_piece()
            journal.record_registration(tmp, piece, source="test")
            updates = actions.reconcile_pending_piece_deletions()
            saved = journal.get_by_commitment(tmp, piece["commitmentHash"])
        self.assertEqual([], updates)
        self.assertEqual("pending", saved["deletionStatus"])
        self.assertFalse(saved["deleted"])

    def test_stale_chain_journal_piece_is_never_reconciled_on_current_chain(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            actions.C, "BASE_DIR", tmp
        ), mock.patch.object(
            actions,
            "_current_registration_namespace",
            return_value=(31337, FILE_REGISTRATION),
        ), mock.patch.object(
            actions.CH, "verify_deletion_onchain"
        ) as chain_read, mock.patch.object(actions.L, "log"):
            piece = _journal_piece()
            piece["chainId"] = 1
            journal.record_registration(tmp, piece, source="stale-chain-test")
            updates = actions.reconcile_pending_piece_deletions()
            saved = journal.get_by_commitment(
                tmp,
                piece["commitmentHash"],
                chain_id=1,
                file_registration_contract=FILE_REGISTRATION,
            )

        self.assertEqual([], updates)
        self.assertEqual("pending", saved["deletionStatus"])
        chain_read.assert_not_called()

    def test_drop_folder_delete_uses_durable_lifecycle_entrypoint(self):
        piece = _journal_piece(state="active")
        record = {
            "name": "drop.bin",
            "path": "/tmp/drop.bin",
            "pieces": [piece],
        }
        with mock.patch.object(
            actions.PJ, "get_by_commitment", return_value=piece
        ), mock.patch.object(
            actions, "delete_vk_piece", return_value=(True, "confirmed")
        ) as durable_delete, mock.patch.object(
            actions, "_delete_vk_piece_item"
        ) as network_only_delete, mock.patch.object(
            actions.R, "update_drop_upload_record"
        ), mock.patch.object(
            actions, "load_policies_browser"
        ), mock.patch.object(
            actions, "load_stored_pieces_list"
        ), mock.patch.object(
            actions.L, "log"
        ), mock.patch.object(
            actions.L, "set_status"
        ), mock.patch.object(
            actions.L, "show_info"
        ):
            actions._run_drop_folder_delete(record)
        durable_delete.assert_called_once_with(
            commitment_hash=piece["commitmentHash"]
        )
        network_only_delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
