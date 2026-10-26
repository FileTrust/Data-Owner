"""F.1 DO monitor-path tests.

These exercise the REAL reconcile_pending_piece_deletions / _schedule_pending_deletion_
reconciliation from do_actions.py, importing it with lightweight fakes for its heavy
dependencies (tkinter, web3, and the do_* siblings) so no live chain or GUI is needed.
do_deletion_redrive is loaded for real so the actual classifier/planner runs.

Run:  python3 -m pytest App/DO/core/test_deletion_monitor.py -v
"""

import sys
import types
import importlib.util
import pathlib
from unittest import mock

import pytest

_HERE = pathlib.Path(__file__).resolve().parent


def _load_do_actions_with_fakes():
    for name in ["tkinter", "tkinter.filedialog", "tkinter.simpledialog", "web3"]:
        sys.modules[name] = mock.MagicMock()
    pkg = types.ModuleType("docore")
    pkg.__path__ = [str(_HERE)]
    sys.modules["docore"] = pkg
    siblings = ["do_config", "do_state", "do_log", "do_records", "do_chain", "do_txlog",
                "do_tx_manager", "do_vaultmesh", "do_network", "do_hex",
                "do_piece_journal", "do_crypto"]
    for s in siblings:
        sys.modules["docore." + s] = mock.MagicMock()
    # Real classifier module under the package.
    spec = importlib.util.spec_from_file_location(
        "docore.do_deletion_redrive", _HERE / "do_deletion_redrive.py")
    dr = importlib.util.module_from_spec(spec)
    sys.modules["docore.do_deletion_redrive"] = dr
    spec.loader.exec_module(dr)
    # Real do_actions under the package, using the fakes for its siblings.
    spec2 = importlib.util.spec_from_file_location(
        "docore.do_actions", _HERE / "do_actions.py")
    mod = importlib.util.module_from_spec(spec2)
    sys.modules["docore.do_actions"] = mod
    spec2.loader.exec_module(mod)
    return mod, dr


@pytest.fixture()
def da():
    mod, dr = _load_do_actions_with_fakes()
    # Neutralize helpers that touch the (faked) chain namespace / receipts.
    mod._piece_commitment_hash = lambda item: str(item.get("commitmentHash", "0xabc"))
    mod._journal_scope_for_current_chain = lambda item: {}
    mod._vk_peer_for_delete_item = lambda item, receipt: "peer-1"
    mod._load_vk_receipt_for_piece = lambda piece_root, commitment: {}
    mod._settle_piece_transfer_after_confirmed_deletion = lambda *a, **k: None
    mod.CH.recent_deletion_confirmation_events.return_value = set()
    # Reset the durable-journal mock recorders.
    mod.PJ.reset_mock()
    return mod, dr


def _item(commitment="0xabc", piece_root="0xpiece"):
    return {"commitmentHash": commitment, "pieceRoot": piece_root, "privateReceipt": {}}


def test_restart_reload_of_unresolved_entry_invokes_redrive(da):
    """Bullet 2: an unresolved journal entry (as reloaded after restart) triggers a
    secret-bearing re-drive, and the entry is preserved (pending), not failed/confirmed."""
    mod, dr = da
    calls = []
    mod.CH.redrive_deletion_request = lambda peer, ch, secret: (
        calls.append((peer, ch, secret)) or
        {"ok": True, "accepted": True, "declared": False, "retryable": True})
    mod.CH.verify_deletion_onchain.return_value = {"ok": False, "declared": False, "confirmed": False}
    mod.PJ.unresolved_deletions.return_value = [_item()]

    mod.reconcile_pending_piece_deletions()

    assert len(calls) == 1, "unresolved undeclared entry must be re-driven exactly once per tick"
    assert mod.PJ.mark_deletion_pending.called, "entry must be preserved as pending"
    assert not mod.PJ.mark_deletion_failed.called
    assert not mod.PJ.mark_deletion_confirmed.called


def test_one_redrive_per_deletion_per_tick(da):
    """Bullet 1 (per-item): each unresolved deletion is re-driven exactly once per tick."""
    mod, dr = da
    counts = {}
    def rec(peer, ch, secret):
        counts[ch] = counts.get(ch, 0) + 1
        return {"ok": True, "accepted": True, "declared": False, "retryable": True}
    mod.CH.redrive_deletion_request = rec
    mod.CH.verify_deletion_onchain.return_value = {"ok": False, "declared": False, "confirmed": False}
    mod.PJ.unresolved_deletions.return_value = [_item("0xa"), _item("0xb")]

    mod.reconcile_pending_piece_deletions()

    assert counts == {"0xa": 1, "0xb": 1}


def test_declared_on_chain_stops_secret_redrive(da):
    """DECLARED: once the chain shows declared, the secret-bearing re-drive stops; the
    entry stays pending for confirmation polling (no re-drive, no dispute)."""
    mod, dr = da
    calls = []
    mod.CH.redrive_deletion_request = lambda peer, ch, secret: calls.append(1) or {}
    mod.CH.verify_deletion_onchain.return_value = {"ok": False, "declared": True, "confirmed": False}
    mod.PJ.unresolved_deletions.return_value = [_item()]

    mod.reconcile_pending_piece_deletions()

    assert calls == [], "declared deletions must NOT be re-driven with the secret"
    assert mod.PJ.mark_deletion_pending.called
    assert not mod.PJ.mark_deletion_disputed.called  # not grace-expired yet


def test_terminal_stops_redrive_without_dispute(da):
    """TERMINAL: an explicit permanent rejection stops the re-drive and marks failed
    WITHOUT raising a dispute (the deletion was never declared)."""
    mod, dr = da
    mod.CH.redrive_deletion_request = lambda peer, ch, secret: {
        "ok": False, "terminal": True, "error": "invalid deletion authorization secret"}
    mod.CH.verify_deletion_onchain.return_value = {"ok": False, "declared": False, "confirmed": False}
    mod.PJ.unresolved_deletions.return_value = [_item()]

    mod.reconcile_pending_piece_deletions()

    assert mod.PJ.mark_deletion_failed.called
    assert not mod.PJ.mark_deletion_disputed.called
    assert not mod.PJ.mark_deletion_confirmed.called


def test_monitor_single_flight_guard(da):
    """Bullet 1 (orchestration): overlapping schedule calls start only ONE monitor, so a
    deletion is not re-driven by two concurrent monitors."""
    mod, dr = da
    mod.PJ.unresolved_deletions.return_value = [_item()]
    started = []
    with mock.patch.object(mod.threading, "Thread") as Thread:
        Thread.return_value.start.side_effect = lambda: started.append(1)
        # First schedule: flag is False + unresolved non-empty -> starts one monitor.
        mod._PENDING_DELETION_MONITOR_RUNNING = False
        mod._schedule_pending_deletion_reconciliation()
        # Second schedule while the first is "running": must be a no-op.
        mod._schedule_pending_deletion_reconciliation()
    assert Thread.call_count == 1, "a second overlapping schedule must not start another monitor"
