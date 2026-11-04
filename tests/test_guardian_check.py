"""A guardian chosen from discovery's directory is checked field by field on chain.

Discovery nodes are not trusted. The directory decides which guardians are
ranked best, so every figure a guardian was chosen on -- reputation, price,
stake, failures, complaints, proof penalties, availability -- is read again
from the chain before the guardian is staged. A listed figure better than the
chain's means the list was stale or dishonest, and the guardian is refused. On
success the row holds the chain's values from then on.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path
import pytest

DO_ROOT = Path(__file__).resolve().parents[1]
if str(DO_ROOT) not in sys.path:
    sys.path.insert(0, str(DO_ROOT))

os.environ["DO_CONFIG_PATH"] = str(Path(__file__).with_name("config.selection.test.json"))

from core import do_network as N

ADDRESS = "0x00000000000000000000000000000000000003e9"


class Call:
    def __init__(self, value=None, error=None):
        self.value, self.error = value, error

    def call(self):
        if self.error:
            raise self.error
        return self.value


def chain(active=True, reputation=7000, stake=10**18, failed=0, complaints=0,
          penalties=0, pre_bad=0, prices=(10, 20, 30, 40), max_days=90, error=None):
    profile = [ADDRESS, b"k", 0, 0, "", 1, 2, 3, stake, reputation, 5, failed, 0, active, 1, 2]
    registry = types.SimpleNamespace(functions=types.SimpleNamespace(
        isActiveGuardian=lambda a: Call(active, error),
        getGuardian=lambda a: Call(profile, error),
        minStake=lambda: Call(10**18, error),
        getGuardianServiceInfo=lambda a: Call([*prices, max_days, True], error),
    ))
    reputation_manager = types.SimpleNamespace(functions=types.SimpleNamespace(
        getGuardianStats=lambda a: Call([reputation, 0, 0, 0, 0, complaints, 0, 0, 3, 0]),
        getTotalShareProofPenalties=lambda a: Call(penalties),
    ))
    share_proof = types.SimpleNamespace(functions=types.SimpleNamespace(lastProofAt=lambda a: Call(4)))
    telg = types.SimpleNamespace(functions=types.SimpleNamespace(preBadPartialCount=lambda a: Call(pre_bad)))
    return registry, reputation_manager, share_proof, telg


def install(monkeypatch, **kw):
    registry, rep, proof, telg = chain(**kw)
    monkeypatch.setattr(N.C, "guardian_registry", registry, raising=False)
    monkeypatch.setattr(N.C, "reputation_manager", rep, raising=False)
    monkeypatch.setattr(N.C, "guardian_share_proof", proof, raising=False)
    monkeypatch.setattr(N.C, "telg_v2", telg, raising=False)
    monkeypatch.setattr(N.C, "w3", types.SimpleNamespace(to_checksum_address=lambda a: a), raising=False)
    monkeypatch.setattr(N, "get_service_duration_days", lambda default=30: 30)


def listed(**over) -> dict:
    """The row as the directory gave it, matching the default chain above."""
    row = {"address": ADDRESS, "reputation": 7000, "stake": 10**18, "failed": 0,
           "dkg_complaints": 0, "total_proof_penalties": 0, "pre_bad_partial": 0,
           "dkg_material_su": 10, "dkg_share_key_su": 20, "pre_batch_partial_su": 30,
           "daily_share_custody_su": 40,
           "total_su": 10 + 20 + 30 + 30 * 40, "max_service_days": 90}
    row.update(over)
    return row


def test_a_truthful_listing_passes_and_the_row_takes_the_chain_values(monkeypatch):
    install(monkeypatch)
    row = listed()
    ok, reason = N._verify_guardian_before_use(row)
    assert ok, reason
    assert row["last_proof_at"] == 4 and row["last_activity_at"] == 3
    assert row["price_source"] == "guardian"


def test_an_inactive_guardian_is_refused(monkeypatch):
    install(monkeypatch, active=False)
    ok, reason = N._verify_guardian_before_use(listed())
    assert not ok and "not active" in reason


def test_an_overstated_reputation_is_refused(monkeypatch):
    install(monkeypatch, reputation=3000)
    ok, reason = N._verify_guardian_before_use(listed(reputation=9000))
    assert not ok and "reputation overstated" in reason


def test_an_understated_price_is_refused(monkeypatch):
    install(monkeypatch, prices=(10, 20, 30, 400))
    ok, reason = N._verify_guardian_before_use(listed())
    assert not ok and "price understated" in reason


def test_a_list_loaded_for_other_service_days_is_not_refused(monkeypatch):
    """The total depends on the days; only the unit prices are compared."""
    install(monkeypatch)
    ok, reason = N._verify_guardian_before_use(listed(total_su=10 + 20 + 30 + 7 * 40))
    assert ok, reason


def test_an_overstated_stake_is_refused(monkeypatch):
    install(monkeypatch, stake=10**18)
    ok, reason = N._verify_guardian_before_use(listed(stake=5 * 10**18))
    assert not ok and "stake overstated" in reason


def test_hidden_failures_complaints_or_penalties_are_refused(monkeypatch):
    for kw, key in (({"failed": 3}, "failed"), ({"complaints": 2}, "dkg_complaints"),
                    ({"penalties": 1}, "total_proof_penalties"), ({"pre_bad": 1}, "pre_bad_partial")):
        install(monkeypatch, **kw)
        ok, reason = N._verify_guardian_before_use(listed())
        assert not ok and key in reason, (kw, reason)


def test_a_guardian_not_available_for_the_service_days_is_refused(monkeypatch):
    install(monkeypatch, max_days=10)
    ok, reason = N._verify_guardian_before_use(listed())
    assert not ok and "service days" in reason


def test_a_chain_that_cannot_be_reached_refuses_rather_than_trusts(monkeypatch):
    install(monkeypatch, error=ConnectionError("refused"))
    ok, reason = N._verify_guardian_before_use(listed())
    assert not ok and "chain check failed" in reason


def test_a_listing_worse_than_the_chain_is_fine(monkeypatch):
    """Being listed as worse than you are is no reason to refuse you."""
    install(monkeypatch)
    ok, reason = N._verify_guardian_before_use(
        listed(reputation=6000, total_su=99999, stake=1, daily_share_custody_su=999)
    )
    assert ok, reason


def test_bond_reduced_stake_refreshes_but_requires_a_second_selection(monkeypatch):
    install(monkeypatch, stake=1007000000000000000)
    row=listed(stake=1008000000000000000)
    ok,reason=N._verify_guardian_before_use(row)
    assert not ok and 'repeat selection' in reason
    assert row['stake']==1007000000000000000
    assert N._verify_guardian_before_use(row)==(True,'ok')


def test_stake_refresh_retains_penalties_and_refuses_the_old_choice(monkeypatch):
    install(monkeypatch, stake=10**18, penalties=1)
    row = listed(stake=1008000000000000000)
    ok, message = N._verify_guardian_before_use(row)
    assert not ok and N.guardian_record_was_refreshed(message)
    assert row['stake'] == 10**18
    assert row['total_proof_penalties'] == 1


def test_insufficient_stake_is_never_refreshed_into_acceptance(monkeypatch):
    install(monkeypatch, stake=10**18-1)
    for stake in (1008000000000000000, 10**18-1):
        row = listed(stake=stake)
        ok, message = N._verify_guardian_before_use(row)
        assert not ok and message == 'insufficient on-chain stake'
        assert row['stake'] == stake


def test_stake_refresh_requires_a_successful_minimum_read(monkeypatch):
    install(monkeypatch,stake=10**18)
    monkeypatch.setattr(N.C.guardian_registry.functions,'minStake',lambda:Call(error=ConnectionError('unavailable')))
    row=listed(stake=1008000000000000000)
    assert N._verify_guardian_before_use(row)[0] is False
    assert row['stake']==1008000000000000000


@pytest.mark.parametrize('field,chain_kw,value', [
    ('failed', 'failed', 1), ('dkg_complaints', 'complaints', 2),
    ('total_proof_penalties', 'penalties', 3), ('pre_bad_partial', 'pre_bad', 4),
    ('reputation', 'reputation', 3000),
])
def test_changed_history_requires_reselection_and_retains_chain_facts(monkeypatch, field, chain_kw, value):
    install(monkeypatch, **{chain_kw: value})
    row = listed()
    ok, reason = N._verify_guardian_before_use(row)
    assert not ok and N.guardian_record_was_refreshed(reason)
    assert row[field] == value
    assert N._verify_guardian_before_use(row) == (True, 'ok')


def test_changed_prices_are_shown_before_the_next_selection(monkeypatch):
    install(monkeypatch, prices=(11, 22, 33, 44))
    row = listed()
    ok, reason = N._verify_guardian_before_use(row)
    assert not ok and N.guardian_record_was_refreshed(reason)
    assert row['dkg_material_su'] == 11
    assert row['daily_share_custody_su'] == 44


def test_manual_selection_shows_updated_failures_and_does_not_stage_them(monkeypatch):
    from core import do_actions as actions
    from unittest.mock import Mock
    install(monkeypatch, failed=1)
    row = listed()
    monkeypatch.setattr(N.S, 'guardian_display_records', [row])
    monkeypatch.setattr(N.S, 'staged_guardians', [ADDRESS])
    monkeypatch.setattr(N, 'get_selected_guardians', lambda: [ADDRESS])
    render, warning = Mock(), Mock()
    monkeypatch.setattr(N, '_render_guardian_records', render)
    monkeypatch.setattr(actions.L, 'show_warning', warning)
    monkeypatch.setattr(actions.L, 'log', lambda *a: None)
    actions.add_selected_guardians_to_policy()
    assert row['failed'] == 1
    assert N.S.staged_guardians == []
    render.assert_called_once()
    warning.assert_called_once()


def test_watched_folder_retries_the_same_file_after_selection_wait(monkeypatch, tmp_path):
    from core import do_actions as actions
    source = tmp_path / 'original.bin'
    source.write_bytes(b'original contents')
    key, snapshot, now = str(source), [17, 1], [100.0]
    monkeypatch.setattr(actions, 'time', types.SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(actions.C, 'config', types.SimpleNamespace(DROP_FOLDER_STABLE_SECONDS=5))
    monkeypatch.setattr(actions, '_drop_folder_path', lambda: tmp_path)
    monkeypatch.setattr(actions, '_skip_drop_child', lambda p: False)
    monkeypatch.setattr(actions, '_path_upload_snapshot', lambda p: snapshot)
    monkeypatch.setattr(actions, '_path_file_inventory', lambda p: {})
    monkeypatch.setattr(actions, '_find_matching_drop_upload_record_for_live_item', lambda *a: False)
    for attr, value in dict(drop_folder_current_item=key, drop_folder_seen={key: snapshot},
                            drop_folder_pending={}, drop_folder_inventory={}, drop_folder_queue=[],
                            drop_folder_status_var=None).items():
        monkeypatch.setattr(actions.S, attr, value)
    monkeypatch.setattr(actions.L, 'log', lambda *a: None)
    monkeypatch.setattr(actions.L, 'set_status', lambda *a: None)
    actions._guardian_selection_waiting(N.GuardianSelectionPending('records changed'))
    assert key not in actions.S.drop_folder_seen
    monkeypatch.setattr(actions.S, 'drop_folder_current_item', '')
    actions._scan_drop_folder_once()
    assert actions.S.drop_folder_queue == []
    now[0] = 136.0
    actions._scan_drop_folder_once()
    actions._scan_drop_folder_once()
    assert actions.S.drop_folder_queue == [key]
    assert source.read_bytes() == b'original contents'
