"""The VK and Guardian tables, and automatic selection, come from discovery.

Before, the DO asked the chain about every keeper and guardian -- about eight
calls each, plus a request to every keeper -- on every table load and every
upload, repeated by every Data Owner for the same public answer. Now discovery
reads the network once a minute and serves it as one compact document; the DO
holds a copy, asks only for what changed, and checks against the chain only the
few keepers and guardians it actually chooses.
"""
from __future__ import annotations

import inspect
import json
import os
import sys
import types
from pathlib import Path

DO_ROOT = Path(__file__).resolve().parents[1]
if str(DO_ROOT) not in sys.path:
    sys.path.insert(0, str(DO_ROOT))

os.environ["DO_CONFIG_PATH"] = str(Path(__file__).with_name("config.selection.test.json"))

from core import do_directory as D
from core import do_network as N

VK_COLUMNS = [
    "address", "peerId", "multiaddr", "location", "lat", "lon",
    "storageFee", "stake", "active", "registeredAt", "lastHeartbeat",
    "suspendedUntil", "maxServiceDays", "maxPieceSizeBytes",
    "admissionClosed", "admissionClosureReason", "reportedFreeBytes",
    "reputation", "penaltyPoints", "disputeCount", "missedProofs",
    "lastActivityAt", "completedPieces", "lastProofAt",
    "declaredBytes", "registeredFreeBytes", "registeredDataBytes",
    "provedFreeBytes", "provedDataBytes", "conservativeFreeBytes",
    "capacityProofFresh",
]
G_COLUMNS = [
    "address", "active", "stake", "reputation", "completedJobs", "failedJobs",
    "disputes", "dkgFee", "telgFee", "refreshFee", "registeredAt",
    "lastHeartbeat", "pricingSet", "dkgMaterialSu", "dkgShareKeySu",
    "preBatchPartialSu", "dailyShareCustodySu", "maxServiceDays",
    "lastProofAt", "totalProofPenalties", "dkgComplaints", "lastActivityAt",
    "preBadPartial",
]
META = {"blockNumber": 9, "blockTimestamp": 0, "vaultKeeperCount": 0, "guardianCount": 0,
        "vaultKeeperMinStake": 10**18, "guardianMinStake": 10**18,
        "admissionMarginBytes": 1024, "guardianProofPeriodSeconds": 3600,
        "sources": {"capacityProof": 1}}


def vk(i: int, **over) -> list:
    v = {c: 0 for c in VK_COLUMNS}
    v.update({
        "address": f"0x{i:040x}", "peerId": f"12D3KooWpeer{i}",
        "multiaddr": f"/ip4/127.0.0.1/tcp/{4100 + i}/p2p/12D3KooWpeer{i}",
        "location": "Germany, Berlin", "storageFee": 6000 + i, "stake": 10**18, "active": 1,
        "maxServiceDays": 30, "reportedFreeBytes": 100 * 1024 * 1024, "reputation": 5000 + i,
    })
    v.update(over)
    return [v[c] for c in VK_COLUMNS]


def g(i: int, **over) -> list:
    v = {c: 0 for c in G_COLUMNS}
    v.update({"address": f"0x{1000 + i:040x}", "active": 1, "stake": 10**18,
              "reputation": 7000 + i, "pricingSet": 1, "dkgMaterialSu": 10,
              "dkgShareKeySu": 20, "preBatchPartialSu": 30, "dailyShareCustodySu": 40})
    v.update(over)
    return [v[c] for c in G_COLUMNS]


def full_doc(vks: list, gs: list, version: int = 1, epoch: str = "e1") -> dict:
    return {"format": 1, "node": "n", "epoch": epoch, "version": version, "refreshedAt": 1,
            "full": True, "authoritative": False, "meta": META,
            "vkColumns": VK_COLUMNS, "vk": vks, "gColumns": G_COLUMNS, "g": gs}


class FakeDiscovery:
    """Answers D._get by URL; records what was asked."""

    def __init__(self):
        self.answers: dict[str, list] = {}
        self.asked: list[str] = []

    def __call__(self, url: str):
        self.asked.append(url)
        for prefix, queue in self.answers.items():
            if url.startswith(prefix) and queue:
                answer = queue.pop(0)
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise ConnectionError("unreachable")


LIVE = {"totalCapacityBytes": 10_000, "usedBytes": 3_000, "freeBytes": 6_000,
        "admissionFreeBytes": 5_000, "admissionMarginBytes": 1_000}


def reset_directory(monkeypatch, tmp_path, urls=("http://d1", "http://d2"), live=None) -> FakeDiscovery:
    from core import do_vaultmesh
    # Each keeper's own live capacity report (VaultMesh info protocol).
    monkeypatch.setattr(do_vaultmesh, "get_vk_info", lambda peer: dict(LIVE if live is None else live(peer)))
    fake = FakeDiscovery()
    monkeypatch.setattr(D, "_get", fake)
    monkeypatch.setattr(D, "_discovery_urls", lambda: list(urls))
    monkeypatch.setattr(D, "CACHE_PATH", tmp_path / "directory_cache.json")
    monkeypatch.setattr(D, "_asked_at", 0.0)
    monkeypatch.setattr(D, "_disk_loaded", False)
    monkeypatch.setattr(D, "_state", {
        "node": "", "epoch": "", "version": 0, "refreshedAt": 0, "meta": {},
        "vkColumns": [], "gColumns": [], "vk": {}, "g": {},
    })
    return fake


# --- the local copy --------------------------------------------------------


def test_the_first_refresh_takes_the_full_document(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1), vk(2)], [g(1)]))]
    assert D.refresh(force=True)
    assert len(D.keepers()) == 2 and len(D.guardians()) == 1
    assert D.keepers()[0]["reputation"] == 5001
    assert D.meta()["admissionMarginBytes"] == 1024


def test_holding_a_version_asks_only_for_changes_and_takes_304(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1)], []))]
    D.refresh(force=True)
    fake.answers["http://d1/v1/directory?since=1&epoch=e1"] = [(304, None)]
    assert D.refresh(force=True)
    assert fake.asked[-1] == "http://d1/v1/directory?since=1&epoch=e1"


def test_a_delta_updates_only_the_changed_rows(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1), vk(2)], [g(1)]))]
    D.refresh(force=True)
    delta = {"epoch": "e1", "version": 2, "since": 1, "full": False, "refreshedAt": 2, "meta": META,
             "vk": [vk(2, reputation=1)], "g": [], "removedVk": [], "removedG": [g(1)[0]]}
    fake.answers["http://d1/v1/directory?since=1&epoch=e1"] = [(200, delta)]
    D.refresh(force=True)
    by_addr = {k["address"]: k for k in D.keepers()}
    assert by_addr[vk(2)[0]]["reputation"] == 1
    assert by_addr[vk(1)[0]]["reputation"] == 5001
    assert D.guardians() == []


def test_a_delta_that_does_not_fit_is_replaced_by_a_full_read(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1)], []))]
    D.refresh(force=True)
    wrong = {"epoch": "e1", "version": 5, "since": 3, "full": False, "meta": META,
             "vk": [], "g": [], "removedVk": [], "removedG": []}
    fake.answers["http://d1/v1/directory?since=1&epoch=e1"] = [(200, wrong)]
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1), vk(3)], [], version=5))]
    D.refresh(force=True)
    assert len(D.keepers()) == 2


def test_a_node_that_is_not_ready_is_skipped_for_the_next(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(503, None)]
    fake.answers["http://d2/v1/directory"] = [(200, full_doc([vk(1)], []))]
    assert D.refresh(force=True)
    assert len(D.keepers()) == 1


def test_an_unreachable_discovery_keeps_the_copy_held(monkeypatch, tmp_path):
    """Losing contact with discovery must not read as "there are no keepers"."""
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1), vk(2)], []))]
    D.refresh(force=True)
    assert D.refresh(force=True) is True
    assert len(D.keepers()) == 2


def test_a_restarted_do_starts_from_its_copy_on_disk(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1), vk(2)], [g(1)]))]
    D.refresh(force=True)
    assert json.loads((tmp_path / "directory_cache.json").read_text())["version"] == 1

    fake = reset_directory(monkeypatch, tmp_path)  # memory gone, disk kept
    fake.answers["http://d1/v1/directory?since=1&epoch=e1"] = [(304, None)]
    assert D.refresh(force=True)
    assert len(D.keepers()) == 2
    assert fake.asked == ["http://d1/v1/directory?since=1&epoch=e1"], "only the changes are asked for"


def test_tables_reloading_often_ask_discovery_at_most_once_per_ttl(monkeypatch, tmp_path):
    fake = reset_directory(monkeypatch, tmp_path)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc([vk(1)], []))]
    D.refresh()
    for _ in range(5):
        D.refresh()
    assert len(fake.asked) == 1


def test_no_directory_anywhere_is_an_error_not_an_empty_network(monkeypatch, tmp_path):
    reset_directory(monkeypatch, tmp_path)
    assert D.refresh(force=True) is False
    monkeypatch.setattr(N, "get_service_duration_days", lambda default=30: 30)
    try:
        N._vk_rows_from_directory()
    except RuntimeError as exc:
        assert "discovery" in str(exc).lower()
    else:
        raise AssertionError("an empty table would look like a network with no keepers")


# --- rows ------------------------------------------------------------------


def install_rows(monkeypatch, tmp_path, vks, gs=(), live=None):
    fake = reset_directory(monkeypatch, tmp_path, live=live)
    fake.answers["http://d1/v1/directory"] = [(200, full_doc(list(vks), list(gs)))]
    D.refresh(force=True)
    monkeypatch.setattr(N.C, "w3", types.SimpleNamespace(to_checksum_address=lambda a: a), raising=False)
    monkeypatch.setattr(N, "_current_estimated_vk_piece_size", lambda: 0)
    monkeypatch.setattr(N, "get_service_duration_days", lambda default=30: 30)


def test_rows_carry_reputation_and_proofs_with_no_chain_read(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [vk(1, completedPieces=7, lastProofAt=123, penaltyPoints=2)])
    monkeypatch.setattr(N.C, "vault_keeper_registry", None, raising=False)
    monkeypatch.setattr(N.C, "reputation_manager", None, raising=False)
    row = N._vk_rows_from_directory()[0]
    assert row["reputation"] == 5001 and row["completedPieces"] == 7
    assert row["lastProofAt"] == 123 and row["penaltyPoints"] == 2
    assert row["eligible"] and row["admissionOpen"]
    assert row["location"] == "Germany, Berlin"
    assert row["discoverySource"] == "directory"


def test_inactive_suspended_or_understaked_keepers_are_not_eligible(monkeypatch, tmp_path):
    import time as _t
    install_rows(monkeypatch, tmp_path, [
        vk(1, active=0), vk(2, suspendedUntil=int(_t.time()) + 3600), vk(3, stake=1), vk(4),
    ])
    rows = {r["address"]: r for r in N._vk_rows_from_directory()}
    assert rows[vk(1)[0]]["eligibilityReason"] == "inactive"
    assert rows[vk(2)[0]]["eligibilityReason"] == "suspended"
    assert "stake below minimum" in rows[vk(3)[0]]["eligibilityReason"]
    assert rows[vk(4)[0]]["eligible"]
    assert not any(rows[vk(i)[0]]["admissionOpen"] for i in (1, 2, 3))


def test_a_closed_admission_is_not_open(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [vk(1, admissionClosed=1)])
    row = N._vk_rows_from_directory()[0]
    assert row["eligible"] and not row["admissionOpen"]


def test_free_space_comes_live_from_each_keeper_not_the_chain_ledger(monkeypatch, tmp_path):
    """The ledger only moves at each capacity proof; on a fresh chain it is zero.

    Taking free space from it made every keeper look full and stopped every
    upload. Capacity is the keeper's own live report, as it always was.
    """
    install_rows(monkeypatch, tmp_path, [vk(1, declaredBytes=0, conservativeFreeBytes=0, reportedFreeBytes=0)])
    row = N._vk_rows_from_directory()[0]
    assert row["totalCapacityBytes"] == 10_000 and row["usedBytes"] == 3_000
    assert row["freeBytes"] == 6_000
    assert row["admissionFreeBytes"] == 5_000 and row["admissionMarginBytes"] == 1_000
    assert row["admissionAllocatableBytes"] == 5_000
    assert row["admissionOpen"] is True


def test_a_keeper_that_reports_itself_closed_is_not_open(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [vk(1)], live=lambda peer: dict(LIVE, admissionClosed=True))
    row = N._vk_rows_from_directory()[0]
    assert row["admissionClosedLocal"] is True and row["admissionOpen"] is False


def test_a_keeper_that_does_not_answer_has_unknown_capacity(monkeypatch, tmp_path):
    """Zero total capacity is what the load test reads as "unknown", not "full"."""
    install_rows(monkeypatch, tmp_path, [vk(1)], live=lambda peer: {})
    row = N._vk_rows_from_directory()[0]
    assert row["totalCapacityBytes"] == 0 and row["freeBytes"] == 0


def test_every_listed_keeper_is_asked_for_its_live_capacity(monkeypatch, tmp_path):
    asked = []
    install_rows(monkeypatch, tmp_path, [vk(i) for i in range(1, 6)] + [vk(9, multiaddr="")],
                 live=lambda peer: asked.append(peer) or dict(LIVE))
    N._vk_rows_from_directory()
    assert len(asked) == 5, "every keeper with an address, and none without"


def test_no_capacity_contract_means_no_ledger_keys_not_zeros(monkeypatch, tmp_path):
    """The load tester reads a missing ledger as "unknown" and zeros as "converged"."""
    fake = reset_directory(monkeypatch, tmp_path)
    doc = full_doc([vk(1)], [])
    doc["meta"] = dict(META, sources={"capacityProof": 0})
    fake.answers["http://d1/v1/directory"] = [(200, doc)]
    D.refresh(force=True)
    monkeypatch.setattr(N.C, "w3", types.SimpleNamespace(to_checksum_address=lambda a: a), raising=False)
    monkeypatch.setattr(N, "_current_estimated_vk_piece_size", lambda: 0)
    monkeypatch.setattr(N, "get_service_duration_days", lambda default=30: 30)
    row = N._vk_rows_from_directory()[0]
    assert "provedFreeBytes" not in row and "registeredDataBytes" not in row


def test_guardians_without_own_prices_use_the_defaults(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [], [g(1), g(2, pricingSet=0, maxServiceDays=5)])
    monkeypatch.setattr(N, "_reward_default_su", lambda name: 1)
    records = {r["address"]: r for r in (N._guardian_record_from_directory(e, 30) for e in D.guardians())}
    own = records[g(1)[0]]
    assert own["price_source"] == "guardian" and own["total_su"] == 10 + 20 + 30 + 30 * 40
    default = records[g(2)[0]]
    assert default["price_source"] == "default" and default["max_service_days"] == 0
    assert default["total_su"] == 1 + 1 + 1 + 30 * 1


# --- selection -------------------------------------------------------------


def test_headless_selection_uses_the_directory_and_verifies_only_the_chosen(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [vk(i) for i in range(1, 11)])
    monkeypatch.setattr(N.S, "vault_keepers_listbox", None)
    monkeypatch.setattr(N, "_estimated_vk_piece_sizes", lambda n, t: ([0], "test"))
    monkeypatch.setattr(N, "_selected_vk_cost_estimate", lambda rows: {"ok": False, "reason": "test"})
    monkeypatch.setattr(N, "_log_selected_vk_cost_estimate", lambda e: None)
    monkeypatch.setattr(N, "refresh_ida_info", lambda: None)
    verified: list[str] = []

    def verify(row, required_piece_size=None, service_days=None):
        verified.append(row["address"])
        assert service_days == 30, "the chain check must judge the keeper for this upload's days"
        return True, "ok"

    monkeypatch.setattr(N, "_verify_vk_before_paying", verify)
    monkeypatch.setattr(N, "load_vault_keepers",
                        lambda: (_ for _ in ()).throw(AssertionError("no table to load headless")))

    peers = N.select_best_vault_keepers(count=4, threshold=3, service_days=30)
    assert len(peers) == 4
    assert len(verified) == 4, "only the keepers actually chosen are checked on chain"


def test_headless_guardian_selection_loads_records_and_verifies_the_chosen(monkeypatch, tmp_path):
    install_rows(monkeypatch, tmp_path, [], [g(i) for i in range(1, 8)])
    monkeypatch.setattr(N.S, "guardians_listbox", None)
    monkeypatch.setattr(N, "set_auto_defaults", lambda **k: None)
    refused = g(7)[0]

    def verify(row, service_days=None):
        return (False, "reputation overstated") if row["address"] == refused else (True, "ok")

    monkeypatch.setattr(N, "_verify_guardian_before_use", verify)
    chosen = N.select_best_guardians(count=5, threshold=3, service_days=30)
    assert len(chosen) == 5
    assert refused not in chosen, "the best-ranked guardian the chain disagrees about is replaced"


def test_the_table_loaders_make_no_chain_read_per_entry():
    for fn in (N.load_vault_keepers, N.load_guardians, N._vk_row_from_directory,
               N._guardian_record_from_directory):
        source = inspect.getsource(fn)
        assert ".functions." not in source, f"{fn.__name__} must not read the chain"


def test_auto_selection_reranks_after_a_stake_snapshot_changes(monkeypatch,tmp_path):
    install_rows(monkeypatch,tmp_path,[],[g(1,stake=3*10**18,reputation=7000),g(2,stake=2*10**18,reputation=7000)])
    monkeypatch.setattr(N.S,'guardians_listbox',None)
    monkeypatch.setattr(N,'set_auto_defaults',lambda **kw:None)
    checks=[]
    def verify(row,service_days=None):
        checks.append(row['address'])
        if row['address']==g(1)[0] and row['stake']!=10**18:
            row['stake']=10**18
            return False,'stake overstated; current chain row refreshed; repeat selection'
        return True,'ok'
    monkeypatch.setattr(N,'_verify_guardian_before_use',verify)
    assert N.select_best_guardians(count=1,threshold=1,service_days=30)==[g(2)[0]]
    assert checks.count(g(1)[0])==2
