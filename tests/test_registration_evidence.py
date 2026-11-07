"""Ordinary read-only registration recovery and confirmation regressions."""
import copy
from types import SimpleNamespace

import pytest
from hexbytes import HexBytes
from web3 import Web3
from web3.datastructures import AttributeDict

from core.do_registration_evidence import (
    RegistrationEvidenceUnavailable, recover_registration_transaction,
)


def digest(number):
    return HexBytes(number.to_bytes(32, "big"))


class Views:
    chain_id = 31337

    def __init__(self):
        self.address = "0x" + "11" * 20
        self.vk = "0x" + "22" * 20
        self.commitment, self.sector = digest(33), digest(44)
        self.tx = digest(55)
        self.reads, self.queries = [], []
        self.reorg = False
        self.receipt = {"chainId": self.chain_id, "commitmentHash": self.commitment.hex(),
                        "sectorRoot": self.sector.hex(), "vkAddress": self.vk,
                        "deadlineIndex": 1, "partitionIndex": 2, "serviceEnd": 2_000_000_000}
        self.record = [self.sector, digest(0), self.vk, 1, 2, 2_000_000_000, 1010, True, digest(0)]
        self.log = {"address": self.address, "topics": [
            Web3.keccak(text="FileStorageRegistered(bytes32,bytes32,address,uint8,uint8,uint64)"),
            self.commitment, self.sector, HexBytes("0x" + "00" * 12 + "22" * 20)],
            "data": HexBytes(b"".join(n.to_bytes(32, "big") for n in (1, 2, 2_000_000_000))),
            "blockNumber": 21, "blockHash": digest(22), "transactionHash": self.tx,
            "logIndex": 0, "removed": False}
        self.logs = [self.log]
        self.mined = {"transactionHash": self.tx, "status": 1, "to": self.address,
                      "blockNumber": 21, "blockHash": digest(22), "logs": [self.log]}
        self.functions = self
        self.eth = self

    def getRecord(self, commitment):
        assert bytes(commitment) == self.commitment
        return SimpleNamespace(call=lambda **_: self.record)

    def get_block(self, number):
        self.reads.append(number)
        if number == "latest":
            number = 63
        changed = self.reorg and number == 63 and self.reads.count(63) > 0
        return {"number": number, "hash": digest(number + (2 if changed else 1)),
                "timestamp": 1000 + number // 2}

    def get_logs(self, query):
        self.queries.append(query)
        return self.logs

    def get_transaction_receipt(self, tx):
        assert tx.lower().removeprefix("0x") == self.tx.hex().removeprefix("0x")
        return AttributeDict.recursive(self.mined)


def recover(view):
    return recover_registration_transaction(view, view, view.receipt)


def test_missing_hash_recovers_exact_receipt_without_replaying_history():
    view = Views()
    original = copy.deepcopy(view.receipt)
    assert recover(view) == "0x" + bytes(view.tx).hex()
    assert view.receipt == original, "original receipt is never rewritten"
    assert len(view.reads) < 25
    assert len(view.queries) == 1
    query = view.queries[0]
    assert (query["fromBlock"], query["toBlock"]) == (20, 21)
    assert query["address"] == view.address
    assert query["topics"][1] == "0x" + bytes(view.commitment).hex()


@pytest.mark.parametrize("change", ["chain", "vk", "sector", "deadline", "service", "removed",
                                   "wrong_contract", "wrong_commitment", "reverted", "missing_receipt",
                                   "receipt_hash", "receipt_block", "log_fork", "receipt_log", "no_logs"])
def test_uncertain_or_unrelated_evidence_never_completes(change):
    view = Views()
    if change == "chain": view.receipt["chainId"] += 1
    elif change == "vk": view.receipt["vkAddress"] = "0x" + "88" * 20
    elif change == "sector": view.receipt["sectorRoot"] = digest(99)
    elif change == "deadline": view.receipt["deadlineIndex"] = 3
    elif change == "service": view.receipt["serviceEnd"] += 1
    elif change == "removed": view.log["removed"] = True
    elif change == "wrong_contract": view.log["address"] = "0x" + "88" * 20
    elif change == "wrong_commitment": view.log["topics"][1] = digest(99)
    elif change == "reverted": view.mined["status"] = 0
    elif change == "missing_receipt": view.mined = None
    elif change == "receipt_hash": view.mined["transactionHash"] = digest(99)
    elif change == "receipt_block": view.mined["blockHash"] = digest(99)
    elif change == "log_fork": view.log["blockHash"] = digest(99)
    elif change == "receipt_log": view.mined["logs"] = []
    elif change == "no_logs": view.logs = []
    with pytest.raises(RegistrationEvidenceUnavailable): recover(view)


def test_conflicting_registration_events_and_changed_snapshot_are_rejected():
    view = Views()
    second = {**view.log, "transactionHash": digest(66), "logIndex": 1}
    view.logs = [view.log, second]
    def receipt(tx):
        event = view.log if tx.endswith(bytes(view.tx).hex()) else second
        return {**view.mined, "transactionHash": event["transactionHash"], "logs": [event]}
    view.get_transaction_receipt = receipt
    with pytest.raises(RegistrationEvidenceUnavailable, match="one exact"):
        recover(view)
    view = Views(); view.reorg = True
    with pytest.raises(RegistrationEvidenceUnavailable, match="snapshot changed"):
        recover(view)


def test_rpc_failure_stays_a_failure():
    view = Views()
    def unavailable(_): raise ConnectionError("read unavailable")
    view.get_logs = unavailable
    with pytest.raises(ConnectionError): recover(view)


def test_oversized_timestamp_bucket_stays_pending_without_a_broad_log_scan():
    view = Views()
    view.get_block = lambda n: {"number": 4095 if n == "latest" else n,
                               "hash": digest((4095 if n == "latest" else n) + 1),
                               "timestamp": 1010}
    with pytest.raises(RegistrationEvidenceUnavailable, match="too large"):
        recover(view)
    assert not view.queries
