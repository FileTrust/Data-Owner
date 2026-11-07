"""Recover public registration evidence without resending storage or payments.

The record's registeredAt timestamp bounds the lookup. Binary searches locate
that timestamp's blocks; only its indexed registration logs are requested.
No wallet, configuration, journal or private receipt is changed by this module.
"""
from web3 import Web3


class RegistrationEvidenceUnavailable(RuntimeError):
    pass


def _hex(value, size):
    if isinstance(value, str):
        raw = value.removeprefix("0x")
        try:
            result = bytes.fromhex(raw)
        except ValueError:
            raise RegistrationEvidenceUnavailable("invalid registration evidence hex") from None
    else:
        try:
            result = bytes(value)
        except (ValueError, TypeError):
            raise RegistrationEvidenceUnavailable("invalid registration evidence bytes") from None
    if len(result) != size:
        raise RegistrationEvidenceUnavailable("invalid registration evidence length")
    return "0x" + result.hex()


def _field(value, name, index):
    if isinstance(value, dict):
        return value[name]
    if hasattr(value, name):
        return getattr(value, name)
    return value[index]


def recover_registration_transaction(w3, contract, receipt):
    """Return one canonically mined, exact matching registration transaction.

    A candidate hash is never proof by itself. Callers still perform their
    normal signed-receipt, event, record, partition and storage-proof checks.
    Failed reads propagate; missing/ambiguous evidence leaves the piece pending.
    """
    chain_id = int(receipt["chainId"])
    if chain_id <= 0 or int(w3.eth.chain_id) != chain_id:
        raise RegistrationEvidenceUnavailable("registration belongs to a different chain")
    address = _hex(contract.address, 20)
    commitment = _hex(receipt["commitmentHash"], 32)
    sector = _hex(receipt["sectorRoot"], 32)
    vk = _hex(receipt["vkAddress"], 20)
    deadline, partition, service_end = (
        int(receipt[name]) for name in ("deadlineIndex", "partitionIndex", "serviceEnd")
    )
    if not (0 <= deadline <= 255 and 0 <= partition <= 255 and 0 < service_end < 2**64):
        raise RegistrationEvidenceUnavailable("invalid registration event fields")

    head = w3.eth.get_block("latest")
    height = int(head["number"])
    if not 0 <= height < 2**64:
        raise RegistrationEvidenceUnavailable("invalid registration lookup head")
    anchor = _hex(head["hash"], 32)
    record = contract.functions.getRecord(bytes.fromhex(commitment[2:])).call(
        block_identifier=height
    )
    expected = [sector, vk, deadline, partition, service_end]
    actual = [_hex(_field(record, "sectorRoot", 0), 32),
              _hex(_field(record, "vkAddress", 2), 20),
              int(_field(record, "deadlineIndex", 3)),
              int(_field(record, "partitionIndex", 4)),
              int(_field(record, "serviceEnd", 5))]
    if actual != expected:
        raise RegistrationEvidenceUnavailable("registration record differs from the receipt")
    timestamp = int(_field(record, "registeredAt", 6))
    if not 0 < timestamp <= int(head["timestamp"]):
        raise RegistrationEvidenceUnavailable("registration timestamp is unavailable")

    blocks = {height: head}

    def block(number):
        if number not in blocks:
            blocks[number] = w3.eth.get_block(number)
        value = blocks[number]
        if int(value["number"]) != number:
            raise RegistrationEvidenceUnavailable("registration block identity differs")
        return value

    def lower_bound(target):
        low, high = 0, height + 1
        while low < high:
            middle = (low + high) // 2
            if int(block(middle)["timestamp"]) < target:
                low = middle + 1
            else:
                high = middle
        return low

    first, after = lower_bound(timestamp), lower_bound(timestamp + 1)
    # Some chains have several blocks per second. Never assume one timestamp
    # identifies a unique block, and never replace this with a genesis scan.
    if first > height or after <= first or after - first > 2048:
        raise RegistrationEvidenceUnavailable("registration timestamp range is unavailable or too large")
    topic = _hex(Web3.keccak(text="FileStorageRegistered(bytes32,bytes32,address,uint8,uint8,uint64)"), 32)
    topics = [topic, commitment, sector, "0x" + "0" * 24 + vk[2:]]
    data = b"".join(x.to_bytes(32, "big") for x in (deadline, partition, service_end))
    logs = w3.eth.get_logs({"address": Web3.to_checksum_address(address),
                            "fromBlock": first, "toBlock": after - 1,
                            "topics": topics})
    if len(logs) > 64:
        raise RegistrationEvidenceUnavailable("too many matching registration logs")
    candidates = {}
    for entry in logs:
        if entry.get("removed") or _hex(entry["address"], 20) != address:
            continue
        if [_hex(x, 32) for x in entry["topics"]] != topics or bytes(entry["data"]) != data:
            continue
        number = int(entry["blockNumber"])
        if not first <= number < after or int(block(number)["timestamp"]) != timestamp:
            continue
        digest = _hex(entry["blockHash"], 32)
        if digest != _hex(block(number)["hash"], 32):
            raise RegistrationEvidenceUnavailable("registration log is no longer canonical")
        tx = _hex(entry["transactionHash"], 32)
        mined = w3.eth.get_transaction_receipt(tx)
        if (mined is None or int(mined["status"]) != 1 or
                _hex(mined["transactionHash"], 32) != tx or
                _hex(mined["to"], 20) != address or
                int(mined["blockNumber"]) != number or
                _hex(mined["blockHash"], 32) != digest):
            raise RegistrationEvidenceUnavailable("registration receipt is not confirmed and canonical")
        # Cross-check the indexed log against the independently fetched receipt.
        matching = [item for item in mined["logs"]
                    if not item.get("removed") and _hex(item["address"], 20) == address
                    and [_hex(x, 32) for x in item["topics"]] == topics
                    and bytes(item["data"]) == data
                    and int(item["logIndex"]) == int(entry["logIndex"])]
        if len(matching) != 1:
            raise RegistrationEvidenceUnavailable("registration log differs from its receipt")
        candidates[tx] = number
    if len(candidates) != 1:
        raise RegistrationEvidenceUnavailable("one exact registration transaction is not available")
    if (_hex(w3.eth.get_block(height)["hash"], 32) != anchor or
            int(w3.eth.chain_id) != chain_id):
        raise RegistrationEvidenceUnavailable("registration lookup snapshot changed")
    return next(iter(candidates))
