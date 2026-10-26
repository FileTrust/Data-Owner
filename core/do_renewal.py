"""Data Owner side of storage renewal (extending a live service term).

Why this exists
---------------
A storage agreement used to be fixed at deposit time: the only way to buy more
days was to delete the piece and upload it again, paying full re-ingest cost and
leaving a window where the data was at risk.  Renewal extends a running term in
place.

The privacy rule
----------------
The whole escrow design rests on DO and VK not being linkable on-chain before
service end.  Renewal must not weaken that, so the DO's transaction carries ONLY
paymentCommitment — never the VK address, never registrationCommitment, never
the private link nonce.  The VK proves it agreed by opening an extension secret
it generated itself; that proof names nobody.

Ordering
--------
Money parks first, the VK accepts the longer obligation second, and only then is
the escrow term moved.  If the VK never confirms, the DO reclaims the parked
funds and the original term runs on untouched.  The VK can never be paid for a
window it does not owe, because VKEscrow.claimEscrow independently re-checks
that the VK's registered obligation covers the escrow term.
"""

from __future__ import annotations

import json
import time

from . import do_config as C
from . import do_log as L
from . import do_hex as HX
from . import do_txlog as TX
from . import do_tx_manager as TM


DAY_SECONDS = 86400

# Domain separator for the VK's renewal quote signature. Must match
# renewalQuoteDomain in the VK's escrow_extend.go.
RENEWAL_QUOTE_DOMAIN = "FileTrust VK Renewal Quote v1"


def _bytes32(value: str, label: str) -> bytes:
    return HX.hex_to_bytes(value, expected_bytes=32, field=label)


def latest_chain_timestamp() -> int:
    if C.w3 is None:
        raise RuntimeError("blockchain connection is unavailable")
    return int(C.w3.eth.get_block("latest")["timestamp"])


def request_renewal_quote(peer: str, payment_commitment: str, new_service_end: int) -> dict | None:
    """Ask a VK to quote a longer term. Returns the RenewResp dict or None."""
    from .do_vaultmesh import run_vaultmesh_cmd, _quote_client_identity_path

    if not peer or not payment_commitment or int(new_service_end) <= 0:
        return None
    try:
        out = run_vaultmesh_cmd([
            C.VAULTMESH_CMD,
            "--mode", "renew",
            "--peer", peer,
            "--payment-commitment", payment_commitment,
            "--service-end", str(int(new_service_end)),
            "--client-identity-key", str(_quote_client_identity_path()),
        ])
        resp = json.loads(out)
        if not resp.get("ok"):
            L.log(f"[renewal] VK declined: {resp.get('err', 'unknown error')}")
            return None
        return resp
    except Exception as exc:
        L.log(f"[renewal] quote error: {exc}")
        return None


def verify_renewal_quote(quote: dict, expected_vk: str = "") -> tuple[bool, str]:
    """Check the VK actually signed these terms before we part with any money."""
    try:
        vk_address = C.w3.to_checksum_address(quote.get("vkAddress", ""))
        escrow_address = C.w3.to_checksum_address(quote.get("vkEscrowContract", ""))
        if C.vk_escrow is None:
            return False, "VKEscrow is not configured"
        if escrow_address != C.w3.to_checksum_address(C.vk_escrow.address):
            return False, "quote names a different escrow contract"
        if expected_vk and vk_address != C.w3.to_checksum_address(expected_vk):
            return False, "quote signed by an unexpected VK"

        added_price = int(quote.get("addedPriceWei", "0") or 0)
        if added_price <= 0:
            return False, "renewal price is zero"

        digest = C.w3.solidity_keccak(
            [
                "string", "uint256", "address", "address", "bytes32", "bytes32",
                "uint256", "uint64", "uint64", "uint64", "uint64",
            ],
            [
                RENEWAL_QUOTE_DOMAIN,
                int(C.w3.eth.chain_id),
                vk_address,
                escrow_address,
                _bytes32(quote["paymentCommitment"], "paymentCommitment"),
                _bytes32(quote["extensionCommitment"], "extensionCommitment"),
                added_price,
                int(quote["currentServiceEnd"]),
                int(quote["newServiceEnd"]),
                int(quote["confirmBy"]),
                int(quote["quoteValidUntil"]),
            ],
        )
        from eth_account.messages import encode_defunct

        recovered = C.w3.eth.account.recover_message(
            encode_defunct(digest), signature=quote.get("vkSignature", "")
        )
        if C.w3.to_checksum_address(recovered) != vk_address:
            return False, "renewal quote signature does not match the quoting VK"

        chain_now = latest_chain_timestamp()
        if int(quote["quoteValidUntil"]) <= chain_now:
            return False, "renewal quote expired"
        if int(quote["newServiceEnd"]) <= int(quote["currentServiceEnd"]):
            return False, "quoted term does not extend the agreement"
        if int(quote["confirmBy"]) <= chain_now:
            return False, "confirm window already closed"
        return True, "renewal quote verified"
    except Exception as exc:
        return False, f"renewal quote verification error: {exc}"


def extend_escrow(quote: dict) -> tuple[bool, str]:
    """Park the extra payment for the longer term.

    Sends ONLY paymentCommitment, the new end date, the VK's extension
    commitment and the confirm deadline. Nothing here identifies the VK.
    """
    if C.vk_escrow is None:
        return False, "VKEscrow is not configured"
    payment_commitment = str(quote.get("paymentCommitment", ""))
    added_price = int(quote.get("addedPriceWei", "0") or 0)
    new_service_end = int(quote.get("newServiceEnd", 0) or 0)
    confirm_by = int(quote.get("confirmBy", 0) or 0)
    try:
        pc = _bytes32(payment_commitment, "paymentCommitment")
        ec = _bytes32(quote["extensionCommitment"], "extensionCommitment")

        existing = C.vk_escrow.functions.extensionStatus(pc).call()
        if int(existing[1]) > 0:
            return False, "an extension is already pending for this agreement"

        with TM.account_transaction_lock(C.DO):
            nonce = TM.pending_nonce(C.w3, C.DO)
            gas_price = C.gas_price_wei()
            tx = C.vk_escrow.functions.extendEscrow(
                pc, new_service_end, ec, confirm_by,
            ).build_transaction({
                "from": C.DO,
                "value": added_price,
                "nonce": nonce,
                "gas": 250_000,
                "gasPrice": gas_price,
            })
            signed = C.DO_ACCOUNT.sign_transaction(tx)
            tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            TX.log_contract_transaction(
                C,
                C.w3,
                actor_address=C.DO,
                contract_name="VKEscrow",
                function_name="extendEscrow",
                contract_address=C.vk_escrow.address,
                tx=tx,
                tx_hash=tx_hash,
                receipt=receipt,
                payment_commitment=payment_commitment,
                price_wei=added_price,
                service_end=new_service_end,
            )
        if receipt.status != 1:
            return False, f"extendEscrow reverted in block {receipt.blockNumber}"
        L.log(
            f"[renewal] parked {added_price} wei for new term {new_service_end} "
            f"pc={payment_commitment[:18]}...  tx={tx_hash.hex()[:18]}..."
        )
        return True, tx_hash.hex()
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            C,
            actor_address=C.DO,
            contract_name="VKEscrow",
            function_name="extendEscrow",
            contract_address=getattr(C.vk_escrow, "address", ""),
            status="failed",
            error=str(exc),
            payment_commitment=payment_commitment,
            price_wei=added_price,
            service_end=new_service_end,
        )
        return False, f"extendEscrow error: {exc}"


def extension_state(payment_commitment: str) -> dict:
    """Read the current renewal state for monitoring."""
    pc = _bytes32(payment_commitment, "paymentCommitment")
    pending_amount, pending_end, confirm_by, ext_commitment, service_end, window_open = (
        C.vk_escrow.functions.extensionStatus(pc).call()
    )
    return {
        "pendingAmount": int(pending_amount),
        "pendingServiceEnd": int(pending_end),
        "confirmBy": int(confirm_by),
        "extensionCommitment": "0x" + bytes(ext_commitment).hex(),
        "serviceEnd": int(service_end),
        "confirmWindowOpen": bool(window_open),
    }


def wait_for_confirmation(payment_commitment: str, timeout_seconds: int = 180) -> tuple[bool, str]:
    """Poll until the VK confirms the renewal, or the window closes."""
    target_end = 0
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = extension_state(payment_commitment)
        if target_end == 0:
            target_end = state["pendingServiceEnd"]
        if state["pendingServiceEnd"] == 0:
            if target_end and state["serviceEnd"] >= target_end:
                return True, f"renewed to {state['serviceEnd']}"
            return False, "renewal disappeared without taking effect"
        if not state["confirmWindowOpen"]:
            return False, "VK did not confirm before the deadline"
        time.sleep(3)
    return False, "timed out waiting for the VK to confirm"


def reclaim_extension(payment_commitment: str) -> tuple[bool, str]:
    """Take back parked funds the VK never confirmed. Original term survives."""
    if C.vk_escrow is None:
        return False, "VKEscrow is not configured"
    try:
        pc = _bytes32(payment_commitment, "paymentCommitment")
        with TM.account_transaction_lock(C.DO):
            nonce = TM.pending_nonce(C.w3, C.DO)
            gas_price = C.gas_price_wei()
            tx = C.vk_escrow.functions.reclaimExtension(pc).build_transaction({
                "from": C.DO,
                "nonce": nonce,
                "gas": 150_000,
                "gasPrice": gas_price,
            })
            signed = C.DO_ACCOUNT.sign_transaction(tx)
            tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            TX.log_contract_transaction(
                C,
                C.w3,
                actor_address=C.DO,
                contract_name="VKEscrow",
                function_name="reclaimExtension",
                contract_address=C.vk_escrow.address,
                tx=tx,
                tx_hash=tx_hash,
                receipt=receipt,
                payment_commitment=payment_commitment,
            )
        if receipt.status != 1:
            return False, f"reclaimExtension reverted in block {receipt.blockNumber}"
        L.log(f"[renewal] reclaimed unconfirmed extension  pc={payment_commitment[:18]}...")
        return True, tx_hash.hex()
    except Exception as exc:
        return False, f"reclaimExtension error: {exc}"


def renew_piece(peer: str, payment_commitment: str, extra_days: int,
                expected_vk: str = "") -> tuple[bool, str]:
    """Full renewal for one piece: quote, verify, park funds, await confirmation.

    Returns (ok, reason). On a VK no-show the parked funds are reclaimed here so
    the DO is never left with money stuck against a promise nobody kept.
    """
    if int(extra_days) <= 0:
        return False, "extra days must be positive"
    if C.vk_escrow is None:
        return False, "VKEscrow is not configured"

    current = extension_state(payment_commitment)
    if current["serviceEnd"] <= 0:
        return False, "no escrow found for this commitment"
    new_service_end = current["serviceEnd"] + int(extra_days) * DAY_SECONDS

    quote = request_renewal_quote(peer, payment_commitment, new_service_end)
    if not quote:
        return False, "VK did not quote a renewal"

    ok, reason = verify_renewal_quote(quote, expected_vk=expected_vk)
    if not ok:
        return False, reason
    L.log(
        f"[renewal] VK quoted {quote['addedPriceWei']} wei for "
        f"{extra_days} more day(s), new end {quote['newServiceEnd']}"
    )

    ok, reason = extend_escrow(quote)
    if not ok:
        return False, reason

    ok, reason = wait_for_confirmation(payment_commitment)
    if ok:
        return True, reason

    L.log(f"[renewal] not confirmed ({reason}); reclaiming parked funds")
    state = extension_state(payment_commitment)
    if state["pendingServiceEnd"] > 0 and not state["confirmWindowOpen"]:
        reclaimed, detail = reclaim_extension(payment_commitment)
        if reclaimed:
            return False, f"{reason}; funds reclaimed"
        return False, f"{reason}; reclaim failed: {detail}"
    return False, reason
