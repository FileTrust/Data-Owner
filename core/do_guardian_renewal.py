"""Data Owner side of Guardian service renewal (extending a live policy term).

Why this exists
---------------
A Guardian service term used to be fixed once it was written. The only way to
change it was to write it again from scratch, which restarted the clock: the
days already served stopped counting, every past proof epoch stopped looking
obligated, and the Guardians were never asked whether they wanted the longer
job at all.

Renewal extends a running term in place. serviceStart stays where it is, and
serviceEnd only moves once every Guardian on the policy has agreed.

The order things happen in
--------------------------
Money for the extra days parks first, the Guardians take on the longer job
second, and the term moves last. If they do not all agree before the deadline
the DO cancels, the parked money comes back, and the original term runs on
untouched. A Guardian can never be paid for days it did not agree to hold.

Why every Guardian has to agree
-------------------------------
Each one holds a share and owes a daily proof for it, so a majority cannot vote
the rest into more work. One Guardian staying silent blocks the renewal; the DO
cancels and buys a fresh agreement, which is the same fallback it always had.
"""
from __future__ import annotations

import time

from . import do_config as C
from . import do_log as L

DAY_SECONDS = 86400

# The contract will not accept a longer answer deadline than this.
MAX_CONFIRM_SECONDS = 3 * DAY_SECONDS
# Default time to give the Guardians to answer. They poll far more often than
# this, so it is generous rather than tight.
DEFAULT_CONFIRM_SECONDS = 6 * 3600


def _require_contracts() -> tuple[object, object]:
    if C.guardian_share_proof is None:
        raise RuntimeError("GuardianShareProof is not configured")
    if C.reward_manager is None:
        raise RuntimeError("RewardManager is not configured")
    return C.guardian_share_proof, C.reward_manager


def latest_chain_timestamp() -> int:
    if C.w3 is None:
        raise RuntimeError("blockchain connection is unavailable")
    return int(C.w3.eth.get_block("latest")["timestamp"])


def service_period(file_id: bytes) -> dict:
    share_proof, _ = _require_contracts()
    exists, service_start, service_end, duration_days = (
        share_proof.functions.getPolicyServicePeriod(file_id).call()
    )
    return {
        "exists": bool(exists),
        "serviceStart": int(service_start),
        "serviceEnd": int(service_end),
        "durationDays": int(duration_days),
    }


def renewal_state(file_id: bytes) -> dict:
    """What the policy's renewal is currently waiting on."""
    share_proof, _ = _require_contracts()
    (pending, round_no, new_service_end, confirm_by, accepted_count,
     guardian_count, window_open, _mine) = (
        share_proof.functions.getServicePeriodExtension(
            file_id, "0x0000000000000000000000000000000000000000"
        ).call()
    )
    return {
        "pending": bool(pending),
        "round": int(round_no),
        "newServiceEnd": int(new_service_end),
        "confirmBy": int(confirm_by),
        "acceptedCount": int(accepted_count),
        "guardianCount": int(guardian_count),
        "acceptWindowOpen": bool(window_open),
    }


def custody_state(file_id: bytes) -> dict:
    _, reward_manager = _require_contracts()
    balance, committed, free, stretch_count, _claimable = (
        reward_manager.functions.custodyStatus(
            file_id, "0x0000000000000000000000000000000000000000"
        ).call()
    )
    return {
        "balance": int(balance),
        "committed": int(committed),
        "free": int(free),
        "stretchCount": int(stretch_count),
    }


def _top_up_custody(file_id: bytes, needed_wei: int) -> int:
    """Put in whatever the pot is short of `needed_wei`. Returns what was sent."""
    from .do_chain import send_signed_tx_receipt

    _, reward_manager = _require_contracts()
    free = custody_state(file_id)["free"]
    if free >= needed_wei:
        return 0
    top_up = needed_wei - free
    receipt = send_signed_tx_receipt(
        reward_manager.functions.depositCustodyEscrow(file_id),
        C.DO_ACCOUNT,
        "Guardian custody escrow deposit",
        gas_padding=80_000,
        value=top_up,
    )
    if receipt.status != 1:
        raise RuntimeError("custody escrow deposit failed")
    return top_up


def fund_current_term_custody(file_id: bytes) -> tuple[bool, str]:
    """Pay the Guardians for the term that is already running.

    Optional. A policy that never calls this keeps working exactly as before —
    the Guardians simply hold the share unpaid, which is what happened for every
    policy before custody payment existed. Call it once per term, before any
    renewal, since the days it buys have to come first in the run of stretches.
    """
    from .do_chain import send_signed_tx_receipt

    share_proof, reward_manager = _require_contracts()
    period = service_period(file_id)
    if not period["exists"]:
        return False, "this policy has no Guardian service term yet"
    now = latest_chain_timestamp()
    if now >= period["serviceEnd"]:
        return False, "the term has already ended"
    if custody_state(file_id)["stretchCount"] > 0:
        return False, "this term's custody is already paid for"

    try:
        price = int(reward_manager.functions.quoteCustody(
            file_id, period["serviceStart"], period["serviceEnd"]
        ).call())
    except Exception as exc:
        return False, f"could not price the term: {exc}"

    try:
        _top_up_custody(file_id, price)
        receipt = send_signed_tx_receipt(
            share_proof.functions.reserveServicePeriodCustody(file_id),
            C.DO_ACCOUNT,
            "Guardian custody reserved for the current term",
            gas_padding=150_000,
        )
        if receipt.status != 1:
            return False, "reserving the term's custody failed"
    except Exception as exc:
        return False, f"could not reserve the term's custody: {exc}"

    L.log(f"[G-renewal] paid {price} wei of custody for the current term")
    return True, f"custody funded for the current term ({price} wei)"


def request_renewal(file_id: bytes, extra_days: int,
                    confirm_seconds: int = DEFAULT_CONFIRM_SECONDS) -> tuple[bool, str]:
    """Park the money for `extra_days` more and ask the Guardians to agree."""
    from .do_chain import send_signed_tx_receipt

    share_proof, reward_manager = _require_contracts()
    if int(extra_days) <= 0:
        return False, "extra days must be positive"

    period = service_period(file_id)
    if not period["exists"]:
        return False, "this policy has no Guardian service term yet"
    now = latest_chain_timestamp()
    if now >= period["serviceEnd"]:
        return False, "the term has already ended; buy a fresh agreement instead"
    if renewal_state(file_id)["pending"]:
        return False, "a renewal is already waiting on this policy"

    new_service_end = period["serviceEnd"] + int(extra_days) * DAY_SECONDS

    # The Guardians must answer while the original term still runs, so a refusal
    # still leaves time to arrange something else.
    window = min(int(confirm_seconds), MAX_CONFIRM_SECONDS)
    confirm_by = min(now + window, period["serviceEnd"])
    if confirm_by <= now:
        return False, "the term ends too soon to leave the Guardians time to answer"

    try:
        price = int(reward_manager.functions.quoteCustody(
            file_id, period["serviceEnd"], new_service_end
        ).call())
    except Exception as exc:
        return False, f"could not price the extra days: {exc}"

    try:
        sent = _top_up_custody(file_id, price)
    except Exception as exc:
        return False, f"could not fund the extra days: {exc}"
    if sent:
        L.log(f"[G-renewal] topped the custody pot up by {sent} wei")

    try:
        receipt = send_signed_tx_receipt(
            share_proof.functions.requestServicePeriodExtension(
                file_id, new_service_end, confirm_by
            ),
            C.DO_ACCOUNT,
            "Guardian service renewal requested",
            gas_padding=200_000,
        )
        if receipt.status != 1:
            return False, "the renewal request was rejected on-chain"
    except Exception as exc:
        return False, f"renewal request failed: {exc}"

    state = renewal_state(file_id)
    L.log(
        f"[G-renewal] asked {state['guardianCount']} Guardian(s) for "
        f"{extra_days} more day(s) at a cost of {price} wei; "
        f"new end {new_service_end}, answers due by {confirm_by}"
    )
    return True, f"renewal round {state['round']} requested"


def wait_for_guardians(file_id: bytes, timeout_seconds: int = 600) -> tuple[bool, str]:
    """Poll until every Guardian has agreed, or the deadline passes."""
    target_end = 0
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = renewal_state(file_id)
        if target_end == 0:
            target_end = state["newServiceEnd"]
        if not state["pending"]:
            if target_end and service_period(file_id)["serviceEnd"] >= target_end:
                return True, f"renewed to {target_end}"
            return False, "the renewal disappeared without taking effect"
        if not state["acceptWindowOpen"]:
            return False, (
                f"only {state['acceptedCount']} of {state['guardianCount']} "
                "Guardian(s) agreed before the deadline"
            )
        time.sleep(3)
    return False, "timed out waiting for the Guardians to answer"


def cancel_renewal(file_id: bytes, refund: bool = True) -> tuple[bool, str]:
    """Take back money parked against a renewal the Guardians never all agreed
    to. The original term is untouched and runs on."""
    from .do_chain import send_signed_tx_receipt

    share_proof, reward_manager = _require_contracts()
    state = renewal_state(file_id)
    if not state["pending"]:
        return False, "there is no renewal waiting on this policy"
    if state["acceptWindowOpen"]:
        return False, "the Guardians still have time to answer"

    try:
        receipt = send_signed_tx_receipt(
            share_proof.functions.cancelServicePeriodExtension(file_id),
            C.DO_ACCOUNT,
            "Guardian service renewal cancelled",
            gas_padding=150_000,
        )
        if receipt.status != 1:
            return False, "cancelling the renewal was rejected on-chain"
    except Exception as exc:
        return False, f"cancel failed: {exc}"

    freed = custody_state(file_id)["free"]
    if refund and freed > 0:
        try:
            send_signed_tx_receipt(
                reward_manager.functions.refundUnusedCustody(file_id, freed),
                C.DO_ACCOUNT,
                "Unused Guardian custody refunded",
                gas_padding=80_000,
            )
            L.log(f"[G-renewal] took back {freed} wei of unused custody money")
        except Exception as exc:
            # The cancel itself succeeded, so the money is already free to take;
            # say so rather than reporting the whole renewal as stuck.
            return True, f"renewal cancelled, but the refund failed: {exc}"
    return True, "renewal cancelled and the parked money returned"


def renew_policy(file_id: bytes, extra_days: int,
                 timeout_seconds: int = 600) -> tuple[bool, str]:
    """Full renewal for one policy: price it, park the money, ask the Guardians,
    wait for them, and clean up if they do not all agree.

    Returns (ok, reason). On a Guardian no-show the parked money is taken back
    here, so the DO is never left with money stuck against a promise nobody made.
    """
    ok, reason = request_renewal(file_id, extra_days)
    if not ok:
        return False, reason

    ok, reason = wait_for_guardians(file_id, timeout_seconds=timeout_seconds)
    if ok:
        period = service_period(file_id)
        L.log(
            f"[G-renewal] renewed: term now runs to {period['serviceEnd']} "
            f"({period['durationDays']} day(s) from the original start)"
        )
        return True, reason

    L.log(f"[G-renewal] not agreed ({reason}); taking the parked money back")
    state = renewal_state(file_id)
    if state["pending"] and not state["acceptWindowOpen"]:
        cancelled, detail = cancel_renewal(file_id)
        if cancelled:
            return False, f"{reason}; money returned"
        return False, f"{reason}; cancel failed: {detail}"
    return False, reason
