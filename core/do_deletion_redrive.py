"""F.1 deletion re-drive classification.

Pure decision logic for the DO's durable secret-bearing deletion re-drive. This module
intentionally has NO GUI, chain, or network imports so it can be unit-tested in isolation.

The classifier turns a structured VK delete response plus the authoritative on-chain
deletion status into one of four re-drive decisions. It is deliberately conservative:
anything that is not clearly declared, confirmed, or a permanent rejection is treated as
retryable, so transport failures, timeouts, RPC errors, malformed responses, temporary VK
errors, and busy conditions never become terminal.
"""

from __future__ import annotations

# Re-drive decisions.
REDRIVE_CONTINUE = "continue"    # accepted_queued / transient / busy: re-send next tick.
REDRIVE_DECLARED = "declared"    # declared on-chain: stop the secret-bearing re-drive,
                                 # keep polling for confirmation.
REDRIVE_CONFIRMED = "confirmed"  # deletion confirmed on-chain.
REDRIVE_TERMINAL = "terminal"    # explicit permanent VK rejection: terminal failure.


def _truthy(value: object) -> bool:
    return bool(value)


def classify_redrive(resp: object, chain_status: object) -> tuple[str, str]:
    """Classify a re-drive outcome.

    Args:
        resp: the structured VK delete response (a dict), or None/empty when the request
            could not produce a structured response (transport/timeout/malformed).
        chain_status: the authoritative on-chain deletion status dict from
            verify_deletion_onchain (may carry ok/declared/confirmed/error), or None.

    Returns:
        (decision, summary) where decision is one of the REDRIVE_* constants. The summary
        never contains the deletion secret (this function never receives it).
    """
    chain = chain_status if isinstance(chain_status, dict) else {}

    # Authoritative chain state wins over any VK self-report.
    if _truthy(chain.get("ok")) or _truthy(chain.get("confirmed")):
        return REDRIVE_CONFIRMED, "deletion confirmed on-chain"
    if _truthy(chain.get("declared")):
        return REDRIVE_DECLARED, "declared on-chain; continuing confirmation polling"

    # No structured VK response at all (transport error / timeout / malformed) -> retry.
    if not isinstance(resp, dict) or not resp:
        return REDRIVE_CONTINUE, "deletion re-drive: no structured VK response; will retry"

    phase = str(resp.get("phase", "") or "").strip().lower()

    # VK reports confirmation / declaration (structured), still authoritative-adjacent.
    if _truthy(resp.get("confirmed")) or phase == "confirmed":
        return REDRIVE_CONFIRMED, "deletion confirmed"
    if _truthy(resp.get("declared")) or phase == "declared_pending":
        return REDRIVE_DECLARED, "declared on-chain; stop secret re-drive, poll for confirmation"

    # Explicitly retryable / busy / accepted-but-undeclared -> keep re-driving.
    if _truthy(resp.get("busy")) or _truthy(resp.get("retryable")):
        return REDRIVE_CONTINUE, "deletion accepted_queued / busy; will re-drive"
    if _truthy(resp.get("accepted")) and not _truthy(resp.get("declared")):
        return REDRIVE_CONTINUE, "deletion accepted_queued; will re-drive"

    # The ONLY terminal case: an EXPLICIT permanent rejection. The VK enumerates these by
    # setting `terminal: true` (e.g. invalid authorization secret, unknown commitment,
    # missing commitment). A generic/unknown/unversioned error WITHOUT the terminal flag
    # is NOT permanent — it stays retryable, so a responder that merely omitted a
    # retryability field can never be misclassified as a permanent failure.
    if resp.get("ok") is False and _truthy(resp.get("terminal")):
        return REDRIVE_TERMINAL, "deletion permanently rejected by VK: " + str(resp.get("error") or "terminal")

    # Anything ambiguous (unknown shape, generic error without an explicit terminal
    # marker) is retried, never terminal by default.
    return REDRIVE_CONTINUE, "deletion re-drive: ambiguous/generic VK result; will retry"


# Durable reconcile actions.
ACTION_CONFIRMED = "confirmed"  # mark confirmed / resolve.
ACTION_PENDING = "pending"      # keep the entry unresolved (retained), keep monitoring.
ACTION_FAILED = "failed"        # terminal failure; resolve WITHOUT a dispute.


def plan_reconcile_action(chain_status: object, resp: object) -> tuple[str, bool]:
    """Map a re-drive outcome to a durable reconcile action.

    Returns (action, redrive_again) where action is one of ACTION_*, and redrive_again is
    True only when the secret-bearing re-drive should continue on subsequent ticks.

      CONFIRMED -> (ACTION_CONFIRMED, False)
      TERMINAL  -> (ACTION_FAILED,   False)   # stop; do NOT dispute (never declared)
      DECLARED  -> (ACTION_PENDING,  False)   # stop secret re-drive, keep confirmation poll
      CONTINUE  -> (ACTION_PENDING,  True)    # keep re-driving, preserve the entry
    """
    decision, _ = classify_redrive(resp, chain_status)
    if decision == REDRIVE_CONFIRMED:
        return ACTION_CONFIRMED, False
    if decision == REDRIVE_TERMINAL:
        return ACTION_FAILED, False
    if decision == REDRIVE_DECLARED:
        return ACTION_PENDING, False
    return ACTION_PENDING, True
