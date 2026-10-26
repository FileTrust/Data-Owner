"""Bounded replacement planning on an already validated candidate snapshot.

Eligibility is supplied by the chain/directory client. A heartbeat is a useful
selection signal, not a promise that a node will accept or answer. This helper
never reduces a threshold or edits the running attempt; persist its result
before creating the next on-chain request.
"""
from dataclasses import dataclass
from secrets import SystemRandom

from web3 import Web3


class NoEligibleGuardians(RuntimeError):
    pass


def addresses(values):
    result = [Web3.to_checksum_address(value) for value in values]
    if len(set(value.lower() for value in result)) != len(result):
        raise ValueError('Duplicate Guardian addresses in recovery selection')
    return result


@dataclass(frozen=True)
class ReplacementPlan:
    receivers: tuple[str, ...]
    dealer_indices: tuple[int, ...]


def select_replacements(*, receivers, n, t, eligible, excluded, profiles,
                        old_guardians=None, old_threshold=None, previous_dealers=(), rng=None):
    if type(n) is not int or type(t) is not int or not 2 <= t <= n <= 20 or (n, t) not in profiles:
        raise ValueError('The requested Guardian profile is not approved for this operation')
    receivers, candidates = addresses(receivers), addresses(eligible)
    if len(receivers) != n:
        raise ValueError('The receiver count differs from the approved profile')
    failed = {value.lower() for value in addresses(excluded)}
    available = {value.lower(): value for value in candidates if value.lower() not in failed}
    chosen = [value if value.lower() in available else None for value in receivers]
    occupied = {value.lower() for value in chosen if value is not None}
    pool = [value for key, value in available.items() if key not in occupied]
    missing = sum(value is None for value in chosen)
    if len(pool) < missing:
        raise NoEligibleGuardians('Not enough eligible Guardians to replace the missing receivers; the threshold was kept')
    rng = rng or SystemRandom()
    replacements = iter(rng.sample(pool, missing))
    chosen = [value if value is not None else next(replacements) for value in chosen]
    if old_guardians is None:
        if old_threshold is not None or previous_dealers:
            raise ValueError('Fresh DKG has no old contributing set')
        return ReplacementPlan(tuple(chosen), tuple(range(1, n+1)))
    old = addresses(old_guardians)
    if type(old_threshold) is not int or not 2 <= old_threshold <= len(old) <= 20:
        raise ValueError('Invalid previous active Guardian threshold')
    usable = [index for index, value in enumerate(old, 1) if value.lower() in available]
    previous = list(previous_dealers)
    if (len(set(previous)) != len(previous) or len(previous) > old_threshold or
            any(type(index) is not int or not 1 <= index <= len(old) for index in previous)):
        raise ValueError('Invalid previous refresh contributor set')
    kept = [index for index in previous if index in usable]
    pool = [index for index in usable if index not in kept]
    if len(kept) + len(pool) < old_threshold:
        raise NoEligibleGuardians('Fewer than the old threshold of share holders are available; the active key and shares must be kept')
    selected = kept + rng.sample(pool, old_threshold-len(kept))
    return ReplacementPlan(tuple(chosen), tuple(sorted(selected)))
