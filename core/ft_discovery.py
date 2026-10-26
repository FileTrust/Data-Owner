# ft_discovery.py — which directory servers this app asks, and in what order.
#
# Two lists, because they have two owners:
#
#   discovery_urls           the network's own, written by the config service
#                            whenever the user asks it to update. Anything a
#                            user typed here would be overwritten by that.
#   my_discovery_urls        theirs. Nothing in the app ever writes it.
#
# Both are used, the user's first, so adding a server of your own is safe and
# does not cost you the defaults. Anyone will be able to run a discovery node;
# somebody who trusts only their own sets use_only_my_discovery_urls and the
# network's list is ignored.
#
# One judgement call, stated rather than hidden: "only mine" with an empty list
# of your own falls back to the network's. An app with no directory server at
# all cannot find a single keeper, and failing that way -- silently, after an
# edit that looks harmless -- is worse than ignoring a setting that was left
# in a state nobody can have meant.

from __future__ import annotations


def _clean(raw) -> list[str]:
    """A list of addresses from whatever the settings file happens to hold.

    Accepts a list, or one line with commas in it, because both are things a
    person reasonably types into a JSON file by hand.
    """
    if isinstance(raw, str):
        items = raw.replace("\n", ",").split(",")
    elif isinstance(raw, (list, tuple)):
        items = raw
    else:
        items = []
    out: list[str] = []
    for item in items:
        url = str(item or "").strip().rstrip("/")
        if url and url not in out:
            out.append(url)
    return out


def _is_true(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def mine(config) -> list[str]:
    return _clean(getattr(config, "MY_DISCOVERY_URLS", []))


def network(config) -> list[str]:
    return _clean(getattr(config, "DISCOVERY_URLS", []))


def urls(config) -> list[str]:
    """Every directory server to ask, the user's own first."""
    own = mine(config)
    if own and _is_true(getattr(config, "USE_ONLY_MY_DISCOVERY_URLS", False)):
        return own
    return own + [url for url in network(config) if url not in own]


NO_SERVERS = (
    "This app has no directory server to ask, so it cannot find keepers or "
    "guardians. Pick \"Update network settings\" from the tray icon to fetch "
    "the network's list, or add your own under my_discovery_urls in "
    "config.json."
)


def problem(config) -> str:
    """Empty when there is somewhere to ask; otherwise what to do about it.

    The list is empty on a fresh install whose setup could not reach the
    config service -- a real case, and one the old message ("check
    DISCOVERY_URLS") did not help with at all.
    """
    return "" if urls(config) else NO_SERVERS
