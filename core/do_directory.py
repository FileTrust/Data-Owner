# do_directory.py — every Vault Keeper and Guardian, from a discovery node.
#
# Discovery reads the whole network from the chain once a minute and serves it
# as one compact document. This module keeps a copy of it, so the VK and
# Guardian tables and automatic selection never read the network row by row.
#
# Cheap by design:
#   - a request is made at most once per TTL, however often the tables reload;
#   - holding a version, the DO asks only for what changed since then
#     (?since=&epoch=) and is answered 304 when nothing did;
#   - bodies are gzip;
#   - the copy is kept on disk, so a restarted DO has a full table at once and
#     only asks for the changes.
#
# Everything here is a hint for choosing. Keepers and guardians actually chosen
# are checked against the chain before they are used (see do_network).

from __future__ import annotations

import gzip
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import do_config as C
from . import do_log as L

TTL_SECONDS = 30.0
CACHE_PATH = Path(C.BASE_DIR) / "directory_cache.json"

_lock = threading.Lock()
_state: dict = {
    "node": "",          # discovery URL the held version came from
    "epoch": "",
    "version": 0,
    "refreshedAt": 0,    # when discovery last read the chain for this version
    "meta": {},
    "vkColumns": [],
    "gColumns": [],
    "vk": {},            # address (lowercase) -> row array
    "g": {},
}
_asked_at = 0.0
_disk_loaded = False


def _discovery_urls() -> list[str]:
    """The user's own directory servers first, then the network's."""
    from . import ft_discovery

    return ft_discovery.urls(C.config)


def _timeout() -> float:
    try:
        return float(getattr(C.config, "DISCOVERY_TIMEOUT_SECONDS", 2) or 2)
    except Exception:
        return 2.0


def _get(url: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={
        "Accept-Encoding": "gzip",
        # Cloudflare answers Python's default user agent with 403, and the
        # discovery nodes are behind it. A healthy node would read as broken.
        "User-Agent": "FileTrust-DO",
    })
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            body = resp.read()
            if resp.headers.get("Content-Encoding", "") == "gzip":
                body = gzip.decompress(body)
            return resp.status, json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _apply(doc: dict, node: str) -> bool:
    """Take a full document or a delta. Returns False if a delta does not fit."""
    if doc.get("full"):
        _state["vkColumns"] = list(doc.get("vkColumns") or [])
        _state["gColumns"] = list(doc.get("gColumns") or [])
        _state["vk"] = {str(r[0]).lower(): r for r in doc.get("vk") or []}
        _state["g"] = {str(r[0]).lower(): r for r in doc.get("g") or []}
    else:
        if (
            node != _state["node"]
            or doc.get("epoch") != _state["epoch"]
            or int(doc.get("since", -1)) != int(_state["version"])
        ):
            return False
        for r in doc.get("vk") or []:
            _state["vk"][str(r[0]).lower()] = r
        for r in doc.get("g") or []:
            _state["g"][str(r[0]).lower()] = r
        for addr in doc.get("removedVk") or []:
            _state["vk"].pop(str(addr).lower(), None)
        for addr in doc.get("removedG") or []:
            _state["g"].pop(str(addr).lower(), None)
    _state["node"] = node
    _state["epoch"] = str(doc.get("epoch", ""))
    _state["version"] = int(doc.get("version", 0))
    _state["refreshedAt"] = int(doc.get("refreshedAt", 0))
    _state["meta"] = dict(doc.get("meta") or {})
    return True


def _load_disk() -> None:
    global _disk_loaded
    _disk_loaded = True
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return
    if isinstance(data, dict) and data.get("vkColumns") is not None:
        _state.update({k: data.get(k, _state[k]) for k in _state})


def _save_disk() -> None:
    try:
        tmp = CACHE_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_state, separators=(",", ":")), encoding="utf-8")
        tmp.replace(CACHE_PATH)
    except Exception as exc:
        L.log(f"[directory] could not save the local copy: {exc}")


def refresh(force: bool = False) -> bool:
    """Bring the local copy up to date. True when a directory is available.

    Asks at most once per TTL unless forced. Tries the node the held version
    came from first (so it can answer with only the changes), then the others
    for a full document. If none answers, the previous copy is kept: an
    unreachable discovery is not an empty network.
    """
    global _asked_at
    with _lock:
        if not _disk_loaded:
            _load_disk()
        now = time.time()
        have = bool(_state["vk"] or _state["g"])
        if not force and have and now - _asked_at < TTL_SECONDS:
            return True
        _asked_at = now

        urls = _discovery_urls()
        held = _state["node"] if _state["version"] else ""
        if held in urls:
            urls.remove(held)
            urls.insert(0, held)

        for url in urls:
            try:
                if url == held:
                    status, doc = _get(
                        f"{url}/v1/directory?since={_state['version']}&epoch={_state['epoch']}"
                    )
                    if status == 304:
                        return True
                    if status == 200 and doc is not None and not _apply(doc, url):
                        status, doc = _get(f"{url}/v1/directory")
                        if status == 200 and doc is not None:
                            _apply(doc, url)
                else:
                    status, doc = _get(f"{url}/v1/directory")
                    if status == 200 and doc is not None:
                        _apply(doc, url)
            except Exception as exc:
                L.log(f"[directory] {url} failed: {exc}")
                continue
            if status == 200 and doc is not None:
                _save_disk()
                return True
            if status == 503:
                L.log(f"[directory] {url} has not read the chain yet")

        if have:
            L.log("[directory] no discovery node answered; using the copy held locally")
        return have


def meta() -> dict:
    with _lock:
        return dict(_state["meta"])


def age_seconds() -> int:
    """How long ago discovery read the chain for the held version."""
    with _lock:
        refreshed = int(_state["refreshedAt"] or 0)
    return int(time.time()) - refreshed if refreshed else -1


def keepers() -> list[dict]:
    """Every keeper as a dict keyed by column name, in a stable order."""
    with _lock:
        cols = list(_state["vkColumns"])
        rows = [_state["vk"][k] for k in sorted(_state["vk"])]
    return [dict(zip(cols, r)) for r in rows]


def guardians() -> list[dict]:
    with _lock:
        cols = list(_state["gColumns"])
        rows = [_state["g"][k] for k in sorted(_state["g"])]
    return [dict(zip(cols, r)) for r in rows]
