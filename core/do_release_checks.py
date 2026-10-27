"""May this DO begin new escrows? Start-up release checks (Phase 2.5).

Run once when the app starts (with the escrow reconciler) and kept for ten minutes.
They block only NEW obligations, never disputes, settlements, refunds, reclaims or
reading data, and they never change an address:

1. The signed network binding shipped with this release (network-bindings.json): when it
   names the current chain, every bound contract this DO uses must have the configured
   address, the configured ABI file's hash and the bound runtime code.
2. A pinned deployment manifest, when config.json names one (deployment_manifest).
3. The network's minimum DO version, recorded by the last settings check. The config
   service is not authenticated, so a newer requirement stops new escrows only when the
   signed (TUF-verified) release information confirms such a release exists; otherwise
   it is a warning. The address-registry check stays in do_vaultmesh.

A check that cannot run (RPC or service unavailable) blocks nothing by itself: deposits
need the chain anyway, and existing obligations must stay serviceable.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from . import do_config as C
from . import do_log as L
from .ft_network_config import CONTRACTS, digest, semver

APP_DIR = Path(__file__).resolve().parents[1]
CHECK_SECONDS = 600
_lock = threading.Lock()
_result = {"checked_at": 0.0, "reason": ""}


def _config() -> dict:
    try:
        return json.loads(Path(C.config.CONFIG_PATH).read_text())
    except (OSError, ValueError, AttributeError):
        return {}


def _abi_file(cfg: dict, prefix: str) -> Path | None:
    value = cfg.get(prefix + "_json")
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = APP_DIR / value if (APP_DIR / value).is_file() else APP_DIR / "core" / value
    return path


def binding_problem(chain_id: int, cfg: dict, code_of) -> str:
    """Why the configured contracts differ from this release's signed binding, or ""."""
    path = APP_DIR / "network-bindings.json"
    if not path.is_file():
        return ""
    data = json.loads(path.read_text())
    rows = ((data.get("networks") or {}).get(str(chain_id)) or {}).get("contracts") or {}
    for prefix, name in CONTRACTS.items():
        row = rows.get(name)
        if not row or not cfg.get(prefix + "_address"):
            continue
        if str(cfg[prefix + "_address"]).lower() != str(row["address"]).lower():
            return f"{name} differs from the signed binding of this release (address)"
        abi_file = _abi_file(cfg, prefix)
        if abi_file is not None:
            try:
                abi = json.loads(abi_file.read_text())["abi"]
            except (OSError, ValueError, KeyError):
                return f"{name} ABI file is missing or invalid"
            if digest(abi) != row["abi_sha256"]:
                return f"{name} differs from the signed binding of this release (ABI)"
        code = code_of(row["address"])
        if hashlib.sha256(bytes(code)).hexdigest() != row["code_sha256"]:
            return f"{name} differs from the signed binding of this release (runtime code)"
    return ""


def manifest_problem(chain_id: int, cfg: dict) -> str:
    path = cfg.get("deployment_manifest")
    if not path:
        return ""
    from . import do_deployment_manifest as DM
    addresses = {name: cfg[prefix + "_address"] for prefix, name in CONTRACTS.items() if cfg.get(prefix + "_address")}
    try:
        DM.enforce_manifest(str(path), chain_id=chain_id, addresses=addresses)
    except (DM.DeploymentManifestError, OSError, ValueError) as exc:
        return f"deployment manifest check failed: {exc}"
    return ""


def verified_latest() -> str:
    """The newest release the signed update check has verified, or ""."""
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    try:
        status = json.loads((base / "filetrust/updates/do/status.json").read_text())
    except (OSError, ValueError):
        return ""
    return str(status.get("latest") or "") if status.get("state") in ("available", "current") else ""


def minimum_version_problem() -> tuple[str, str]:
    """(blocking reason, warning) from the network's minimum DO version."""
    try:
        status = json.loads((APP_DIR / ".network-updates/status.json").read_text())
        minimum = status.get("minimum_version") or {}
        required, installed = minimum.get("required"), minimum.get("installed")
        if not required or semver(installed, "installed version") >= semver(required, "minimum version"):
            return "", ""
    except (OSError, ValueError, TypeError):
        return "", ""
    latest = verified_latest()
    try:
        confirmed = bool(latest) and semver(latest, "verified version") >= semver(required, "minimum version")
    except ValueError:
        confirmed = False
    message = f"the network needs DO {required} or newer (installed {installed})"
    if confirmed:
        return message + f"; the signed update {latest} is available: prepare and apply it", ""
    return "", message + "; no signed release confirms it yet, so new escrows are not stopped"


def run_checks() -> str:
    cfg = _config()
    reasons = []
    try:
        chain_id = int(C.w3.eth.chain_id)
        reasons.append(binding_problem(chain_id, cfg, C.w3.eth.get_code))
        reasons.append(manifest_problem(chain_id, cfg))
    except Exception as exc:  # RPC or file trouble: report, block nothing by itself
        L.log(f"[release] start-up contract checks could not run: {exc}")
    blocking, warning = minimum_version_problem()
    reasons.append(blocking)
    if warning:
        L.log(f"[release] {warning}")
    reason = "; ".join(item for item in reasons if item)
    with _lock:
        _result.update(checked_at=time.time(), reason=reason)
    L.log(f"[release] new escrows are blocked: {reason}" if reason else "[release] start-up release checks passed")
    return reason


def new_obligations_blocked() -> str:
    """Why no new escrow may begin, or "". Never blocks settling existing ones."""
    with _lock:
        fresh = time.time() - _result["checked_at"] < CHECK_SECONDS
        reason = _result["reason"]
    return reason if fresh else run_checks()
