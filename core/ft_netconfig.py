# ft_netconfig.py — take the chain's addresses from the network config service.
#
# Contract addresses change whenever the chain is redeployed. Until now the
# apps learned about that from a file written once at install: a user who had
# installed before a redeploy kept the old addresses for ever, saw calls fail
# against contracts that were no longer there, and had no way to find out why
# short of being told to edit config.json by hand.
#
# The Vault Keepers and the Guardians already solve this: the blockchain server
# runs a small service (App/NetworkConfig) that publishes the deployed
# addresses, the RPC URL, the discovery nodes and the contract ABIs, and their
# updaters fetch it. This is the same thing for the Data Owner and the
# Requester, with two differences, because these two run on a stranger's
# desktop rather than on our own servers:
#
#   * it is never allowed to stop the app starting. Any failure -- no network,
#     service down, rubbish payload -- leaves the settings exactly as they were
#     and the app opens as usual;
#   * it is asked once, during install, and after that only when the user picks
#     "Update network settings" from the tray. A redeploy is a rare event and
#     the answer carries every ABI on the chain; polling it on a timer would
#     put thousands of pointless megabytes through one small server for a value
#     that changes a few times a year.
#
# The URL in config.json is the trust anchor: whatever answers it decides which
# chain this app talks to. The default is https://config.filetrust.io,
# with HTTPS certificate verification enabled. The URL remains configurable.

from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

STATE_FILENAME = "network_config_state.json"
DEFAULT_TIMEOUT = 30.0
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024


class NetConfigError(Exception):
    """The service could not be read, or did not answer with a config."""


# Which config.json setting takes which deployed contract. The superset for
# both apps: only the keys an app already has are written, so the Data Owner
# does not grow Requester settings and the other way round.
ADDRESS_FIELDS = {
    "guardian_registry_address": ("GuardianRegistry", "GUARDIAN_REGISTRY_ADDRESS"),
    "vault_keeper_registry_address": ("VaultKeeperRegistry", "VAULT_KEEPER_REGISTRY_ADDRESS"),
    "acl_address": ("AccessControlFT", "ACL_ADDRESS"),
    "dv_address": ("DataVault", "DV_ADDRESS"),
    "dkg_address": ("DKG", "DKG_ADDRESS"),
    "telg_address": ("TElG", "TELG_ADDRESS"),
    "telg_v2_address": ("TElGv2", "TELG_V2_ADDRESS"),
    "zkdkg_coordinator_v2_address": ("ZkDkgCoordinatorV2", "ZKDKG_COORDINATOR_V2_ADDRESS"),
    "guardian_share_proof_address": ("GuardianShareProof", "GUARDIAN_SHARE_PROOF_ADDRESS"),
    "reputation_manager_address": ("ReputationManager", "REPUTATION_MANAGER_ADDRESS"),
    "reward_manager_address": ("RewardManager", "REWARD_MANAGER_ADDRESS"),
    "file_registration_address": ("FileRegistrationSC", "FILE_REGISTRATION_ADDRESS"),
    "storageproof_address": ("StorageProofSC", "STORAGE_PROOF_ADDRESS"),
    "capacity_proof_address": ("CapacityProofSC", "CAPACITY_PROOF_ADDRESS"),
    "vk_escrow_address": ("VKEscrow", "VK_ESCROW_ADDRESS"),
    "storage_receipt_dispute_address": ("StorageReceiptDispute", "STORAGE_RECEIPT_DISPUTE_ADDRESS"),
    "storage_registration_timeout_address": (
        "StorageRegistrationTimeout", "STORAGE_REGISTRATION_TIMEOUT_ADDRESS",
    ),
}

# Settings that describe where the network is, rather than what is deployed on
# it. Same rule: only written when the app already has the key.
NETWORK_FIELDS = ("rpc_url", "discovery_urls")


# ── Reading the service ──────────────────────────────────────────────────────

def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """The published config, or NetConfigError. Never raises anything else."""
    address = str(url or "").strip()
    if not address:
        raise NetConfigError("no network config URL is set")
    request = urllib.request.Request(address, headers={
        "Accept": "application/json",
        "User-Agent": "FileTrust-app",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise NetConfigError(f"the config service answered HTTP {response.status}")
            raw = response.read(MAX_PAYLOAD_BYTES + 1)
    except NetConfigError:
        raise
    except Exception as exc:   # URLError, timeout, DNS, TLS, anything
        raise NetConfigError(f"the config service could not be reached: {exc}") from exc
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise NetConfigError("the config service sent more than this app will read")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise NetConfigError("the config service did not answer with JSON") from exc
    if not isinstance(payload, dict):
        raise NetConfigError("the config service did not answer with a config")
    if "deployed_addresses" not in payload or "network" not in payload:
        raise NetConfigError("the config is missing deployed_addresses or network")
    return payload


def _address_of(deployed: dict, contract: str, env_key: str) -> str:
    contracts = deployed.get("contracts") if isinstance(deployed, dict) else None
    env = deployed.get("env") if isinstance(deployed, dict) else None
    value = ""
    if isinstance(contracts, dict):
        value = str(contracts.get(contract, "") or "").strip()
    if not value and isinstance(env, dict):
        value = str(env.get(env_key, "") or "").strip()
    return value


def _looks_like_address(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) == 42
        and all(c in "0123456789abcdefABCDEF" for c in value[2:])
    )


# ── Writing what changed ─────────────────────────────────────────────────────

def _write_json(path: Path, data) -> None:
    """Atomic, and 0600 for config.json, which may still hold a key."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply_to_config(config_path, payload: dict) -> list[str]:
    """Update the app's settings from the payload. Returns what changed.

    Addresses are network truth, not a preference, so a differing value is
    replaced rather than kept -- that is the whole point of asking. A key the
    app does not already have is never added: the two apps read different
    settings, and inventing one only makes the file harder to read.
    """
    path = Path(config_path)
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NetConfigError(f"{path} could not be read: {exc}") from exc
    if not isinstance(config, dict):
        raise NetConfigError(f"{path} is not a settings file")

    deployed = payload.get("deployed_addresses") or {}
    network = payload.get("network") or {}
    advertised=deployed.get('capabilities',{}).get('dkgAttemptProtocol',0)
    if advertised!=config.get('dkg_attempt_protocol',0):
        raise NetConfigError('DKG protocol changes require a matching versioned installation; saved settings retained')
    target=(deployed.get('contracts') or {}).get('ZkDkgCoordinatorV2')
    if config.get('dkg_attempt_protocol')==1 and target and str(target).lower()!=str(config.get('zkdkg_coordinator_v2_address','')).lower():
        raise NetConfigError('A different DKG deployment needs a custody migration review')
    changed: list[str] = []

    for key, (contract, env_key) in ADDRESS_FIELDS.items():
        if key not in config:
            continue
        value = _address_of(deployed, contract, env_key)
        # A missing or malformed address means the service does not know that
        # contract. Keeping what we have beats writing an empty address, which
        # would turn every call on it into a crash at start-up.
        if not _looks_like_address(value) or config.get(key) == value:
            continue
        config[key] = value
        changed.append(key)

    for key in NETWORK_FIELDS:
        if key not in config:
            continue
        value = network.get(key)
        if not value or config.get(key) == value:
            continue
        config[key] = value
        changed.append(key)

    if changed:
        _write_json(path, config)
    return changed


def apply_artifacts(contracts_dir, payload: dict) -> list[str]:
    """Refresh the contract ABIs the app already carries.

    Only files that exist: an ABI the app never opens is not its business, and
    a redeploy that changes a contract's interface has to change the ABI as
    well as the address or the next call fails on a function that moved.
    """
    directory = Path(contracts_dir)
    files = payload.get("artifact_files")
    if not directory.is_dir() or not isinstance(files, dict):
        return []
    written: list[str] = []
    for name, artifact in files.items():
        target = directory / str(name)
        if not target.is_file() or not isinstance(artifact, dict):
            continue
        if not isinstance(artifact.get("abi"), list):
            continue
        try:
            current = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            current = None
        if isinstance(current, dict) and current.get("abi") == artifact["abi"]:
            continue
        _write_json(target, artifact)
        written.append(str(name))
    return written


# ── When to ask ──────────────────────────────────────────────────────────────

def _state_path(base_dir) -> Path:
    return Path(base_dir) / STATE_FILENAME


def read_state(base_dir) -> dict:
    try:
        data = json.loads(_state_path(base_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(base_dir, **fields) -> None:
    state = read_state(base_dir)
    state.update(fields)
    try:
        _write_json(_state_path(base_dir), state)
    except OSError:
        pass   # a settings check must not fail over its own bookkeeping


def config_value(config_path, key: str, default=None):
    """One setting, read without importing the app's config module.

    The refresh runs before anything that reads settings properly, because the
    addresses it writes are the ones that module will turn into contracts.
    """
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    if not isinstance(data, dict):
        return default
    value = data.get(key, default)
    return default if value in ("", None) else value


def refresh(base_dir, *, contracts_dir=None, timeout=DEFAULT_TIMEOUT):
    """Manual GUI action. Stage/validate, then switch settings as one generation.

    Existing in-memory settings keep using old immutable ABIs until restart.
    No periodic polling is enabled for desktop applications.
    """
    from .ft_network_config import check, apply
    base=Path(base_dir)
    if not (base/'config.json').is_file() or not config_value(base/'config.json','network_config_url',''):
        return [], ''
    result=check(base,base,force=True)
    if result['state']=='blocked' and result.get('reason'):
        # For example an older app on a network that needs a newer one: say so.
        return [], result['reason']
    if result['state'] not in {'available','current'}:
        return [], 'Network settings could not be validated; saved settings retained.'
    try:
        changed=apply(base,base,gui=True)
    except Exception:
        return [], 'Network settings could not be activated; saved settings retained.'
    return changed, ''


# ── Command line, for install.sh and for a check by hand ─────────────────────
#
#   python3 -m core.ft_netconfig update --dir .          # ask and apply
#   python3 -m core.ft_netconfig show   --dir .          # what we last saw

def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="ft_netconfig", description=__doc__)
    parser.add_argument("command", choices=("update", "show"))
    parser.add_argument("--dir", default=".", help="the app directory")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    base = Path(args.dir)
    if args.command == "show":
        state = read_state(base)
        url = config_value(base / "config.json", "network_config_url", "")
        print(f"  network config service: {url or '(none set)'}")
        if state.get("checked_at"):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(state["checked_at"])))
            print(f"  last read: {when}  chain {state.get('chain_id', '?')}")
        else:
            print("  never read yet")
        if state.get("last_error"):
            print(f"  last problem: {state['last_error']}")
        return 0

    changed, problem = refresh(base, timeout=args.timeout)
    if problem:
        # Not an error exit: an install with no network is still an install,
        # and the app has settings to work from either way.
        if not args.quiet:
            print(f"  could not read the network settings ({problem})")
            print("  the app will use the settings it already has")
        return 0
    if not args.quiet:
        if changed:
            print(f"  network settings updated ({len(changed)} item(s))")
        else:
            print("  network settings are current")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
