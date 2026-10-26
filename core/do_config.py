# do_config.py — configuration loading, Web3 setup, contract instances, shared constants.
# No imports from other migration modules.

import os
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Tuple, List

from web3 import Web3
from .do_rpc import new_web3

# _CORE_DIR = App/DO/core/  — contracts/ lives here
# BASE_DIR  = App/DO/       — runtime data (config.json, pieces/, logs/, …) lives here
# _DO_DIR   = App/DO/       — same level; kept for resolver fallback paths
_CORE_DIR = os.path.dirname(os.path.abspath(__file__))   # App/DO/core/
BASE_DIR  = os.path.dirname(_CORE_DIR)                    # App/DO/
_DO_DIR   = BASE_DIR                                       # App/DO/ (no migration layer)
ROOT_DIR  = Path(_DO_DIR).parent.parent                      # FileTrust root
DEFAULT_CONFIG_PATH = Path(BASE_DIR) / "config.json"      # App/DO/config.json — user-editable

from .do_v2_crypto import (
    baby_add,
    baby_is_on_curve,
    baby_mul,
    v2_batch_encryption_secret,
    v2_encrypt_to_pk,
    v2_encrypt_with_shared,
    v2_lagrange_coeff,
)
from . import do_txlog as TX
from . import ft_keyvault as KEYVAULT

# --- the wallet key on disk ---------------------------------------------------

def secret_file_is_private(path) -> tuple[bool, str]:
    """Is this file readable only by the account running the app?

    The runtime data around it -- receipts, transfer state, records -- is all
    written 0600 inside 0700 directories. The wallet key is not: it lives in the
    config file, written with whatever the umask gives, and nothing looked. A
    key every local account can read defeats every signature check built on top
    of it at once, because whoever reads it simply becomes this identity.

    The mode is read back rather than inferred from chmod returning cleanly. On
    a filesystem that cannot store permissions -- NTFS or exFAT, common when an
    application lives on a second drive -- chmod succeeds and changes nothing, so
    trusting it would report every key on such a disk as protected.
    """
    import stat as _stat

    p = Path(path)
    try:
        mode = _stat.S_IMODE(os.stat(p).st_mode)
    except OSError as exc:
        return False, f"cannot read the permissions of {p}: {exc}"
    if mode & 0o077:
        return False, (
            f"{p} is mode {mode:04o}: other accounts on this machine can "
            f"read the wallet key. Move it to a filesystem that keeps "
            f"permissions and set it to 0600."
        )
    return True, "ok"


def restrict_secret_file(path) -> tuple[bool, str]:
    """Ask for 0600, then check whether it was actually granted."""
    try:
        os.chmod(Path(path), 0o600)
    except OSError:
        pass  # reported by the read-back below, with the mode that resulted
    return secret_file_is_private(path)


def _resolve_config_path(value: str | os.PathLike, base: Path) -> str:
    raw = Path(str(value)).expanduser()
    if raw.is_absolute():
        return str(raw)
    candidates = [
        (Path(_CORE_DIR) / raw).resolve(),  # DO/core/ — contracts/ lives here
        (base / raw).resolve(),             # DO/ — data files
        (Path(_DO_DIR) / raw).resolve(),    # DO/ fallback — for "../../Blockchain" paths
        (ROOT_DIR / raw).resolve(),
        (Path.cwd() / raw).resolve(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def _load_do_config() -> SimpleNamespace:
    config_path = Path(os.getenv("DO_CONFIG_PATH", str(DEFAULT_CONFIG_PATH))).expanduser()
    if not config_path.is_absolute():
        config_path = (Path(BASE_DIR) / config_path).resolve()

    defaults = {
        "RPC_URL": "https://rpc.filetrust.io",
        "RPC_TIMEOUT_SECONDS": 30,
        "RPC_READ_ATTEMPTS": 4,
        "RPC_RETRY_INITIAL_SECONDS": 0.25,
        "RPC_RETRY_MAX_SECONDS": 2.0,
        "GUARDIAN_REGISTRY_ADDRESS": "",
        "VAULT_KEEPER_REGISTRY_ADDRESS": "",
        "ACL_ADDRESS": "",
        "DV_ADDRESS": "",
        "TELG_V2_ADDRESS": "",
        "ZKDKG_COORDINATOR_V2_ADDRESS": "",
        "GUARDIAN_SHARE_PROOF_ADDRESS": "",
        "REPUTATION_MANAGER_ADDRESS": "",
        "REWARD_MANAGER_ADDRESS": "",
        "GUARDIAN_REGISTRY_JSON": "contracts/GuardianRegistry.json",
        "VAULT_KEEPER_REGISTRY_JSON": "contracts/VaultKeeperRegistry.json",
        "ACL_JSON": "contracts/AccessControlFT.json",
        "DV_JSON": "contracts/DataVault.json",
        "TELG_V2_JSON": "contracts/TElGv2.json",
        "ZKDKG_COORDINATOR_V2_JSON": "contracts/ZkDkgCoordinatorV2.json",
        "GUARDIAN_SHARE_PROOF_JSON": "contracts/GuardianShareProof.json",
        "REPUTATION_MANAGER_JSON": "contracts/ReputationManager.json",
        "REWARD_MANAGER_JSON": "contracts/RewardManager.json",
        "DO_PRIVATE_KEY": "",
        # Where this app asks for the deployed contract addresses, the RPC URL
        # and the discovery nodes: during install, and afterwards only when the
        # user asks for it from the tray. Whatever answers this URL decides
        # which chain the app talks to, so it is a setting rather than a
        # constant. The default uses HTTPS at config.filetrust.io, with
        # certificate verification enabled. Empty means
        # "never ask", for an install pinned by hand.
        "NETWORK_CONFIG_URL": "https://config.filetrust.io/v1/network-config",
        "POLICY_DKG_MODE": "ZKDKG_V2",
        "VAULTMESH_CMD": str((Path(_DO_DIR).parent / "vaultmesh").resolve()),
        "MAX_PARALLEL_PIECE_UPLOADS": 4,
        # Empty means OpenStreetMap, which serves tiles without an account. A
        # user behind a block, or with their own provider, puts that
        # provider's {z}/{x}/{y} address here, key included if it needs one.
        "MAP_TILE_SERVER": "",
        "MAP_MAX_ZOOM": 19,
        "DO_DELETION_VERIFY_ATTEMPTS": 6,
        "DO_DELETION_VERIFY_DELAY_SECONDS": 2.0,
        "DO_DELETION_MONITOR_SECONDS": 30.0,
        "DO_DELETION_EVENT_LOOKBACK_BLOCKS": 10000,
        # No built-in list. These come from the network config service during
        # install, and from "Update network settings" in the tray after that.
        # The old default pointed at 127.0.0.1, which answers on a developer's
        # machine and nowhere else -- a user whose list went missing got
        # "cannot reach discovery" with no hint that the addresses were never
        # real.
        "DISCOVERY_URLS": [],
        # Yours, and never written by the app: "Update network settings"
        # replaces discovery_urls above, so anything typed there would be
        # lost. These are asked first, and anyone will be able to run a
        # directory server. Set use_only_my_discovery_urls to ignore the
        # network's list entirely.
        "MY_DISCOVERY_URLS": [],
        "USE_ONLY_MY_DISCOVERY_URLS": False,
        "DISCOVERY_TIMEOUT_SECONDS": 2,
        "DISCOVERY_VERIFY_ENDPOINT_HASH": True,
        "DISCOVERY_REQUIRE_ENDPOINT_HASH": True,
        "DISCOVERY_ENDPOINT_CACHE_SECONDS": 30,
        "MIN_GUARDIAN_STAKE_WEI": "10000000000000000",
        "SU_TO_WEI_RATE": "1000000000000",
        "FILETRUST_FIXED_GAS_PRICE_WEI": "1000000",
        "FILE_REGISTRATION_ADDRESS": "",
        "FILE_REGISTRATION_JSON": "contracts/FileRegistrationSC.json",
        "DATAVAULT_COMBINED_V2_BATCH_UPLOAD": True,
        "DATA_VAULT_COMBINED_V2_BATCH_FUNCTION": "createV2BatchWithCids",
        "STORAGE_PROOF_ADDRESS": "",
        "STORAGE_PROOF_JSON": "contracts/StorageProofSC.json",
        "CAPACITY_PROOF_ADDRESS": "",
        "CAPACITY_PROOF_JSON": "contracts/CapacityProofSC.json",
        "VK_ESCROW_ADDRESS": "",
        "VK_ESCROW_JSON": "contracts/VKEscrow.json",
        "STORAGE_RECEIPT_DISPUTE_ADDRESS": "",
        "STORAGE_RECEIPT_DISPUTE_JSON": "contracts/StorageReceiptDispute.json",
        "STORAGE_REGISTRATION_TIMEOUT_ADDRESS": "",
        "STORAGE_REGISTRATION_TIMEOUT_JSON": "contracts/StorageRegistrationTimeout.json",
        "TRANSACTION_LOG_PATH": str(Path(BASE_DIR) / "log" / "do_transactions.jsonl"),
        "DROP_FOLDER": str(Path(BASE_DIR) / "drop"),
        "DROP_FOLDER_ENABLED": True,
        "DROP_FOLDER_DELETE_FROM_VK": False,
        "DROP_FOLDER_POLL_SECONDS": 3,
        "DROP_FOLDER_STABLE_SECONDS": 5,
        "LATEST_UPLOAD_SETTINGS": {},
        # Lower-case on purpose: the log archiver is shared by every entity and
        # looks these up by their config.json spelling first. Without them here
        # the loader dropped all three, the lookup missed, and the archiver's
        # own defaults won -- so editing the log limits in config.json did
        # nothing at all, silently, because the shipped values happened to
        # equal those defaults.
        "log_max_mb": 50,
        "log_keep_days": 14,
        "log_max_total_mb": 1000,
    }
    aliases = {
        "dkg_attempt_protocol": "DKG_ATTEMPT_PROTOCOL",
        "dkg_recovery": "DKG_RECOVERY",
        "chain_id": "CHAIN_ID",
        "staking_manager_address": "STAKING_MANAGER_ADDRESS",
        "rpc_url": "RPC_URL",
        "rpc_timeout_seconds": "RPC_TIMEOUT_SECONDS",
        "rpc_read_attempts": "RPC_READ_ATTEMPTS",
        "rpc_retry_initial_seconds": "RPC_RETRY_INITIAL_SECONDS",
        "rpc_retry_max_seconds": "RPC_RETRY_MAX_SECONDS",
        "guardian_registry_address": "GUARDIAN_REGISTRY_ADDRESS",
        "vault_keeper_registry_address": "VAULT_KEEPER_REGISTRY_ADDRESS",
        "acl_address": "ACL_ADDRESS",
        "dv_address": "DV_ADDRESS",
        "telg_v2_address": "TELG_V2_ADDRESS",
        "zkdkg_coordinator_v2_address": "ZKDKG_COORDINATOR_V2_ADDRESS",
        "guardian_share_proof_address": "GUARDIAN_SHARE_PROOF_ADDRESS",
        "reputation_manager_address": "REPUTATION_MANAGER_ADDRESS",
        "reward_manager_address": "REWARD_MANAGER_ADDRESS",
        "guardian_registry_json": "GUARDIAN_REGISTRY_JSON",
        "vault_keeper_registry_json": "VAULT_KEEPER_REGISTRY_JSON",
        "acl_json": "ACL_JSON",
        "dv_json": "DV_JSON",
        "telg_v2_json": "TELG_V2_JSON",
        "zkdkg_coordinator_v2_json": "ZKDKG_COORDINATOR_V2_JSON",
        "guardian_share_proof_json": "GUARDIAN_SHARE_PROOF_JSON",
        "reputation_manager_json": "REPUTATION_MANAGER_JSON",
        "reward_manager_json": "REWARD_MANAGER_JSON",
        "do_private_key": "DO_PRIVATE_KEY",
        "network_config_url": "NETWORK_CONFIG_URL",
        "policy_dkg_mode": "POLICY_DKG_MODE",
        "vaultmesh_cmd": "VAULTMESH_CMD",
        "max_parallel_piece_uploads": "MAX_PARALLEL_PIECE_UPLOADS",
        "map_tile_server": "MAP_TILE_SERVER",
        "map_max_zoom": "MAP_MAX_ZOOM",
        "do_deletion_verify_attempts": "DO_DELETION_VERIFY_ATTEMPTS",
        "do_deletion_verify_delay_seconds": "DO_DELETION_VERIFY_DELAY_SECONDS",
        "do_deletion_monitor_seconds": "DO_DELETION_MONITOR_SECONDS",
        "do_deletion_event_lookback_blocks": "DO_DELETION_EVENT_LOOKBACK_BLOCKS",
        "discovery_urls": "DISCOVERY_URLS",
        "my_discovery_urls": "MY_DISCOVERY_URLS",
        "use_only_my_discovery_urls": "USE_ONLY_MY_DISCOVERY_URLS",
        "discovery_timeout_seconds": "DISCOVERY_TIMEOUT_SECONDS",
        "discovery_verify_endpoint_hash": "DISCOVERY_VERIFY_ENDPOINT_HASH",
        "discovery_require_endpoint_hash": "DISCOVERY_REQUIRE_ENDPOINT_HASH",
        "discovery_endpoint_cache_seconds": "DISCOVERY_ENDPOINT_CACHE_SECONDS",
        "min_guardian_stake_wei": "MIN_GUARDIAN_STAKE_WEI",
        "su_to_wei_rate": "SU_TO_WEI_RATE",
        "filetrust_fixed_gas_price_wei": "FILETRUST_FIXED_GAS_PRICE_WEI",
        "file_registration_address": "FILE_REGISTRATION_ADDRESS",
        "file_registration_json": "FILE_REGISTRATION_JSON",
        "datavault_combined_v2_batch_upload": "DATAVAULT_COMBINED_V2_BATCH_UPLOAD",
        "data_vault_combined_v2_batch_function": "DATA_VAULT_COMBINED_V2_BATCH_FUNCTION",
        "storageproof_address": "STORAGE_PROOF_ADDRESS",
        "storageproof_json": "STORAGE_PROOF_JSON",
        "capacity_proof_address": "CAPACITY_PROOF_ADDRESS",
        "capacity_proof_json": "CAPACITY_PROOF_JSON",
        "vk_escrow_address": "VK_ESCROW_ADDRESS",
        "vk_escrow_json": "VK_ESCROW_JSON",
        "storage_receipt_dispute_address": "STORAGE_RECEIPT_DISPUTE_ADDRESS",
        "storage_receipt_dispute_json": "STORAGE_RECEIPT_DISPUTE_JSON",
        "storage_registration_timeout_address": "STORAGE_REGISTRATION_TIMEOUT_ADDRESS",
        "storage_registration_timeout_json": "STORAGE_REGISTRATION_TIMEOUT_JSON",
        "transaction_log_path": "TRANSACTION_LOG_PATH",
        "drop_folder": "DROP_FOLDER",
        "drop_folder_enabled": "DROP_FOLDER_ENABLED",
        "drop_folder_delete_from_vk": "DROP_FOLDER_DELETE_FROM_VK",
        "drop_folder_poll_seconds": "DROP_FOLDER_POLL_SECONDS",
        "drop_folder_stable_seconds": "DROP_FOLDER_STABLE_SECONDS",
        "latest_upload_settings": "LATEST_UPLOAD_SETTINGS",
    }

    raw = {}
    if config_path.is_file():
        raw = json.loads(config_path.read_text(encoding="utf-8"))

    values = dict(defaults)
    values.update(DKG_ATTEMPT_PROTOCOL=0, DKG_RECOVERY={}, CHAIN_ID=None, STAKING_MANAGER_ADDRESS="")
    for key, value in raw.items():
        canonical = aliases.get(key, key)
        if canonical in values:
            values[canonical] = value

    for key in list(values):
        if key.endswith("_JSON") or key == "VAULTMESH_CMD":
            values[key] = _resolve_config_path(values[key], Path(BASE_DIR))
    values["TRANSACTION_LOG_PATH"] = str(Path(values["TRANSACTION_LOG_PATH"]).expanduser())
    if not Path(values["TRANSACTION_LOG_PATH"]).is_absolute():
        values["TRANSACTION_LOG_PATH"] = str((Path(BASE_DIR) / values["TRANSACTION_LOG_PATH"]).resolve())
    values["DROP_FOLDER"] = str(Path(values["DROP_FOLDER"]).expanduser())
    if not Path(values["DROP_FOLDER"]).is_absolute():
        values["DROP_FOLDER"] = str((Path(BASE_DIR) / values["DROP_FOLDER"]).resolve())

    values["CONFIG_PATH"] = str(config_path)
    return SimpleNamespace(**values)


_RUNTIME_CONFIG_ALIASES = {
    "drop_folder": "DROP_FOLDER",
    "drop_folder_enabled": "DROP_FOLDER_ENABLED",
    "drop_folder_delete_from_vk": "DROP_FOLDER_DELETE_FROM_VK",
    "drop_folder_poll_seconds": "DROP_FOLDER_POLL_SECONDS",
    "drop_folder_stable_seconds": "DROP_FOLDER_STABLE_SECONDS",
    "latest_upload_settings": "LATEST_UPLOAD_SETTINGS",
}


def save_runtime_config_updates(updates: dict) -> None:
    """Merge runtime UI settings into the editable DO config file."""
    config_path = Path(getattr(config, "CONFIG_PATH", DEFAULT_CONFIG_PATH))
    raw = {}
    if config_path.is_file():
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            raw = {}

    raw.update(updates)
    config_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    # This file holds the wallet key. Everything else sensitive the app writes
    # is already 0600; this was the one that was not.
    private, reason = restrict_secret_file(config_path)
    # Only a file that really holds the key is worth the warning. With the key
    # in the vault this is a settings file with no secret in it, and saying
    # "other accounts can read the wallet key" about it is simply untrue --
    # which is worse than silence, because the one warning that does matter
    # stops being read.
    if not private and str(raw.get("do_private_key", "") or "").strip():
        print(f"[WARN] {reason}")

    for key, value in updates.items():
        canonical = _RUNTIME_CONFIG_ALIASES.get(key, key)
        if canonical == "DROP_FOLDER":
            value = str(Path(value).expanduser())
            if not Path(value).is_absolute():
                value = str((Path(BASE_DIR) / value).resolve())
        setattr(config, canonical, value)


# ── Load config ───────────────────────────────────────────────────────────────
config = _load_do_config()
DKG_ATTEMPT_PROTOCOL = config.DKG_ATTEMPT_PROTOCOL
if type(DKG_ATTEMPT_PROTOCOL) is not int or DKG_ATTEMPT_PROTOCOL not in (0, 1):
    raise ValueError("Unsupported DKG recovery protocol version")
META_PIECE_INDEX = 65535
POLICY_DKG_MODE = getattr(config, "POLICY_DKG_MODE", "LEGACY").upper()
SUPPORTED_ZKDKG_GUARDIAN_COUNTS = (3, 5, 7, 10, 15, 20)

# ── Web3 ──────────────────────────────────────────────────────────────────────
w3 = new_web3(config)

# ── Gas price ─────────────────────────────────────────────────────────────────

_gas_price_wei: Optional[int] = None


def gas_price_wei() -> int:
    """The price per unit of gas to put in the transactions this app signs.

    Gas price is a bid: it is a field inside a signed transaction, so the app
    has to choose a number before the chain ever sees it. Every call site used
    to read the number straight out of config.json, which means a node that
    raises its minimum rejects everything this app sends until somebody edits a
    file -- and nothing in the app would say why.

    So ask the node what it wants, once, and keep the configured number as the
    answer for when it cannot be reached. Deliberately not capped against the
    configured value: refusing a higher price the node has just asked for would
    recreate exactly the rejection this avoids. The chosen value is printed so
    an unexpected one is visible rather than merely paid.
    """
    global _gas_price_wei
    if _gas_price_wei is not None:
        return _gas_price_wei

    configured = 1_000_000
    try:
        configured = int(getattr(config, "FILETRUST_FIXED_GAS_PRICE_WEI", "1000000"))
    except (TypeError, ValueError):
        pass

    chosen, source = configured, "config.json"
    try:
        asked = int(w3.eth.gas_price)
        # A node that answers 0 is not telling us a price; some development
        # chains do that, and signing with 0 gets the transaction dropped.
        if asked > 0:
            chosen, source = asked, "the node"
    except Exception as exc:
        print(f"[gas] the node did not give a price ({exc}); using config.json")

    # Two threads racing here both ask the node and store the same answer.
    _gas_price_wei = chosen
    if source != "config.json" and chosen != configured:
        print(f"[gas] using {chosen} wei per gas from {source} "
              f"(config.json says {configured})")
    return chosen

# ── AccessControlFT ───────────────────────────────────────────────────────────
acl_artifact = json.loads(Path(config.ACL_JSON).read_text())
acl = w3.eth.contract(
    address=w3.to_checksum_address(config.ACL_ADDRESS),
    abi=acl_artifact["abi"],
)

# ── Guardian Registry ─────────────────────────────────────────────────────────
guardian_registry = None
try:
    gr_artifact = json.loads(Path(config.GUARDIAN_REGISTRY_JSON).read_text())
    guardian_registry = w3.eth.contract(
        address=w3.to_checksum_address(config.GUARDIAN_REGISTRY_ADDRESS),
        abi=gr_artifact["abi"],
    )
except Exception:
    guardian_registry = None

# ── Vault Keeper Registry ─────────────────────────────────────────────────────
vault_keeper_registry = None
try:
    vkr_json = getattr(config, "VAULT_KEEPER_REGISTRY_JSON", None)
    vkr_addr = getattr(config, "VAULT_KEEPER_REGISTRY_ADDRESS", None)
    if vkr_json and vkr_addr:
        vkr_artifact = json.loads(Path(vkr_json).read_text())
        vault_keeper_registry = w3.eth.contract(
            address=w3.to_checksum_address(vkr_addr),
            abi=vkr_artifact["abi"],
        )
except Exception:
    vault_keeper_registry = None

# ── Legacy DKG disabled (ZKDKG_COORDINATOR_V2 is active) ─────────────────────
dkg = None

coordinator_v2 = None
try:
    coord_addr = getattr(config, "ZKDKG_COORDINATOR_V2_ADDRESS", "")
    coord_json = getattr(config, "ZKDKG_COORDINATOR_V2_JSON", "")
    if coord_addr and coord_json:
        coord_artifact = json.loads(Path(coord_json).read_text())
        coordinator_v2 = w3.eth.contract(
            address=w3.to_checksum_address(coord_addr),
            abi=coord_artifact["abi"],
        )
except Exception:
    coordinator_v2 = None

guardian_share_proof = None
try:
    share_proof_addr = getattr(config, "GUARDIAN_SHARE_PROOF_ADDRESS", "")
    share_proof_json = getattr(config, "GUARDIAN_SHARE_PROOF_JSON", "")
    if share_proof_addr and share_proof_json:
        share_proof_artifact = json.loads(Path(share_proof_json).read_text())
        guardian_share_proof = w3.eth.contract(
            address=w3.to_checksum_address(share_proof_addr),
            abi=share_proof_artifact["abi"],
        )
except Exception:
    guardian_share_proof = None

reputation_manager = None
try:
    rep_addr = getattr(config, "REPUTATION_MANAGER_ADDRESS", "")
    rep_json = getattr(config, "REPUTATION_MANAGER_JSON", "")
    if rep_addr and rep_json:
        rep_artifact = json.loads(Path(rep_json).read_text())
        reputation_manager = w3.eth.contract(
            address=w3.to_checksum_address(rep_addr),
            abi=rep_artifact["abi"],
        )
except Exception:
    reputation_manager = None

reward_manager = None
try:
    reward_addr = getattr(config, "REWARD_MANAGER_ADDRESS", "")
    reward_json = getattr(config, "REWARD_MANAGER_JSON", "")
    if reward_addr and reward_json:
        reward_artifact = json.loads(Path(reward_json).read_text())
        reward_manager = w3.eth.contract(
            address=w3.to_checksum_address(reward_addr),
            abi=reward_artifact["abi"],
        )
except Exception:
    reward_manager = None

telg_v2 = None
try:
    telg_v2_addr = getattr(config, "TELG_V2_ADDRESS", "")
    telg_v2_json = getattr(config, "TELG_V2_JSON", "")
    if telg_v2_addr and telg_v2_json:
        telg_v2_artifact = json.loads(Path(telg_v2_json).read_text())
        telg_v2 = w3.eth.contract(
            address=w3.to_checksum_address(telg_v2_addr),
            abi=telg_v2_artifact["abi"],
        )
except Exception:
    telg_v2 = None

# ── FileRegistrationSC ────────────────────────────────────────────────────────
file_registration_sc = None
try:
    fr_addr = getattr(config, "FILE_REGISTRATION_ADDRESS", "")
    fr_json = getattr(config, "FILE_REGISTRATION_JSON", "")
    if fr_addr and fr_json:
        fr_artifact = json.loads(Path(fr_json).read_text())
        file_registration_sc = w3.eth.contract(
            address=w3.to_checksum_address(fr_addr),
            abi=fr_artifact["abi"],
        )
except Exception:
    file_registration_sc = None

# ── StorageProofSC ───────────────────────────────────────────────────────────
storage_proof_sc = None
try:
    sp_addr = getattr(config, "STORAGE_PROOF_ADDRESS", "")
    sp_json = getattr(config, "STORAGE_PROOF_JSON", "")
    if sp_addr and sp_json:
        sp_artifact = json.loads(Path(sp_json).read_text())
        storage_proof_sc = w3.eth.contract(
            address=w3.to_checksum_address(sp_addr),
            abi=sp_artifact["abi"],
        )
except Exception:
    storage_proof_sc = None

# ── CapacityProofSC ──────────────────────────────────────────────────────────
capacity_proof_sc = None
try:
    cp_addr = getattr(config, "CAPACITY_PROOF_ADDRESS", "")
    cp_json = getattr(config, "CAPACITY_PROOF_JSON", "")
    if cp_addr and cp_json:
        cp_artifact = json.loads(Path(cp_json).read_text())
        capacity_proof_sc = w3.eth.contract(
            address=w3.to_checksum_address(cp_addr),
            abi=cp_artifact["abi"],
        )
except Exception:
    capacity_proof_sc = None

# ── VKEscrow ─────────────────────────────────────────────────────────────────
vk_escrow = None
try:
    vke_addr = getattr(config, "VK_ESCROW_ADDRESS", "")
    vke_json = getattr(config, "VK_ESCROW_JSON", "")
    if vke_addr and vke_json:
        vke_artifact = json.loads(Path(vke_json).read_text())
        vk_escrow = w3.eth.contract(
            address=w3.to_checksum_address(vke_addr),
            abi=vke_artifact["abi"],
        )
except Exception:
    vk_escrow = None

# ── StorageReceiptDispute ─────────────────────────────────────────────────────
storage_receipt_dispute = None
try:
    srd_addr = getattr(config, "STORAGE_RECEIPT_DISPUTE_ADDRESS", "")
    srd_json = getattr(config, "STORAGE_RECEIPT_DISPUTE_JSON", "")
    if srd_addr and srd_json:
        srd_artifact = json.loads(Path(srd_json).read_text())
        storage_receipt_dispute = w3.eth.contract(
            address=w3.to_checksum_address(srd_addr),
            abi=srd_artifact["abi"],
        )
except Exception:
    storage_receipt_dispute = None

# ── StorageRegistrationTimeout ───────────────────────────────────────────────
storage_registration_timeout = None
try:
    srt_addr = getattr(config, "STORAGE_REGISTRATION_TIMEOUT_ADDRESS", "")
    srt_json = getattr(config, "STORAGE_REGISTRATION_TIMEOUT_JSON", "")
    if srt_addr and srt_json:
        srt_artifact = json.loads(Path(srt_json).read_text())
        storage_registration_timeout = w3.eth.contract(
            address=w3.to_checksum_address(srt_addr),
            abi=srt_artifact["abi"],
        )
except Exception:
    storage_registration_timeout = None

# ── DataVault ─────────────────────────────────────────────────────────────────
dv_artifact = json.loads(Path(config.DV_JSON).read_text())
dv = w3.eth.contract(
    address=w3.to_checksum_address(config.DV_ADDRESS),
    abi=dv_artifact["abi"],
)

# ── This account ──────────────────────────────────────────────────────────────
# The private key decides the address -- that is arithmetic, not configuration
# -- so the address is derived here and is not a setting any more. It used to be
# stored beside the key as `do_address`, which meant the two could disagree:
# `DO` came from the stored value and is used in dozens of places, the signer
# came from the key, and nothing compared them, so replacing the key and
# forgetting the address made the app act as two identities at once.
#
# A missing key is not an error here. install.sh offers to generate an account
# and a user may decline, and this module is imported before anything can tell
# them so; raising would end the process with a stack trace instead of advice.
# DO.py checks ACCOUNT_READY and explains what to do. Nothing below this point
# needs an account, and nothing that does is reachable until that check passes.
#
# No REQ constant here either. There was one, read by nothing, built from a
# `req_address` key that duplicated the requester list in
# latest_upload_settings. The list is the only record of who may download now;
# see do_actions.default_requester_address.
#
# Where the key comes from, in order: the vault DO.py already unlocked, a
# vault plus FILETRUST_KEY_PASSWORD for scripts that import this module
# directly, then config.json for an install that has not chosen a password.
DO_ACCOUNT = None
DO = ""
ACCOUNT_READY = False
ACCOUNT_PROBLEM = "no account yet"
KEYVAULT_PATH = KEYVAULT.vault_path(BASE_DIR)
KEYVAULT_IN_USE = KEYVAULT.exists(KEYVAULT_PATH)
try:
    _raw_key = KEYVAULT.unlocked_key()
    if not _raw_key and KEYVAULT_IN_USE:
        try:
            _raw_key = KEYVAULT.key_without_prompt(KEYVAULT_PATH)
        except KEYVAULT.VaultError as _vault_exc:
            _raw_key = ""
            ACCOUNT_PROBLEM = f"the key vault could not be opened: {_vault_exc}"
    if not _raw_key:
        _raw_key = str(getattr(config, "DO_PRIVATE_KEY", "") or "").strip()
    if not _raw_key and KEYVAULT_IN_USE and ACCOUNT_PROBLEM == "no account yet":
        ACCOUNT_PROBLEM = (
            "the account key is protected. Start the app with DO.py to be "
            "asked for the password, or set "
            f"{KEYVAULT.PASSWORD_ENV} for a command-line run"
        )
    if not _raw_key:
        if ACCOUNT_PROBLEM == "no account yet":
            ACCOUNT_PROBLEM = (
                "config.json has no do_private_key, so this app has no account yet"
            )
    else:
        DO_ACCOUNT = w3.eth.account.from_key(_raw_key)
        DO = w3.to_checksum_address(DO_ACCOUNT.address)
        ACCOUNT_READY = True
        ACCOUNT_PROBLEM = ""
except (ValueError, TypeError) as exc:
    ACCOUNT_PROBLEM = f"the account private key cannot be used: {exc}"

# Checked at startup, not only when the file is rewritten: a config that is
# never saved is never otherwise looked at, and the key inside it is the one
# secret whose loss cannot be recovered from by any check downstream.
#
# With a vault in use the config file holds no key, so the permissions that
# matter are the vault's -- and there the warning is milder, because the file
# is encrypted even when a stranger can read it.
if KEYVAULT_IN_USE:
    # Ask for 0600 and say nothing. On a disk that cannot keep permissions the
    # file stays readable, and that was printed at every start -- a line about
    # a file nobody can read the key out of, in front of a user who can do
    # nothing about their filesystem. The README says it once instead.
    restrict_secret_file(KEYVAULT_PATH)
    _key_private, _key_reason = True, ""
elif str(getattr(config, "DO_PRIVATE_KEY", "") or "").strip():
    _key_private, _key_reason = restrict_secret_file(getattr(config, "CONFIG_PATH", DEFAULT_CONFIG_PATH))
else:
    # No vault and no key: nothing secret is on disk yet, so there is nothing
    # to warn about. install.sh is what tells the user they have no account.
    _key_private, _key_reason = True, ""
if not _key_private:
    # A readable *encrypted* file is a note, not a warning: it can be copied
    # and attacked offline, which is worth saying, but nobody reads the key out
    # of it. Keeping the louder word for the case where the key really is in
    # the clear is the only way either line stays meaningful.
    print(f"[{'NOTE' if KEYVAULT_IN_USE else 'WARN'}] {_key_reason}")
TX.install_contract_call_logger(sys.modules[__name__])

# ── Paths ─────────────────────────────────────────────────────────────────────
VAULTMESH_CMD = getattr(config, "VAULTMESH_CMD", str((Path(BASE_DIR).parent / "vaultmesh").resolve()))
PIECES_DIR = os.path.join(BASE_DIR, "pieces")
CHUNK_SIZE = 4 * 1024 * 1024
from .do_deployment import storage_root as _deployment_storage_root
NETWORK_STATE_DIR = str(_deployment_storage_root(BASE_DIR,config))
PK_CACHE_DIR = os.path.join(NETWORK_STATE_DIR, "dkg_public_keys")
CID_RECORDS_DIR = os.path.join(NETWORK_STATE_DIR, "pid_records")
UPLOAD_ZIPS_DIR = os.path.join(BASE_DIR, "upload_zips")
os.makedirs(PK_CACHE_DIR, exist_ok=True)
os.makedirs(CID_RECORDS_DIR, exist_ok=True)
os.makedirs(UPLOAD_ZIPS_DIR, exist_ok=True)

# ── EC curve parameters (secp256k1) ──────────────────────────────────────────
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Point = Optional[Tuple[int, int]]

