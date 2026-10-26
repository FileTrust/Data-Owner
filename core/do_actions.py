# do_actions.py — GUI action callbacks and orchestration.

import os
import json
import datetime
import threading
import concurrent.futures
import itertools
import time
import secrets
import string
import zipfile
import hashlib
import struct
import tempfile
import re
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from . import do_config as C
from . import do_state as S
from . import do_log as L
from . import do_records as R
from . import do_chain as CH
from . import do_txlog as TX
from . import do_tx_manager as TM
from . import do_vaultmesh as VM
from . import do_network as N
from . import do_hex as HX
from . import do_piece_journal as PJ
from . import do_progress as PROG
from . import do_deletion_redrive as DR
from .do_crypto import (
    xor_stream_encrypt, encrypt_with_default_paths, decrypt_file,
    ida_disperse_file, ida_reconstruct_file,
)


_TX_GAS_VALUES_CACHE = None
_PENDING_DELETION_RECONCILE_JOB = None
_PENDING_DELETION_MONITOR_LOCK = threading.Lock()
_PENDING_DELETION_MONITOR_RUNNING = False
_PENDING_DKG_RECONCILE_JOB = None
_PENDING_DKG_RECONCILE_RUNNING = False


def get_current_file_context(show_errors: bool = True):
    policy_name = S.entry_policy_name.get().strip() if S.entry_policy_name is not None else ""
    if not policy_name:
        if show_errors:
            L.show_error("Error", "Please enter a Policy Name first.")
        return None

    data_tag = S.entry_device_id.get().strip() if S.entry_device_id is not None else ""
    if not data_tag:
        if show_errors:
            L.show_error("Error", "Please enter a Data Tag first.")
        return None

    date_str = S.selected_datetime_var.get().strip() if S.selected_datetime_var is not None else ""
    if not date_str or "No date" in date_str:
        if show_errors:
            L.show_error("Error", "Please select a date first.")
        return None

    try:
        target_date = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        if show_errors:
            L.show_error("Error", "Date must be in format YYYY-MM-DD.")
        return None

    ts = int(
        datetime.datetime(
            target_date.year,
            target_date.month,
            target_date.day,
            tzinfo=datetime.timezone.utc,
        ).timestamp()
    )

    # doInput is a unique nonce derived from the DO address and policy name.
    # ACL stores the policy under keccak256(abi.encodePacked(msg.sender, doInput)),
    # so we mirror that computation here to get the actual on-chain fileId.
    do_input = C.w3.keccak(text=f"{C.DO.lower()}|POLICY|{policy_name}")
    file_id = C.w3.solidity_keccak(['address', 'bytes32'], [C.DO, do_input])
    file_id_hex = file_id.hex()

    return file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts


def new_data_tag() -> str:
    """A fresh Data Tag: three letters then three digits, e.g. "KTM407".

    Short enough to read out and type back, and different every time, so two
    uploads do not end up sharing a policy id by leaving the box as it was.
    """
    letters = "".join(secrets.choice(string.ascii_uppercase) for _ in range(3))
    digits = "".join(secrets.choice(string.digits) for _ in range(3))
    return letters + digits


def refresh_file_id_preview():
    if S.file_id_var is None:
        return

    ctx = get_current_file_context(show_errors=False)
    if not ctx:
        S.file_id_var.set("policyId: waiting for Data Tag + Date")
        return

    _, file_id_hex, _, policy_name, data_tag, date_str, _ = ctx
    # The whole id. It is what every other tool in this system identifies the
    # policy by, and an id you cannot copy in full is an id you cannot use.
    S.file_id_var.set(
        f"policyId: {file_id_hex}   policy={policy_name}, batch=({data_tag}, {date_str})"
    )


def get_policy_for_current_file(show_errors: bool = True):
    ctx = get_current_file_context(show_errors=show_errors)
    if not ctx:
        return None

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx

    try:
        exists, active, owner, threshold, guardians = C.acl.functions.getFilePolicy(file_id).call()
        return {
            "file_id": file_id,
            "file_id_hex": file_id_hex,
            "data_tag": data_tag,
            "date_str": date_str,
            "timestamp": ts,
            "exists": bool(exists),
            "active": bool(active),
            "owner": owner,
            "threshold": int(threshold),
            "guardians": [C.w3.to_checksum_address(g) for g in guardians],
        }
    except Exception as e:
        if show_errors:
            L.show_error("Policy error", str(e))
        L.log(f"Policy read error: {e}")
        return None


def show_current_file_policy():
    policy = get_policy_for_current_file()
    if not policy:
        return False

    L.log("=== Current file policy ===")
    L.log(f"policyId: {policy['file_id_hex']}")
    L.log(f"exists: {policy['exists']}")
    L.log(f"active: {policy['active']}")
    L.log(f"owner: {policy['owner']}")
    L.log(f"guardian threshold: {policy['threshold']}")
    L.log(f"guardians: {len(policy['guardians'])}")

    for i, guardian in enumerate(policy["guardians"], start=1):
        L.log(f"  {i}. {guardian}")

    L.log("")

    status = "active" if policy["active"] else "inactive"
    N.set_policy_status_text(
        f"Policy: {'exists' if policy['exists'] else 'not created'} | "
        f"{status} | guardians={len(policy['guardians'])} | guardian_t={policy['threshold']}"
    )

    if S.entry_guardian_t is not None and policy["threshold"] > 0:
        S.entry_guardian_t.delete(0, tk.END)
        S.entry_guardian_t.insert(0, str(policy["threshold"]))
    if S.entry_guardian_n is not None:
        S.entry_guardian_n.delete(0, tk.END)
        S.entry_guardian_n.insert(0, str(len(policy["guardians"])))

    N.select_policy_guardians_in_listbox(policy["guardians"])
    _set_policy_active_button(bool(policy["active"]))
    return True


def _set_policy_active_button(active: bool) -> None:
    """Label the one policy button from a state already read."""
    button = S.policy_active_button
    if button is None:
        return
    try:
        if active:
            button.configure(text="Deactivate Policy", fg_color="#4a0e0e",
                             hover_color="#6b1414", text_color="#f87171")
        else:
            button.configure(text="Activate Policy", fg_color="#2f3a5e",
                             hover_color="#374468", text_color="#FFD700")
    except Exception:
        pass


def create_or_update_file_policy():
    ctx = get_current_file_context()
    if not ctx:
        return False

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx

    selected_guardians = S.staged_guardians if S.staged_guardians else N.get_selected_guardians()
    if not selected_guardians:
        L.show_error(
            "No Guardians staged",
            "Select Guardians from the table and click 'Add Selected' to stage them,\n"
            "then click 'Create / Update Policy'.",
        )
        return False

    threshold = N.get_guardian_threshold()
    if threshold is None:
        L.show_error("Input error", "Guardian threshold must be an integer.")
        return False

    if threshold <= 0 or threshold > len(selected_guardians):
        L.show_error(
            "Guardian error",
            "Guardian threshold must be > 0 and <= selected Guardians.",
        )
        return False

    if not _validate_supported_zkdkg_threshold(threshold, len(selected_guardians)):
        return False

    if not _validate_supported_zkdkg_guardian_count(len(selected_guardians), source=_guardian_selection_source_text()):
        return False

    try:
        L.set_status("Preparing file policy...", "running")
        duration_days = N.get_service_duration_days()
        price_rows, dkg_su, custody_su_per_day, pre_su = N.summarize_selected_guardian_prices(selected_guardians, threshold)
        unsuitable = [
            row for row in price_rows
            if int(row.get("max_service_days", 0)) > 0 and duration_days > int(row["max_service_days"])
        ]
        if unsuitable:
            row = unsuitable[0]
            msg = (
                f"Guardian {row['address']} is available for {row['max_service_days']} days, "
                f"but requested service duration is {duration_days} days."
            )
            L.show_error("Guardian availability error", msg)
            L.log(msg)
            L.set_status("Guardian availability error", "error")
            return False

        exists, _, _, _, _ = C.acl.functions.getFilePolicy(file_id).call()

        acl_service_days = duration_days if C.POLICY_DKG_MODE == "ZKDKG_V2" else 0
        if exists:
            fn = C.acl.functions.updateFilePolicy(file_id, selected_guardians, threshold, acl_service_days)
            label = "File policy updated"
            L.set_status("Updating policy on blockchain...", "running")
        else:
            if C.POLICY_DKG_MODE == "ZKDKG_V2":
                fn = C.acl.functions.createFilePolicyWithMode(do_input, selected_guardians, threshold, 1, acl_service_days)
            else:
                fn = C.acl.functions.createFilePolicy(do_input, selected_guardians, threshold)
            label = "File policy created"
            L.set_status("Creating policy on blockchain...", "running")

        L.log("=== File policy ===")
        L.log(f"policyId: {file_id_hex}")
        L.log(f"selected guardians: {len(selected_guardians)}")
        L.log(f"guardian threshold: {threshold}")
        L.log(f"DKG mode: {C.POLICY_DKG_MODE}")
        if C.POLICY_DKG_MODE == "ZKDKG_V2":
            custody_su_total = duration_days * custody_su_per_day
            total_guardian_su = dkg_su + custody_su_total
            L.log("=== Guardian service price estimate ===")
            for row in price_rows:
                L.log(
                    f"{row['address']} | DKG material={row['dkg_material_su']} SU, "
                    f"shareKey={row['dkg_share_key_su']} SU, PRE={row['pre_batch_partial_su']} SU, "
                    f"daily custody={row['daily_share_custody_su']} SU/day "
                    f"maxDays={'unlimited' if int(row.get('max_service_days', 0)) == 0 else row['max_service_days']} "
                    f"({row['price_source']})"
                )
            L.log(f"Service duration: {duration_days} day(s)")
            L.log(f"Estimated DO DKG service incentive: {dkg_su} SU ({N._format_ftu_from_su(dkg_su)})")
            L.log(
                f"Estimated Guardian daily custody: {custody_su_per_day} SU/day x {duration_days} "
                f"= {custody_su_total} SU ({N._format_ftu_from_su(custody_su_total)})"
            )
            L.log(f"Estimated total Guardian SU for policy period: {total_guardian_su} SU ({N._format_ftu_from_su(total_guardian_su)})")
            L.log(f"Estimated REQ PRE incentive for cheapest threshold: {pre_su} SU ({N._format_ftu_from_su(pre_su)})")
            L.log("Guardian prices are dynamic; these estimates are based on current on-chain prices.")
            L.log("Gas reimbursement is estimated separately and settled from measured verified work.")
            L.log("Daily share-custody is an estimate here; it is settled from "
                  "measured work, not reserved now.")

        CH.send_signed_tx(fn, C.DO_ACCOUNT, label)
        if C.POLICY_DKG_MODE == "ZKDKG_V2":
            CH.register_policy_service_period(
                file_id,
                duration_days,
                allow_replace=bool(exists),
            )
        refresh_file_id_preview()
        show_current_file_policy()
        R.save_policy_record(policy_name, file_id_hex, selected_guardians, threshold)
        save_latest_upload_settings(show_log=True)
        S.root.after(0, load_policies_browser)
        L.set_status("Policy ready", "done")
        L.show_info(label, "Policy transaction submitted and saved locally.")
        return True

    except Exception as e:
        L.show_error("File policy error", str(e))
        L.log(f"File policy error: {e}")
        L.set_status("Policy error", "error")
        return False


def _auto_select_enabled() -> bool:
    try:
        return bool(S.auto_select_var is not None and S.auto_select_var.get())
    except Exception:
        return False


def _entry_text(entry, default: str = "") -> str:
    try:
        value = entry.get().strip()
        return value if value else default
    except Exception:
        return default


def _entry_int_value(entry, default: int) -> int:
    try:
        return int(entry.get())
    except Exception:
        return int(default)


def _set_entry_text(entry, value) -> None:
    if entry is None:
        return
    try:
        entry.delete(0, tk.END)
        entry.insert(0, str(value))
    except Exception:
        pass


def _policy_record_for_name(policy_name: str) -> dict:
    if not policy_name:
        return {}
    return R.load_policies_record().get(policy_name.lower(), {})


def _current_guardian_count(policy_name: str, threshold: int) -> int:
    guardians = S.staged_guardians or N.get_selected_guardians()
    if guardians:
        return len(guardians)

    requested_count = _entry_int_value(S.entry_guardian_n, 0)
    if requested_count > 0:
        return max(int(threshold or 0), requested_count)

    rec = _policy_record_for_name(policy_name)
    recorded = rec.get("guardians") or []
    if recorded:
        return len(recorded)

    return max(5, int(threshold or 0))


def _normalize_requester_entry(req) -> dict | None:
    if isinstance(req, dict):
        addr = str(req.get("address") or "").strip()
        name = str(req.get("name") or "").strip()
    else:
        addr = str(req or "").strip()
        name = ""
    if not addr:
        return None
    try:
        addr = C.w3.to_checksum_address(addr)
    except Exception:
        pass
    return {"address": addr, "name": name}


def default_requester_address() -> str:
    """The requester address to offer when the user has not typed one.

    The requester list is the only record of who may download: it is per
    policy, it carries names, it is edited in the app window and it is what an
    upload actually uses. config.json used to carry a second single-address
    copy as well, which left a user wondering which of the two mattered and
    let the weaker one win. There is one place now.

    An empty list means there is nothing to offer, and the box is left empty.
    """
    for req in _normalize_requester_list(_saved_upload_settings().get("requesters") or []):
        if req.get("address"):
            return req["address"]
    return ""


def _saved_requesters_for_policy(policy_name: str) -> list[dict]:
    settings = _saved_upload_settings()
    saved_policy = str(settings.get("policy_name") or "").strip()
    if saved_policy and policy_name and saved_policy.lower() != policy_name.lower():
        return []
    return _normalize_requester_list(settings.get("requesters") or [])


def _normalize_requester_list(requesters) -> list[dict]:
    out = []
    seen = set()
    for req in requesters or []:
        normalized = _normalize_requester_entry(req)
        if not normalized:
            continue
        key = normalized["address"].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _policy_requesters_from_ui(policy_name: str) -> list[dict]:
    requesters = []

    def add(req) -> None:
        normalized = _normalize_requester_entry(req)
        if normalized:
            requesters.append(normalized)

    for req in R.get_policy_requesters(policy_name):
        add(req)

    if S.req_book_tree is not None:
        for iid in S.req_book_tree.get_children():
            vals = S.req_book_tree.item(iid, "values")
            if vals and len(vals) > 1:
                name = "" if vals[0] == "—" else vals[0]
                add({"name": name, "address": vals[1]})

    return _normalize_requester_list(requesters)


def _current_policy_requesters(
    policy_name: str,
    *,
    include_requester_entry: bool = False,
    prefer_policy_record: bool = False,
) -> list[dict]:
    policy_requesters = _policy_requesters_from_ui(policy_name)
    saved_requesters = [] if prefer_policy_record else _saved_requesters_for_policy(policy_name)
    requesters = policy_requesters if policy_requesters else saved_requesters

    if include_requester_entry:
        entry_req = _normalize_requester_entry({
            "address": _entry_text(S.entry_req_address, ""),
            "name": _entry_text(S.entry_req_name, ""),
        })
        if entry_req:
            requesters = list(requesters) + [entry_req]

    return _normalize_requester_list(requesters)


def _latest_upload_settings_from_ui(
    *,
    include_requester_entry: bool = False,
    prefer_policy_requesters: bool = False,
) -> dict:
    policy_name = _entry_text(S.entry_policy_name, "Policy01")
    service_days = max(1, _entry_int_value(S.entry_service_days, 30))
    guardian_t = max(1, _entry_int_value(S.entry_guardian_t, 3))
    ida_n = max(1, _entry_int_value(S.entry_n, 6))
    ida_t = max(1, min(ida_n, _entry_int_value(S.entry_t, min(ida_n, 4))))

    try:
        aes_enabled = bool(S.chk_var is not None and S.chk_var.get())
    except Exception:
        aes_enabled = False

    try:
        auto_select = bool(S.auto_select_var is not None and S.auto_select_var.get())
    except Exception:
        auto_select = True

    return {
        "policy_name": policy_name,
        "service_days": service_days,
        "guardian_count": _current_guardian_count(policy_name, guardian_t),
        "guardian_threshold": guardian_t,
        "ida_n": ida_n,
        "ida_t": ida_t,
        "aes_enabled": aes_enabled,
        "auto_select": auto_select,
        "requesters": _current_policy_requesters(
            policy_name,
            include_requester_entry=include_requester_entry,
            prefer_policy_record=prefer_policy_requesters,
        ),
        "updated_at": datetime.datetime.now().astimezone().isoformat(),
    }


def _saved_upload_settings() -> dict:
    raw = getattr(C.config, "LATEST_UPLOAD_SETTINGS", {}) or {}
    if not isinstance(raw, dict):
        return {}
    settings = dict(raw)
    settings.pop("vault_keeper_peers", None)
    return settings


def save_latest_upload_settings(
    show_log: bool = False,
    *,
    include_requester_entry: bool = False,
    prefer_policy_requesters: bool = False,
) -> dict:
    if S.entry_policy_name is None:
        return {}

    settings = _latest_upload_settings_from_ui(
        include_requester_entry=include_requester_entry,
        prefer_policy_requesters=prefer_policy_requesters,
    )
    try:
        C.save_runtime_config_updates({"latest_upload_settings": settings})
        if show_log:
            L.log(
                "Latest upload settings saved: "
                f"policy={settings['policy_name']}, "
                f"Guardians n={settings['guardian_count']}/t={settings['guardian_threshold']}, "
                f"IDA n={settings['ida_n']}/t={settings['ida_t']}, "
                f"serviceDays={settings['service_days']}, "
                f"AES={'on' if settings['aes_enabled'] else 'off'}, "
                f"requesters={len(settings.get('requesters') or [])}"
            )
    except Exception as exc:
        L.log(f"Could not save latest upload settings: {exc}")
    return settings


def save_upload_setup() -> dict:
    """Kept for the drop-folder path and tests; the button for it is gone.

    Every field saves itself as it is typed, so this adds only the requester a
    user typed without pressing Add -- which an upload now saves for itself.
    """
    settings = save_latest_upload_settings(show_log=True, include_requester_entry=True)
    if not settings:
        return {}
    L.set_status("Upload setup saved", "done")
    L.log(
        "Drop folder setup saved; new drop-folder uploads will use "
        f"policy '{settings['policy_name']}'."
    )
    return settings


def schedule_latest_upload_settings_save(delay_ms: int = 600) -> None:
    if S.root is None:
        save_latest_upload_settings()
        return
    try:
        if S.drop_folder_settings_save_job is not None:
            S.root.after_cancel(S.drop_folder_settings_save_job)
    except Exception:
        pass
    S.drop_folder_settings_save_job = S.root.after(delay_ms, save_latest_upload_settings)


def restore_latest_upload_settings() -> None:
    settings = _saved_upload_settings()
    if not settings:
        return

    policy_name = str(settings.get("policy_name") or "Policy01")
    if S.entry_policy_name is not None:
        try:
            S.entry_policy_name.set(policy_name)
        except Exception:
            pass
    _set_entry_text(S.entry_service_days, settings.get("service_days", 30))
    _set_entry_text(S.entry_guardian_n, settings.get("guardian_count", 5))
    _set_entry_text(S.entry_guardian_t, settings.get("guardian_threshold", 3))
    _set_entry_text(S.entry_n, settings.get("ida_n", 6))
    _set_entry_text(S.entry_t, settings.get("ida_t", 4))

    if S.chk_var is not None:
        try:
            S.chk_var.set(bool(settings.get("aes_enabled", False)))
        except Exception:
            pass
    if S.auto_select_var is not None:
        try:
            S.auto_select_var.set(bool(settings.get("auto_select", True)))
        except Exception:
            pass

    requesters = _normalize_requester_list(settings.get("requesters") or [])
    if requesters:
        first = requesters[0]
        _set_entry_text(S.entry_req_name, first.get("name", ""))
        _set_entry_text(S.entry_req_address, first.get("address", ""))
    refresh_file_id_preview()
    N.refresh_ida_info()


def _auto_profile_from_settings() -> dict:
    settings = dict(_saved_upload_settings())
    current = _latest_upload_settings_from_ui()
    settings.update({k: v for k, v in current.items() if v not in (None, "")})

    guardian_t = max(1, int(settings.get("guardian_threshold") or 3))
    ida_n = max(1, int(settings.get("ida_n") or 6))
    return {
        "service_days": max(1, int(settings.get("service_days") or 30)),
        "guardian_n": max(guardian_t, int(settings.get("guardian_count") or 5)),
        "guardian_t": guardian_t,
        "vk_n": ida_n,
        "vk_t": max(1, min(ida_n, int(settings.get("ida_t") or min(4, ida_n)))),
    }


def apply_auto_selection_from_latest(show_errors: bool = True) -> bool:
    profile = _auto_profile_from_settings()
    return N.apply_auto_selection(
        service_days=profile["service_days"],
        guardian_n=profile["guardian_n"],
        guardian_t=profile["guardian_t"],
        vk_n=profile["vk_n"],
        vk_t=profile["vk_t"],
        show_errors=show_errors,
    )


def _current_policy_tuple(file_id: bytes):
    exists, active, owner, threshold, guardians = C.acl.functions.getFilePolicy(file_id).call()
    return bool(exists), bool(active), owner, int(threshold), [C.w3.to_checksum_address(g) for g in guardians]


def _ensure_saved_requesters_for_policy(file_id: bytes, file_id_hex: str, policy_name: str) -> bool:
    requesters = _saved_requesters_for_policy(policy_name)
    if not requesters:
        return True

    try:
        exists, _active, _owner, threshold, guardians = _current_policy_tuple(file_id)
        if exists:
            R.save_policy_record(policy_name, file_id_hex, guardians, threshold)
    except Exception as exc:
        L.log(f"[auto] could not refresh local policy record before requester setup: {exc}")

    added = 0
    for req in requesters:
        name = str(req.get("name") or "").strip()
        try:
            addr = C.w3.to_checksum_address(str(req.get("address") or "").strip())
        except Exception as exc:
            L.show_error("Requester setup error", f"Saved requester address is invalid: {req.get('address')}")
            L.log(f"[auto] invalid saved requester address: {req.get('address')} ({exc})")
            return False

        try:
            if C.acl.functions.isRequesterForFile(file_id, addr).call():
                R._update_policy_requesters(policy_name, addr, add=True, name=name)
                continue

            L.log(f"[auto] adding saved requester to policy: {addr}")
            fn = C.acl.functions.addRequesterToFile(file_id, addr)
            CH.send_signed_tx(fn, C.DO_ACCOUNT, f"Requester added {addr[:10]}...")
            R._update_policy_requesters(policy_name, addr, add=True, name=name)
            added += 1
        except Exception as exc:
            L.show_error("Requester setup error", str(exc))
            L.log(f"[auto] requester setup error for {addr}: {exc}")
            return False

    if added:
        L.log(f"[auto] added {added} saved requester(s) to policy '{policy_name}'.")
    save_latest_upload_settings(prefer_policy_requesters=True)
    if S.root is not None:
        S.root.after(0, N.load_policy_requesters_ui)
        S.root.after(0, load_policies_browser)
    return True


def _policy_has_local_or_finalized_key(file_id: bytes, file_id_hex: str, owner: str, threshold: int, guardians: list[str]) -> bool:
    try:
        if getattr(C, "DKG_ATTEMPT_PROTOCOL", 0) != 1 and CH.load_pk_json(expected_file_id_hex=file_id_hex):
            return True
    except Exception:
        pass

    if C.POLICY_DKG_MODE == "ZKDKG_V2" and C.coordinator_v2 is not None:
        try:
            key_exists, finalized, _data_owner, _t, _n, _epoch, _share_version, _pkx, _pky = (
                C.coordinator_v2.functions.getV2Key(file_id).call()
            )
            if bool(key_exists) and bool(finalized):
                return CH.poll_zkdkg_v2_for_key(file_id, file_id_hex, owner, int(threshold), len(guardians))
        except Exception as exc:
            L.log(f"[auto] could not check finalized V2 key: {exc}")

    return False


def _resume_auto_upload_after_key() -> None:
    if not S.auto_upload_pending:
        return
    S.auto_upload_pending = False
    L.log("[auto] key is ready; resuming upload.")
    L.set_status("Auto key ready; resuming upload...", "running")
    threading.Thread(target=run_all, daemon=True).start()


def _auto_prepare_for_upload(file_id: bytes, file_id_hex: str, policy_name: str) -> bool:
    """Return True when upload can continue, False when auto flow is waiting."""
    S.auto_quiet_info = True
    profile = _auto_profile_from_settings()
    service_days = profile["service_days"]
    guardian_n = profile["guardian_n"]
    guardian_t = profile["guardian_t"]
    vk_n = profile["vk_n"]
    vk_t = profile["vk_t"]

    N.set_auto_defaults(
        service_days=service_days,
        guardian_t=guardian_t,
        ida_n=vk_n,
        ida_t=vk_t,
        guardian_n=guardian_n,
    )
    L.log(
        f"[auto] latest settings: serviceDays={service_days}, Guardians n={guardian_n}/t={guardian_t}, "
        f"VaultKeepers n={vk_n}/t={vk_t}"
    )

    try:
        exists, active, owner, threshold, guardians = _current_policy_tuple(file_id)
    except Exception as exc:
        S.auto_quiet_info = False
        L.show_error("Auto policy check error", str(exc))
        L.log(f"[auto] policy check error: {exc}")
        L.set_status("Auto policy check error", "error")
        return False

    if getattr(C, "DKG_ATTEMPT_PROTOCOL", 0) == 1:
        # Policy creation and the custody period are part of the approved DKG
        # debit cap. Never send these through the older auto-upload preamble.
        if exists:
            if not active:
                S.auto_quiet_info = False
                L.show_error("Guardian recovery", "Activate this policy before starting its Guardian key operation")
                return False
            N.select_existing_policy_guardians(guardians, threshold)
        else:
            try:
                guardians = N.select_best_guardians(count=guardian_n, threshold=guardian_t, service_days=service_days)
                threshold = guardian_t
            except Exception as exc:
                S.auto_quiet_info = False
                L.show_error("Auto Guardian selection error", str(exc))
                return False
        if not exists or not _policy_has_local_or_finalized_key(file_id, file_id_hex, owner, threshold, guardians):
            S.auto_upload_pending = True
            run_keygen_request()
            return False

    if exists:
        N.select_existing_policy_guardians(guardians, threshold)
        L.log(f"[auto] existing policy found; preserving {len(guardians)} Guardian(s), t={threshold}.")
        if not active:
            L.log("[auto] existing policy is inactive; activating it.")
            if not set_current_file_policy_active(True):
                S.auto_quiet_info = False
                L.set_status("Auto policy activation failed", "error")
                return False
            exists, active, owner, threshold, guardians = _current_policy_tuple(file_id)
    else:
        try:
            guardians = N.select_best_guardians(count=guardian_n, threshold=guardian_t, service_days=service_days)
        except Exception as exc:
            S.auto_quiet_info = False
            L.show_error("Auto Guardian selection error", str(exc))
            L.log(f"[auto] Guardian selection error: {exc}")
            L.set_status("Auto Guardian selection failed", "error")
            return False

        if not create_or_update_file_policy():
            S.auto_quiet_info = False
            L.set_status("Auto policy creation failed", "error")
            return False
        exists, active, owner, threshold, guardians = _current_policy_tuple(file_id)
        if not active:
            L.log("[auto] newly created policy is inactive; activating it.")
            if not set_current_file_policy_active(True):
                S.auto_quiet_info = False
                L.set_status("Auto policy activation failed", "error")
                return False
            exists, active, owner, threshold, guardians = _current_policy_tuple(file_id)

    if C.POLICY_DKG_MODE == "ZKDKG_V2" and getattr(C, "DKG_ATTEMPT_PROTOCOL", 0) != 1:
        try:
            CH.register_policy_service_period(file_id, service_days)
        except Exception as exc:
            S.auto_quiet_info = False
            L.show_error("Guardian service period error", str(exc))
            L.log(f"[auto] Guardian service period reconciliation failed: {exc}")
            L.set_status("Guardian service period error", "error")
            return False

    if S.drop_folder_current_item:
        L.log("[auto] drop-folder upload: preserving existing requester policy; no requester add/revoke.")
    elif not _ensure_saved_requesters_for_policy(file_id, file_id_hex, policy_name):
        S.auto_quiet_info = False
        L.set_status("Auto requester setup failed", "error")
        return False

    try:
        N.select_best_vault_keepers(count=vk_n, threshold=vk_t, service_days=service_days)
    except Exception as exc:
        S.auto_quiet_info = False
        L.show_error("Auto VaultKeeper selection error", str(exc))
        L.log(f"[auto] VaultKeeper selection error: {exc}")
        L.set_status("Auto VK selection failed", "error")
        return False

    if _policy_has_local_or_finalized_key(file_id, file_id_hex, owner, threshold, guardians):
        L.log("[auto] DKG key already exists; skipping key generation.")
        return True

    L.log("[auto] no finalized/local DKG key yet; requesting key generation and upload will resume automatically.")
    S.auto_upload_pending = True
    run_keygen_request()
    return False


def get_threshold_for_guardian_count(count: int, fallback_threshold: int = 0) -> int:
    threshold = N.get_guardian_threshold(default=fallback_threshold)

    if threshold is None or threshold <= 0:
        threshold = fallback_threshold

    return threshold


def _guardian_selection_source_text() -> str:
    if S.staged_guardians:
        return "staged Guardians"
    return "current table selection"


def _validate_supported_zkdkg_guardian_count(count: int, *, allow_zero: bool = False, source: str | None = None) -> bool:
    supported_counts = set(getattr(C, "SUPPORTED_ZKDKG_GUARDIAN_COUNTS", (3, 5, 7, 10, 15, 20)))
    if C.POLICY_DKG_MODE != "ZKDKG_V2":
        return True
    if allow_zero and count == 0:
        return True
    if count in supported_counts:
        return True
    allowed = ", ".join(str(n) for n in sorted(supported_counts))
    L.show_error(
        "Guardian count error",
        f"ZKDKG_V2 supports only these Guardian counts: {allowed}.\n\n"
        f"Selected Guardians: {count}"
        f"{f' ({source})' if source else ''}.\n\n"
        "If this is from staged Guardians, use Revoke Selected or Clear Staged, then add the correct set again.",
    )
    L.log(f"Guardian count error: selected={count}; source={source or 'unknown'}; supported ZKDKG_V2 counts={allowed}")
    L.set_status("Unsupported Guardian count", "error")
    return False


def _validate_supported_zkdkg_threshold(threshold: int, guardian_count: int) -> bool:
    if C.POLICY_DKG_MODE != "ZKDKG_V2":
        return True
    if guardian_count == 0:
        return True
    if threshold >= 2:
        return True
    L.show_error("Guardian threshold error", "ZKDKG_V2 threshold must be at least 2.")
    L.log(f"Guardian threshold error: selected threshold={threshold}; ZKDKG_V2 minimum is 2")
    L.set_status("Unsupported Guardian threshold", "error")
    return False


def add_selected_guardians_to_policy():
    selected = N.get_selected_guardians()
    if not selected:
        L.show_error("Guardian error", "Select guardian(s) from the table first.")
        return False

    duration_days = N.get_service_duration_days()
    by_addr = {row["address"].lower(): row for row in S.guardian_display_records}
    incompatible = []
    for addr in selected:
        row = by_addr.get(addr.lower())
        if row:
            max_days = int(row.get("max_service_days", 0))
            if max_days > 0 and duration_days > max_days:
                incompatible.append((addr, max_days))

    if incompatible:
        lines = "\n".join(
            f"  {a[:20]}… — max {d} days  (requested: {duration_days})"
            for a, d in incompatible
        )
        L.show_warning(
            "Guardian availability",
            f"The following Guardian(s) are not available for {duration_days} days:\n\n{lines}\n\n"
            "'Create / Update Policy' will be blocked until these are removed\n"
            "or the Service Days value is reduced.",
        )

    # The table is discovery's directory, which is not trusted. Every guardian
    # picked is checked field by field against the chain, and its row then
    # holds the chain's values; one the chain disagrees about is not staged.
    incompatible_set = {a.lower() for a, _d in incompatible}
    refused = []
    for addr in selected:
        row = by_addr.get(addr.lower())
        if row is None or addr.lower() in incompatible_set:
            continue
        ok, reason = N._verify_guardian_before_use(row)
        if not ok:
            refused.append((addr, reason))
    if refused:
        lines = "\n".join(f"  {a[:20]}… — {r}" for a, r in refused)
        L.show_warning(
            "Guardian check",
            f"The chain disagrees with the directory about these Guardian(s); they were not staged:\n\n{lines}",
        )
        L.log(f"Guardian check refused {len(refused)}: " + "; ".join(f"{a[:14]} ({r})" for a, r in refused))
    refused_set = {a.lower() for a, _r in refused}

    for addr in selected:
        if addr.lower() in refused_set:
            continue
        if addr.lower() not in [g.lower() for g in S.staged_guardians]:
            S.staged_guardians.append(addr)

    estimate = _update_staged_g_status()
    L.log(f"Staged guardians: {len(S.staged_guardians)} — click 'Create / Update Policy' to apply on-chain.")
    _log_staged_guardian_cost_estimate(estimate)
    return True


def _update_staged_g_status():
    if S.staged_guardians:
        estimate = _staged_guardian_cost_estimate()
        if S.staged_g_status_var is not None:
            if estimate.get("ok"):
                dkg_total = estimate["dkg_do_outlay_wei"]
                pre_min = estimate["pre_requester_outlay_min_wei"]
                pre_max = estimate["pre_requester_outlay_max_wei"]
                S.staged_g_status_var.set(
                    f"Staged: {len(S.staged_guardians)} Guardian(s), t={estimate['threshold']} | "
                    f"DKG DO {_format_wei_as_eth(dkg_total)} | "
                    f"PRE REQ {_format_wei_range(pre_min, pre_max)}"
                )
            else:
                reason = str(estimate.get("reason") or "cost estimate unavailable")
                if len(reason) > 80:
                    reason = reason[:77] + "..."
                S.staged_g_status_var.set(
                    f"Staged: {len(S.staged_guardians)} Guardian(s) | {reason}"
                )
        return estimate

    if S.staged_g_status_var is not None:
        S.staged_g_status_var.set("Staged Guardians: none")
    return {"ok": False, "reason": "No staged Guardians"}


def _staged_guardian_cost_estimate():
    guardians = _staged_guardians_checksum()
    count = len(guardians)
    if count <= 0:
        return {"ok": False, "reason": "No staged Guardians"}

    threshold = N.get_guardian_threshold()
    if threshold is None or threshold <= 0:
        return {"ok": False, "reason": "Set a valid Guardian threshold to estimate DKG/PRE ETH cost"}
    if threshold > count:
        return {
            "ok": False,
            "reason": f"Threshold {threshold} exceeds {count} staged Guardian(s)",
            "threshold": threshold,
        }

    try:
        dkg_escrow_wei, dkg_escrow_source = _estimate_v2_dkg_escrow_wei(guardians)
        pre_min_wei, pre_max_wei, pre_escrow_source = _estimate_v2_pre_escrow_wei(guardians, threshold)
    except Exception as exc:
        return {"ok": False, "reason": f"Cost estimate unavailable: {exc}", "threshold": threshold}

    gas_price = _fixed_gas_price_wei()
    dkg_gas_rows = _dkg_gas_rows(count)
    pre_gas_rows = _pre_gas_rows(threshold)
    dkg_gas = sum(row["total_gas"] for row in dkg_gas_rows)
    pre_gas = sum(row["total_gas"] for row in pre_gas_rows)
    dkg_gas_wei = dkg_gas * gas_price
    pre_gas_wei = pre_gas * gas_price
    dkg_do_gas_wei = sum(row["total_gas"] for row in dkg_gas_rows if row["payer"] == "DO") * gas_price
    pre_requester_gas_wei = sum(row["total_gas"] for row in pre_gas_rows if row["payer"] == "Requester") * gas_price

    return {
        "ok": True,
        "threshold": threshold,
        "guardian_count": count,
        "gas_price_wei": gas_price,
        "dkg_escrow_wei": int(dkg_escrow_wei),
        "dkg_escrow_source": dkg_escrow_source,
        "pre_escrow_min_wei": int(pre_min_wei),
        "pre_escrow_max_wei": int(pre_max_wei),
        "pre_escrow_source": pre_escrow_source,
        "dkg_gas_rows": dkg_gas_rows,
        "pre_gas_rows": pre_gas_rows,
        "dkg_gas": dkg_gas,
        "pre_gas": pre_gas,
        "dkg_gas_wei": dkg_gas_wei,
        "pre_gas_wei": pre_gas_wei,
        "dkg_do_gas_wei": dkg_do_gas_wei,
        "pre_requester_gas_wei": pre_requester_gas_wei,
        "dkg_do_outlay_wei": int(dkg_escrow_wei) + dkg_do_gas_wei,
        "dkg_workflow_footprint_wei": int(dkg_escrow_wei) + dkg_gas_wei,
        "pre_requester_outlay_min_wei": int(pre_min_wei) + pre_requester_gas_wei,
        "pre_requester_outlay_max_wei": int(pre_max_wei) + pre_requester_gas_wei,
        "pre_workflow_footprint_min_wei": int(pre_min_wei) + pre_gas_wei,
        "pre_workflow_footprint_max_wei": int(pre_max_wei) + pre_gas_wei,
    }


def _log_staged_guardian_cost_estimate(estimate=None):
    estimate = estimate or _staged_guardian_cost_estimate()
    if not estimate.get("ok"):
        L.log(f"Guardian DKG/PRE ETH estimate unavailable: {estimate.get('reason', 'unknown reason')}")
        return

    L.log("=== Staged Guardian DKG/PRE ETH estimate ===")
    L.log(f"staged guardians: {len(S.staged_guardians)}")
    L.log(f"guardian threshold: {estimate['threshold']}")
    L.log(f"fixed gas price: {estimate['gas_price_wei']} wei")
    L.log(
        f"DKG escrow/reimbursement estimate: {_format_wei_as_eth(estimate['dkg_escrow_wei'])} "
        f"({estimate['dkg_escrow_source']})"
    )
    L.log(
        f"DKG tx gas estimate: {estimate['dkg_gas']:,} gas = "
        f"{_format_wei_as_eth(estimate['dkg_gas_wei'])}"
    )
    L.log(f"DKG estimated DO outlay (escrow + DO tx gas): {_format_wei_as_eth(estimate['dkg_do_outlay_wei'])}")
    L.log(
        f"DKG workflow footprint (escrow + all DO/G gas): "
        f"{_format_wei_as_eth(estimate['dkg_workflow_footprint_wei'])}"
    )
    for row in estimate["dkg_gas_rows"]:
        L.log(_format_gas_row(row, estimate["gas_price_wei"]))

    pre_min = estimate["pre_requester_outlay_min_wei"]
    pre_max = estimate["pre_requester_outlay_max_wei"]
    L.log(
        f"PRE escrow/reimbursement estimate: "
        f"{_format_wei_range(estimate['pre_escrow_min_wei'], estimate['pre_escrow_max_wei'])} "
        f"({estimate['pre_escrow_source']})"
    )
    L.log(
        f"PRE tx gas estimate: {estimate['pre_gas']:,} gas = "
        f"{_format_wei_as_eth(estimate['pre_gas_wei'])}"
    )
    L.log(f"PRE estimated requester outlay (escrow + requester tx gas): {_format_wei_range(pre_min, pre_max)}")
    L.log(
        f"PRE workflow footprint (escrow + all requester/G gas): "
        f"{_format_wei_range(estimate['pre_workflow_footprint_min_wei'], estimate['pre_workflow_footprint_max_wei'])}"
    )
    for row in estimate["pre_gas_rows"]:
        L.log(_format_gas_row(row, estimate["gas_price_wei"]))
    L.log("Gas estimates come from recent transaction_dashboard logs; escrow estimates come from RewardManager when available.")


def _staged_guardians_checksum():
    out = []
    seen = set()
    for addr in S.staged_guardians:
        try:
            checksum = C.w3.to_checksum_address(addr)
        except Exception:
            checksum = str(addr)
        key = checksum.lower()
        if key not in seen:
            out.append(checksum)
            seen.add(key)
    return out


def _policy_estimate_file_id():
    ctx = get_current_file_context(show_errors=False)
    if ctx:
        return ctx[0]
    return b"\x00" * 32


def _estimate_v2_dkg_escrow_wei(guardians):
    file_id = _policy_estimate_file_id()
    if C.reward_manager is not None:
        try:
            value = int(
                C.reward_manager.functions.estimateV2DkgEscrowForGuardians(
                    file_id,
                    guardians,
                ).call()
            )
            return value, "RewardManager.estimateV2DkgEscrowForGuardians"
        except Exception as exc:
            L.log(f"RewardManager DKG escrow estimate unavailable, using fallback: {exc}")

    rows, _dkg_su, _custody_su_per_day, _pre_su = N.summarize_selected_guardian_prices(guardians, 1)
    base_su = _reward_uint("v2DkgBaseSu", 100) + _reward_uint("dkgFinalizationSu", 0)
    rate = _su_to_wei_rate()
    fixed_gas_price = _reward_fixed_gas_price_wei()
    material_gas_wei = (
        _reward_uint("estimatedGasV2DkgMaterial", 520_000) +
        _reward_uint("overheadGasV2DkgMaterial", 260_000)
    ) * fixed_gas_price
    share_key_gas_wei = (
        _reward_uint("estimatedGasV2DkgShareKey", 190_000) +
        _reward_uint("overheadGasV2DkgShareKey", 70_000)
    ) * fixed_gas_price
    total_wei = base_su * rate
    for row in rows:
        total_wei += int(row["dkg_material_su"]) * rate + material_gas_wei
        total_wei += int(row["dkg_share_key_su"]) * rate + share_key_gas_wei
    return _with_reward_buffer(total_wei), "fallback reward formula with estimated Guardian gas reimbursement"


def _estimate_v2_pre_escrow_wei(guardians, threshold: int):
    file_id = _policy_estimate_file_id()
    if C.reward_manager is not None:
        try:
            min_estimate, max_estimate = C.reward_manager.functions.estimateV2PreEscrowForGuardians(
                file_id,
                0,
                guardians,
                int(threshold),
            ).call()
            return (
                int(min_estimate),
                int(max_estimate),
                "RewardManager.estimateV2PreEscrowForGuardians",
            )
        except Exception as exc:
            L.log(f"RewardManager PRE escrow estimate unavailable, using fallback: {exc}")

    rows, _dkg_su, _custody_su_per_day, _pre_min_su = N.summarize_selected_guardian_prices(guardians, threshold)
    base_su = _reward_uint("v2PreBaseSu", 50)
    rate = _su_to_wei_rate()
    fixed_gas_price = _reward_fixed_gas_price_wei()
    partial_gas_wei = (
        _reward_uint("estimatedGasV2PreBatchPartial", 1_250_000) +
        _reward_uint("overheadGasV2PreBatchPartial", 120_000)
    ) * fixed_gas_price
    pre_values = sorted(
        int(row["pre_batch_partial_su"]) * rate + partial_gas_wei
        for row in rows
    )
    pre_min_wei = sum(pre_values[:int(threshold)]) if threshold > 0 else 0
    pre_max_wei = sum(pre_values[-int(threshold):]) if threshold > 0 else 0
    return (
        _with_reward_buffer(base_su * rate + pre_min_wei),
        _with_reward_buffer(base_su * rate + pre_max_wei),
        "fallback reward formula with estimated Guardian gas reimbursement",
    )


def _reward_uint(name: str, fallback: int) -> int:
    if C.reward_manager is None:
        return int(fallback)
    try:
        return int(getattr(C.reward_manager.functions, name)().call())
    except Exception:
        return int(fallback)


def _su_to_wei_rate() -> int:
    if C.reward_manager is not None:
        try:
            return int(C.reward_manager.functions.suToWeiRate().call())
        except Exception:
            pass
    try:
        return int(getattr(C.config, "SU_TO_WEI_RATE", "1000000000000"))
    except Exception:
        return 1_000_000_000_000


def _reward_fixed_gas_price_wei() -> int:
    if C.reward_manager is not None:
        try:
            return int(C.reward_manager.functions.fixedGasPriceWei().call())
        except Exception:
            pass
    return _fixed_gas_price_wei()


def _with_reward_buffer(amount_wei: int) -> int:
    bps = _reward_uint("gasReimbursementBufferBps", 1000)
    return int(amount_wei) + (int(amount_wei) * int(bps)) // 10_000


def _fixed_gas_price_wei() -> int:
    try:
        return C.gas_price_wei()
    except Exception:
        return 1_000_000


def _dkg_gas_rows(guardian_count: int):
    n = int(guardian_count)
    return [
        _gas_row("DO", "data_owner", "AccessControlFT", "requestKeyGenForFile", 1, 195_240, "KeyGen request"),
        _gas_row("DO", "data_owner", "RewardManager", "depositPolicyEscrow", 1, 70_343, "DKG escrow deposit"),
        _gas_row("Guardian", "guardian", "ZkDkgDisputeManager", "publishAndAcknowledgeV2Material", n, 421_681, "DKG material publish"),
        _gas_row("Guardian", "guardian", "ZkDkgCoordinatorV2", "publishV2DealerCommitments", n, 264_897, "DKG commitments"),
        _gas_row("Guardian", "guardian", "ZkDkgCoordinatorV2", "publishV2EncryptedShare", n * n, 216_624, "DKG encrypted shares"),
        _gas_row("Guardian", "guardian", "ZkDkgCoordinatorV2", "publishV2SharePublicKey", n, 215_819, "DKG share public keys"),
        _gas_row("Guardian", "guardian", "RewardManager", "claimRewards", n, 30_217, "DKG reward withdrawals"),
        _gas_row("DO", "data_owner", "ZkDkgCoordinatorV2", "finalizeV2Dkg", 1, 425_909, "DKG finalization"),
        _gas_row("Guardian", "guardian", "GuardianShareProof", "registerAsGuardianForPolicy", n, 115_417, "DKG share custody registration"),
    ]


def _pre_gas_rows(threshold: int):
    t = int(threshold)
    return [
        _gas_row("Requester", "requester", "DataVault", "requestDataAccessForFileDataWithEscrow", 1, 476_250, "PRE access request + escrow"),
        _gas_row("Guardian", "guardian", "TElGv2", "submitV2BatchAccessPartial", t, 874_181, "PRE batch partial submissions"),
    ]


def _gas_row(payer: str, facility: str, contract_name: str, function_name: str, multiplier: int, fallback_gas: int, label: str):
    gas, total_gas, source, exact_sample = _transaction_gas_estimate(
        facility,
        contract_name,
        function_name,
        multiplier,
        fallback_gas,
    )
    return {
        "payer": payer,
        "label": label,
        "contract_name": contract_name,
        "function_name": function_name,
        "gas": int(gas),
        "multiplier": int(multiplier),
        "total_gas": int(total_gas),
        "source": source,
        "exact_sample": exact_sample,
    }


def _transaction_gas_estimate(facility: str, contract_name: str, function_name: str, multiplier: int, fallback_gas: int):
    values = _transaction_gas_values()
    key = (facility.lower(), contract_name.lower(), function_name.lower())
    multiplier = max(1, int(multiplier))
    samples = values.get(key) or []
    if samples:
        if len(samples) >= multiplier:
            recent = samples[-multiplier:]
            total_gas = sum(item["gas"] for item in recent)
            avg_gas = int(round(total_gas / multiplier))
            source = "latest transaction_dashboard log" if multiplier == 1 else f"latest {multiplier} transaction_dashboard logs"
            return avg_gas, total_gas, source, True

        latest_gas = int(samples[-1]["gas"])
        return latest_gas, latest_gas * multiplier, "latest transaction_dashboard log scaled", False

    fallback_gas = int(fallback_gas)
    return fallback_gas, fallback_gas * multiplier, "fallback baseline", False


def _transaction_gas_values():
    global _TX_GAS_VALUES_CACHE
    if _TX_GAS_VALUES_CACHE is not None:
        return _TX_GAS_VALUES_CACHE

    grouped = {}
    row_order = 0
    for path in _transaction_log_paths():
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    row_order += 1
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    gas = _int_or_zero(row.get("gas_used"))
                    if gas <= 0 or not row.get("transaction_hash"):
                        continue
                    status = str(row.get("status", "")).lower()
                    if status not in {"1", "success"}:
                        continue
                    key = (
                        str(row.get("facility", "")).lower(),
                        str(row.get("contract_name", "")).lower(),
                        str(row.get("function_name", "")).lower(),
                    )
                    grouped.setdefault(key, []).append({
                        "timestamp": str(row.get("timestamp", "")),
                        "order": row_order,
                        "gas": gas,
                    })
        except Exception:
            continue

    for values in grouped.values():
        values.sort(key=lambda item: (item["timestamp"], item["order"]))

    _TX_GAS_VALUES_CACHE = grouped
    return _TX_GAS_VALUES_CACHE


def _transaction_log_paths():
    roots = [
        Path(C.ROOT_DIR) / "reports" / "transaction_logs",
    ]
    try:
        roots.append(Path(str(getattr(C.config, "TRANSACTION_LOG_PATH", ""))).expanduser().parent)
    except Exception:
        pass

    paths = []
    seen = set()
    for root in roots:
        try:
            candidates = root.glob("*transactions.jsonl") if root.is_dir() else []
            for path in candidates:
                resolved = path.resolve()
                if resolved not in seen:
                    paths.append(resolved)
                    seen.add(resolved)
        except Exception:
            continue
    return paths


def _int_or_zero(value) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _format_gas_row(row, gas_price_wei: int) -> str:
    total_wei = int(row["total_gas"]) * int(gas_price_wei)
    if row.get("exact_sample") and int(row["multiplier"]) > 1:
        avg_gas = int(row["total_gas"]) / int(row["multiplier"])
        return (
            f"  gas {row['payer']} {row['label']}: "
            f"{row['total_gas']:,} gas over {row['multiplier']} recent tx "
            f"(avg {_format_gas_average(avg_gas)}/tx; {_format_wei_as_eth(total_wei)}, {row['source']})"
        )
    return (
        f"  gas {row['payer']} {row['label']}: "
        f"{row['gas']:,} x {row['multiplier']} = {row['total_gas']:,} gas "
        f"({_format_wei_as_eth(total_wei)}, {row['source']})"
    )


def _format_gas_average(value: float) -> str:
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,.1f}"


def _format_wei_range(min_wei: int, max_wei: int) -> str:
    if int(min_wei) == int(max_wei):
        return _format_wei_as_eth(min_wei)
    return f"{_format_wei_as_eth(min_wei)} - {_format_wei_as_eth(max_wei)}"


def _format_wei_as_eth(wei_value: int) -> str:
    wei = int(wei_value or 0)
    if wei == 0:
        return "0 ETH"
    sign = "-" if wei < 0 else ""
    wei = abs(wei)
    whole = wei // 10**18
    frac = str(wei % 10**18).rjust(18, "0").rstrip("0")
    if not frac:
        return f"{sign}{whole} ETH"
    return f"{sign}{whole}.{frac[:9]} ETH"


def clear_staged_guardians():
    S.staged_guardians = []
    _clear_guardian_table_selection()
    _update_staged_g_status()
    L.log("Cleared staged Guardians.")
    return True


def _clear_guardian_table_selection():
    """Drop the highlight in the Guardians table as well as the staged list.

    Clearing the list while the rows stay highlighted reads as "nothing
    happened", because the highlight is the only thing most of the tab shows.
    """
    widget = S.guardians_listbox
    if widget is None:
        return
    try:
        if hasattr(widget, "selection_remove"):
            widget.selection_remove(*widget.selection())
        else:
            widget.selection_clear(0, "end")
    except Exception:
        pass


def _add_selected_guardians_to_policy_legacy():
    """Kept for reference — original on-chain add logic now only used by update path."""
    policy = get_policy_for_current_file()
    if not policy:
        return False

    selected = N.get_selected_guardians()
    if not selected:
        L.show_error("Guardian error", "Select guardian(s) from the list first.")
        return False

    if not policy["exists"]:
        return create_or_update_file_policy()

    new_guardians = N.normalize_guardian_list(policy["guardians"] + selected)
    threshold = get_threshold_for_guardian_count(len(new_guardians), policy["threshold"])

    if threshold <= 0:
        L.show_error("Guardian error", "Invalid guardian threshold.")
        return False

    if not _validate_supported_zkdkg_threshold(threshold, len(new_guardians)):
        return False

    if not _validate_supported_zkdkg_guardian_count(len(new_guardians), source="updated policy Guardian list"):
        return False

    try:
        L.log("=== Add selected guardian(s) ===")
        L.log(f"policyId: {policy['file_id_hex']}")
        L.log(f"new guardians count: {len(new_guardians)}")
        L.log(f"guardian threshold: {threshold}")

        fn = C.acl.functions.updateFilePolicy(policy["file_id"], new_guardians, threshold, 0)
        CH.send_signed_tx(fn, C.DO_ACCOUNT, "Guardian list updated")
        show_current_file_policy()
        return True

    except Exception as e:
        L.show_error("Guardian add error", str(e))
        L.log(f"Guardian add error: {e}")
        return False


def remove_selected_guardians_from_policy():
    policy = get_policy_for_current_file()

    if not policy or not policy["exists"]:
        selected = N.get_selected_guardians()
        if not selected:
            L.show_error("Guardian error", "Select guardian(s) to remove from the staged list.")
            return False
        selected_set = {g.lower() for g in selected}
        S.staged_guardians = [g for g in S.staged_guardians if g.lower() not in selected_set]
        _update_staged_g_status()
        L.log(f"Removed from staged list. Staged guardians: {len(S.staged_guardians)}")
        return True

    selected = N.get_selected_guardians()
    if not selected:
        L.show_error("Guardian error", "Select guardian(s) to revoke from the list first.")
        return False

    selected_set = {g.lower() for g in selected}
    new_guardians = [g for g in policy["guardians"] if g.lower() not in selected_set]

    threshold = get_threshold_for_guardian_count(len(new_guardians), policy["threshold"])

    if threshold <= 0:
        L.show_error("Guardian error", "Invalid guardian threshold after guardian removal.")
        return False

    if not _validate_supported_zkdkg_threshold(threshold, len(new_guardians)):
        return False

    if not _validate_supported_zkdkg_guardian_count(len(new_guardians), allow_zero=True, source="updated policy Guardian list"):
        return False

    if threshold > len(new_guardians):
        L.log(
            f"[WARN] Remaining guardians={len(new_guardians)} is less than "
            f"threshold={threshold}. Policy will be under-threshold."
        )
        L.show_warning(
            "Under-threshold policy",
            f"Remaining Guardians: {len(new_guardians)}\n"
            f"Threshold: {threshold}\n\n"
            "This policy will be saved, but DKG/TElG cannot run until enough Guardians are added again."
        )

    try:
        L.log("=== Revoke selected guardian(s) ===")
        L.log(f"policyId: {policy['file_id_hex']}")
        L.log(f"remaining guardians: {len(new_guardians)}")
        L.log(f"guardian threshold: {threshold}")

        fn = C.acl.functions.updateFilePolicy(policy["file_id"], new_guardians, threshold, 0)
        CH.send_signed_tx(fn, C.DO_ACCOUNT, "Guardian(s) revoked from file policy")
        show_current_file_policy()
        return True

    except Exception as e:
        L.show_error("Guardian revoke error", str(e))
        L.log(f"Guardian revoke error: {e}")
        return False


def set_current_file_policy_active(active: bool):
    policy = get_policy_for_current_file()
    if not policy:
        return False

    if not policy["exists"]:
        L.show_error("Policy error", "No policy exists for this file.")
        return False

    try:
        action = "activated" if active else "deactivated"
        L.log(f"=== Policy {action} ===")
        L.log(f"policyId: {policy['file_id_hex']}")

        fn = C.acl.functions.setFilePolicyActive(policy["file_id"], active)
        CH.send_signed_tx(fn, C.DO_ACCOUNT, f"File policy {action}")
        show_current_file_policy()
        return True

    except Exception as e:
        L.show_error("Policy status error", str(e))
        L.log(f"Policy status error: {e}")
        return False


def activate_current_file_policy():
    return set_current_file_policy_active(True)


def deactivate_current_file_policy():
    return set_current_file_policy_active(False)


def toggle_current_file_policy_active():
    """Turn this policy on if it is off, and off if it is on.

    A policy is one or the other, so one button says which it is now and what
    pressing it does. Two buttons side by side said neither.
    """
    policy = get_policy_for_current_file()
    if not policy:
        return False
    if not policy["exists"]:
        L.show_error("Policy error", "No policy exists for this file.")
        return False
    result = set_current_file_policy_active(not bool(policy.get("active")))
    refresh_policy_active_button()
    return result


def refresh_policy_active_button() -> None:
    """Make the button show the state the chain is in, not the last guess.

    A policy that does not exist yet reads as inactive, which is what it is:
    pressing the button then creates nothing, it only reports that there is no
    policy to switch on.
    """
    if S.policy_active_button is None:
        return
    active = False
    try:
        policy = get_policy_for_current_file(show_errors=False)
        if policy and policy.get("exists"):
            active = bool(policy.get("active"))
    except Exception:
        active = False
    _set_policy_active_button(active)


def add_requester_to_file():
    ctx = get_current_file_context()
    if not ctx:
        return False

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx
    req_addr = S.entry_req_address.get().strip() if S.entry_req_address is not None else default_requester_address()

    if not req_addr:
        L.show_error("Requester error", "Requester address is empty.")
        return False

    try:
        req_addr = C.w3.to_checksum_address(req_addr)

        L.log("=== Add requester to file ===")
        L.log(f"policyId: {file_id_hex}")
        L.log(f"REQ: {req_addr}")

        req_name = S.entry_req_name.get().strip() if S.entry_req_name is not None else ""
        already_assigned = bool(
            C.acl.functions.isRequesterForFile(file_id, req_addr).call()
        )
        if already_assigned:
            L.log("Requester is already assigned on-chain; reusing confirmed assignment.")
        else:
            fn = C.acl.functions.addRequesterToFile(file_id, req_addr)
            CH.send_signed_tx(fn, C.DO_ACCOUNT, "Requester added to file")
            if not C.acl.functions.isRequesterForFile(file_id, req_addr).call():
                raise RuntimeError(
                    "Requester transaction completed but the assignment is not "
                    "confirmed on-chain"
                )
        R._update_policy_requesters(policy_name, req_addr, add=True, name=req_name)
        save_latest_upload_settings(prefer_policy_requesters=True)
        S.root.after(0, N.load_policy_requesters_ui)
        S.root.after(0, load_policies_browser)
        return True

    except Exception as e:
        L.show_error("Requester error", str(e))
        L.log(f"Requester error: {e}")
        return False


def remove_requester_from_file():
    ctx = get_current_file_context()
    if not ctx:
        return False

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx

    # Collect addresses: selected rows in the list take priority; fall back to address field
    addresses = []
    if S.req_book_tree is not None:
        for iid in S.req_book_tree.selection():
            vals = S.req_book_tree.item(iid, "values")
            if vals and len(vals) > 1:
                addresses.append(vals[1])

    if not addresses:
        addr = S.entry_req_address.get().strip() if S.entry_req_address is not None else ""
        if addr:
            addresses.append(addr)

    if not addresses:
        L.show_error("Requester error", "No requester address specified.")
        return False

    try:
        L.log(f"=== Revoke {len(addresses)} requester(s) from policy ===")
        L.log(f"policyId: {file_id_hex}")
        for addr in addresses:
            addr = C.w3.to_checksum_address(addr)
            L.log(f"  revoking: {addr}")
            fn = C.acl.functions.removeRequesterFromFile(file_id, addr)
            CH.send_signed_tx(fn, C.DO_ACCOUNT, f"Revoked {addr[:10]}…")
            R._update_policy_requesters(policy_name, addr, add=False)

        save_latest_upload_settings(prefer_policy_requesters=True)
        S.root.after(0, N.load_policy_requesters_ui)
        S.root.after(0, load_policies_browser)
        return True

    except Exception as e:
        L.show_error("Requester error", str(e))
        L.log(f"Requester revoke error: {e}")
        return False


def extend_guardian_service():
    """Buy more days on the current policy's Guardian term.

    The term is lengthened in place rather than rewritten: the original start
    date stays, so the days already served keep counting, and the end date only
    moves once every Guardian on the policy has agreed. If one of them never
    answers, the parked money comes back and the original term runs on.
    """
    from . import do_guardian_renewal as GR

    policy = get_policy_for_current_file()
    if not policy:
        return
    if not policy["exists"]:
        L.show_error("Extend Service", "Create the policy first.")
        return
    if C.POLICY_DKG_MODE != "ZKDKG_V2":
        L.show_error("Extend Service", "Guardian service terms only exist in ZKDKG_V2 mode.")
        return

    try:
        period = GR.service_period(policy["file_id"])
    except Exception as exc:
        L.show_error("Extend Service", str(exc))
        return
    if not period["exists"]:
        L.show_error("Extend Service", "This policy has no Guardian service term yet.")
        return

    ends_at = datetime.datetime.fromtimestamp(period["serviceEnd"]).astimezone()
    extra_days = simpledialog.askinteger(
        "Extend Guardian Service",
        f"Current term ends {ends_at:%Y-%m-%d %H:%M}.\n\n"
        f"How many more days?\n\n"
        f"All {len(policy['guardians'])} Guardian(s) must agree before the term moves.",
        minvalue=1,
        maxvalue=3650,
        parent=S.root,
    )
    if not extra_days:
        return

    L.set_status("Extending Guardian service…", "running")
    threading.Thread(
        target=_bg_extend_guardian_service,
        args=(policy["file_id"], policy["file_id_hex"], int(extra_days)),
        daemon=True,
    ).start()


def _bg_extend_guardian_service(file_id, file_id_hex, extra_days):
    from . import do_guardian_renewal as GR

    try:
        L.log(f"─── Extending Guardian service for {file_id_hex[:14]}… by {extra_days} day(s)")
        ok, reason = GR.renew_policy(file_id, extra_days)
        if ok:
            period = GR.service_period(file_id)
            ends_at = datetime.datetime.fromtimestamp(period["serviceEnd"]).astimezone()
            L.set_status("Guardian service extended", "done")
            L.show_info(
                "Extend Service",
                f"All Guardians agreed.\n\nThe term now runs to {ends_at:%Y-%m-%d %H:%M}.",
            )
        else:
            L.log(f"[G-renewal] {reason}")
            L.set_status("Guardian service not extended", "error")
            L.show_error("Extend Service", reason)
    except Exception as exc:
        L.log(f"Guardian service extension error: {exc}")
        L.set_status("Guardian service extension error", "error")
        L.show_error("Extend Service", str(exc))


def sync_policy_requesters():
    """Refresh requester list: query chain events, verify on-chain, update local record."""
    ctx = get_current_file_context()
    if not ctx:
        L.show_error("Sync", "Select a policy first (Policy Name in Dashboard).")
        return
    file_id, file_id_hex, _, policy_name, _, _, _ = ctx
    L.set_status("Syncing requesters…", "running")
    threading.Thread(
        target=_bg_sync_requesters,
        args=(file_id, file_id_hex, policy_name),
        daemon=True,
    ).start()


def _collect_logs_windowed(event, argument_filters=None, window: int = 9_000):
    """Collect every matching log, in ranges the chain will actually serve.

    A single request covering all of history is refused outright by chains that
    cap log ranges -- Cosmos allows 10,000 blocks, which a one-second chain
    passes in about three hours -- so page through and join the results instead.
    """
    try:
        head = int(C.w3.eth.block_number)
    except Exception:
        head = 0

    out = []
    from_block = 0
    while from_block <= head:
        to_block = min(head, from_block + window - 1)
        out.extend(
            event.get_logs(
                from_block=from_block,
                to_block=to_block,
                argument_filters=argument_filters or {},
            )
        )
        from_block = to_block + 1
    return out


def _current_requesters_for_file(file_id, page_size: int = 200) -> set:
    """Who may read this file right now, read as current state.

    The contract keeps this as a list, so it is a couple of paged reads whose
    cost depends on how many readers the file has. It used to be reconstructed
    by replaying every add and every remove from the beginning of the chain,
    then re-checking each address found -- which a chain capping log ranges
    refuses, and which on a chain years old cannot finish at all.

    Falls back to the replay for a deployment predating the list.
    """
    if hasattr(C.acl.functions, "getFileRequesterPage"):
        current = set()
        offset = 0
        while True:
            page = C.acl.functions.getFileRequesterPage(file_id, offset, page_size).call()
            if not page:
                break
            current.update(page)
            offset += len(page)
            if len(page) < page_size:
                break
        return current

    L.log("[sync] registry predates the reader list; falling back to replaying events")
    added = _collect_logs_windowed(C.acl.events.RequesterAddedToFile, {"fileId": file_id})
    removed = _collect_logs_windowed(C.acl.events.RequesterRemovedFromFile, {"fileId": file_id})
    candidates = (
        {e["args"]["requester"] for e in added}
        | {e["args"]["requester"] for e in removed}
    )
    current = set()
    for addr in candidates:
        try:
            if C.acl.functions.isRequesterForFile(file_id, addr).call():
                current.add(addr)
        except Exception:
            pass
    return current


def _bg_sync_requesters(file_id, file_id_hex, policy_name):
    try:
        L.log(f"─── Syncing requesters for '{policy_name}' ({file_id_hex[:14]}…)")

        current = _current_requesters_for_file(file_id)

        # preserve locally-stored names
        name_map = {r["address"].lower(): r.get("name", "") for r in R.get_policy_requesters(policy_name)}

        new_reqs = {
            addr.lower(): {"address": addr, "name": name_map.get(addr.lower(), "")}
            for addr in current
        }

        # write back to local record
        import json as _j
        from pathlib import Path as _P
        recs = R.load_policies_record()
        key = policy_name.lower()
        if key in recs:
            recs[key]["requesters"] = new_reqs
            _P(R.policies_record_path()).write_text(_j.dumps(recs, indent=2), encoding="utf-8")

        L.log(f"✓ {len(new_reqs)} active requester(s) synced for policy '{policy_name}'")
        L.set_status("Requesters synced", "done")
        if S.root:
            S.root.after(0, N.load_policy_requesters_ui)

    except Exception as exc:
        L.log(f"✗ Requester sync error: {exc}")
        L.set_status("Sync error", "error")


def _zip_upload_source(source_path: Path) -> Path:
    zip_dir = Path(C.UPLOAD_ZIPS_DIR)
    zip_dir.mkdir(parents=True, exist_ok=True)

    safe_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in source_path.stem)
    if not safe_stem:
        safe_stem = "upload"
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = zip_dir / f"{safe_stem}_{stamp}.zip"
    zip_dir_resolved = zip_dir.resolve()
    zip_path_resolved = zip_path.resolve()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if source_path.is_dir():
            parent = source_path.parent
            wrote_any = False
            for root, dirs, files in os.walk(source_path):
                root_path = Path(root)
                kept_dirs = []
                for dirname in dirs:
                    child = root_path / dirname
                    try:
                        if zip_dir_resolved == child.resolve() or zip_dir_resolved.is_relative_to(child.resolve()):
                            continue
                    except OSError:
                        pass
                    kept_dirs.append(dirname)
                dirs[:] = kept_dirs

                rel_dir = root_path.relative_to(parent)
                zf.write(root_path, rel_dir.as_posix() + "/")
                for filename in files:
                    file_path = root_path / filename
                    try:
                        if file_path.resolve() == zip_path_resolved:
                            continue
                    except OSError:
                        pass
                    zf.write(file_path, file_path.relative_to(parent).as_posix())
                    wrote_any = True
            if not wrote_any:
                L.log(f"Selected directory has no files; created empty folder archive: {zip_path}")
        else:
            zf.write(source_path, source_path.name)

    return zip_path


def set_selected_file(path_value: str) -> bool:
    raw_path = str(path_value or "").strip()
    if not raw_path:
        return False

    source_path = Path(raw_path).expanduser()
    if not source_path.exists():
        L.show_error("File error", "Please select a valid file or directory.")
        L.set_status("Select a valid file or directory", "error")
        return False

    try:
        if source_path.is_file() and source_path.suffix.lower() == ".zip":
            upload_path = source_path
            L.log(f"Selected ZIP is ready for upload: {upload_path}")
        else:
            L.set_status("Preparing ZIP for upload...", "running")
            upload_path = _zip_upload_source(source_path)
            kind = "directory" if source_path.is_dir() else "file"
            L.log(f"Selected {kind} zipped for upload:")
            L.log(f"  Source: {source_path}")
            L.log(f"  ZIP:    {upload_path}")

        S.selected_file_var.set(str(upload_path))
        L.set_status("ZIP ready for upload", "done")
        return True
    except Exception as exc:
        L.show_error("ZIP error", f"Could not prepare upload ZIP:\n{exc}")
        L.log(f"ZIP preparation error: {exc}")
        L.set_status("ZIP preparation failed", "error")
        return False


def select_file():
    filename = filedialog.askopenfilename(
        title="Select a file",
        filetypes=(("All files", "*.*"),),
    )

    if filename:
        set_selected_file(filename)


def select_directory():
    dirname = filedialog.askdirectory(title="Select a directory to ZIP and upload")

    if dirname:
        set_selected_file(dirname)


def _drop_folder_path() -> Path:
    raw = ""
    try:
        if S.drop_folder_var is not None:
            raw = S.drop_folder_var.get().strip()
    except Exception:
        raw = ""
    if not raw:
        raw = str(getattr(C.config, "DROP_FOLDER", Path(C.BASE_DIR) / "drop"))
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path(C.BASE_DIR) / path
    return path.resolve()


def _drop_folder_enabled() -> bool:
    try:
        return bool(S.drop_folder_enabled_var is None or S.drop_folder_enabled_var.get())
    except Exception:
        return bool(getattr(C.config, "DROP_FOLDER_ENABLED", True))


def _drop_folder_delete_from_vk_enabled() -> bool:
    try:
        return bool(S.drop_folder_delete_from_vk_var is not None and S.drop_folder_delete_from_vk_var.get())
    except Exception:
        return bool(getattr(C.config, "DROP_FOLDER_DELETE_FROM_VK", False))


def save_drop_folder_config() -> None:
    try:
        path = _drop_folder_path()
        enabled = _drop_folder_enabled()
        delete_from_vk = _drop_folder_delete_from_vk_enabled()
        C.save_runtime_config_updates({
            "drop_folder": str(path),
            "drop_folder_enabled": enabled,
            "drop_folder_delete_from_vk": delete_from_vk,
        })
        if S.drop_folder_status_var is not None:
            state = "watching" if enabled else "paused"
            S.drop_folder_status_var.set(f"Drop folder: {state}  {path}")
    except Exception as exc:
        L.log(f"Could not save drop folder config: {exc}")


def sync_folder_toggled() -> None:
    """Turn folder syncing on or off, and say plainly what that means.

    Deleting a file here deletes it from the keepers, which cannot be undone,
    so the switch explains itself at the moment it is used rather than relying
    on a label two words long.
    """
    # Deletion follows the folder: one switch, one promise -- the folder and
    # the network hold the same files.
    if S.drop_folder_delete_from_vk_var is not None:
        S.drop_folder_delete_from_vk_var.set(_drop_folder_enabled())
    save_drop_folder_config()

    folder = _drop_folder_path()
    if _drop_folder_enabled():
        L.show_info(
            "Sync folder is on",
            f"{folder}\n\n"
            "Copy a file into this folder and it is uploaded on its own.\n\n"
            "Delete a file from this folder and it is also deleted from the "
            "Vault Keepers holding it. That cannot be undone.",
        )
    else:
        L.show_info(
            "Sync folder is off",
            f"{folder}\n\n"
            "Nothing in this folder is uploaded or deleted any more. Files "
            "already on the network stay there.",
        )


def select_drop_folder():
    dirname = filedialog.askdirectory(title="Select FileTrust drop folder")
    if not dirname:
        return
    if S.drop_folder_var is not None:
        S.drop_folder_var.set(dirname)
    S.drop_folder_seen = {}
    S.drop_folder_inventory = {}
    S.drop_folder_pending = {}
    S.drop_folder_queue = []
    S.drop_folder_delete_queue = []
    save_drop_folder_config()
    _initialize_drop_folder_seen()


def open_drop_folder():
    import subprocess, sys
    path = _drop_folder_path()
    path.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", str(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        L.log(f"Could not open drop folder: {exc}")


def _path_upload_snapshot(path: Path):
    try:
        if path.is_file():
            st = path.stat()
            return int(st.st_size), int(st.st_mtime_ns), 1
        if path.is_dir():
            total_size = 0
            latest_mtime = int(path.stat().st_mtime_ns)
            file_count = 0
            for root, dirs, files in os.walk(path):
                root_path = Path(root)
                try:
                    latest_mtime = max(latest_mtime, int(root_path.stat().st_mtime_ns))
                except OSError:
                    pass
                for filename in files:
                    file_path = root_path / filename
                    try:
                        st = file_path.stat()
                    except OSError:
                        continue
                    total_size += int(st.st_size)
                    latest_mtime = max(latest_mtime, int(st.st_mtime_ns))
                    file_count += 1
            return total_size, latest_mtime, file_count
    except OSError:
        return None
    return None


def _path_file_inventory(path: Path) -> dict:
    inventory = {}
    try:
        if path.is_file():
            st = path.stat()
            return {"": {"size": int(st.st_size), "mtime_ns": int(st.st_mtime_ns)}}
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                root_path = Path(root)
                for filename in files:
                    if filename.startswith("."):
                        continue
                    file_path = root_path / filename
                    if _skip_drop_child(file_path):
                        continue
                    try:
                        st = file_path.stat()
                    except OSError:
                        continue
                    rel = file_path.relative_to(path).as_posix()
                    inventory[rel] = {"size": int(st.st_size), "mtime_ns": int(st.st_mtime_ns)}
    except OSError:
        return {}
    return inventory


def _snapshot_tuple(snapshot):
    if snapshot is None:
        return None
    try:
        if len(snapshot) < 3:
            return None
        return int(snapshot[0]), int(snapshot[1]), int(snapshot[2])
    except Exception:
        return None


def _snapshot_list(snapshot) -> list:
    snap = _snapshot_tuple(snapshot)
    return list(snap) if snap is not None else []


def _drop_folder_baseline_for(path: Path) -> dict:
    records = R.load_drop_folder_baselines()
    record = records.get(str(path.resolve()), {})
    return record if isinstance(record, dict) else {}


def _baseline_item_matches(item: dict, snapshot, inventory: dict) -> bool:
    if not isinstance(item, dict):
        return False
    if _snapshot_tuple(item.get("snapshot")) != _snapshot_tuple(snapshot):
        return False
    item_inventory = item.get("inventory", {})
    return isinstance(item_inventory, dict) and item_inventory == inventory


def _save_drop_folder_baseline_from_state() -> None:
    try:
        folder = _drop_folder_path().resolve()
        items = {}
        for key, snapshot in S.drop_folder_seen.items():
            items[str(key)] = {
                "snapshot": _snapshot_list(snapshot),
                "inventory": S.drop_folder_inventory.get(key, {}),
            }
        R.save_drop_folder_baseline(str(folder), {
            "folder": str(folder),
            "items": items,
            "updatedAt": datetime.datetime.now().astimezone().isoformat(),
        })
    except Exception as exc:
        L.log(f"[drop] could not save drop-folder baseline: {exc}")


def _drop_upload_record_is_reusable(record: dict) -> bool:
    if not isinstance(record, dict):
        return False
    if bool(record.get("vkDeleteOk")) and record.get("vkDeletedAt"):
        return False
    return bool(record.get("uploadedAt") or record.get("uploadSkipped") or record.get("pieces"))


def _drop_upload_record_matches_live_item(
    record: dict,
    path: Path,
    path_key: str,
    snapshot,
    inventory: dict,
) -> bool:
    if not _drop_upload_record_is_reusable(record):
        return False

    record_path = str(record.get("path") or "")
    if record_path and record_path != path_key:
        if str(record.get("name") or "") != path.name:
            return False
        if str(record.get("dataTag") or "") != _derive_data_tag_from_path(path):
            return False
        if str(record.get("date") or "") != _date_from_snapshot(snapshot):
            return False

    record_snapshot = _snapshot_tuple(record.get("snapshot"))
    current_snapshot = _snapshot_tuple(snapshot)
    if record_snapshot is not None and current_snapshot is not None and record_snapshot != current_snapshot:
        return False

    record_inventory = record.get("inventory")
    if isinstance(record_inventory, dict) and record_inventory and record_inventory != inventory:
        return False

    return True


def _find_matching_drop_upload_record_for_live_item(path: Path, snapshot=None, inventory: dict | None = None) -> dict | None:
    path_key = str(path.resolve())
    current_snapshot = snapshot if snapshot is not None else _path_upload_snapshot(path)
    current_inventory = inventory if inventory is not None else _path_file_inventory(path)
    records = R.load_drop_upload_records()

    record = records.get(path_key)
    if _drop_upload_record_matches_live_item(record, path, path_key, current_snapshot, current_inventory):
        return record

    data_tag = _derive_data_tag_from_path(path)
    date_str = _date_from_snapshot(current_snapshot)
    for rec in records.values():
        if not isinstance(rec, dict):
            continue
        if str(rec.get("dataTag") or "") != data_tag:
            continue
        if str(rec.get("date") or "") != date_str:
            continue
        if _drop_upload_record_matches_live_item(rec, path, path_key, current_snapshot, current_inventory):
            return rec
    return None


def _skip_drop_child(path: Path) -> bool:
    name = path.name
    if not name or name.startswith("."):
        return True
    lowered = name.lower()
    return lowered.endswith((".tmp", ".part", ".crdownload", ".download"))


def _handle_drop_folder_nested_delete(child: Path, removed_nested: list[str]) -> None:
    sample = ", ".join(removed_nested[:3])
    more = f" and {len(removed_nested) - 3} more" if len(removed_nested) > 3 else ""
    msg = (
        f"[drop] local-only nested deletion in folder '{child.name}': {sample}{more}. "
        "No VK deletion was requested because the folder was uploaded as one ZIP batch; "
        "individual nested files do not have separate VK piece records. "
        "Delete the top-level folder from the drop folder to delete the whole uploaded ZIP from VKs."
    )
    L.log(msg)
    L.show_warning(
        "Drop Folder Local Delete",
        "A file was deleted inside an uploaded folder.\n\n"
        "It was removed from your local system only. It cannot be deleted individually from VKs because "
        "the folder was uploaded as one ZIP batch. Delete the top-level folder to request deletion of "
        "the whole uploaded ZIP from VKs.",
    )
    if S.drop_folder_status_var is not None:
        S.drop_folder_status_var.set("Drop folder: nested delete is local-only")


def _initialize_drop_folder_seen() -> None:
    path = _drop_folder_path()
    path.mkdir(parents=True, exist_ok=True)
    seen = {}
    inventories = {}
    uploaded = 0
    baselined = 0
    unrecorded = 0
    records = R.load_drop_upload_records()
    baseline = _drop_folder_baseline_for(path)
    baseline_items = baseline.get("items", {}) if isinstance(baseline.get("items", {}), dict) else {}
    has_baseline = bool(baseline)
    live_paths = set()
    try:
        for child in path.iterdir():
            if _skip_drop_child(child):
                continue
            snap = _path_upload_snapshot(child)
            if snap is not None:
                key = str(child.resolve())
                live_paths.add(key)
                inventory = _path_file_inventory(child)
                if _find_matching_drop_upload_record_for_live_item(child, snap, inventory):
                    seen[key] = snap
                    inventories[key] = inventory
                    uploaded += 1
                    continue

                record = records.get(key)
                old_inventory = record.get("inventory", {}) if isinstance(record, dict) else {}
                if child.is_dir() and isinstance(old_inventory, dict) and old_inventory:
                    removed_nested = sorted(set(old_inventory) - set(inventory))
                    if removed_nested:
                        seen[key] = snap
                        inventories[key] = inventory
                        _handle_drop_folder_nested_delete(child, removed_nested)
                        continue

                if _baseline_item_matches(baseline_items.get(key, {}), snap, inventory):
                    seen[key] = snap
                    inventories[key] = inventory
                    baselined += 1
                    continue

                if not has_baseline:
                    seen[key] = snap
                    inventories[key] = inventory
                    baselined += 1
                    continue

                unrecorded += 1
    except OSError as exc:
        L.log(f"Drop folder scan error: {exc}")

    if has_baseline:
        folder_key = str(path.resolve())
        for key, record in records.items():
            if not isinstance(record, dict) or record.get("localDeletedAt"):
                continue
            record_path_text = str(record.get("path") or key)
            try:
                record_path = Path(record_path_text).resolve()
            except Exception:
                continue
            if str(record_path.parent) != folder_key:
                continue
            path_key = str(record_path)
            if path_key in live_paths or path_key not in baseline_items:
                continue
            _handle_drop_folder_top_level_removed(path_key, record.get("snapshot"))

    S.drop_folder_seen = seen
    S.drop_folder_inventory = inventories
    _save_drop_folder_baseline_from_state()
    if uploaded:
        L.log(f"[drop] startup skipped {uploaded} already-uploaded item(s) from drop_uploads.json.")
    if baselined:
        L.log(f"[drop] startup ignored {baselined} pre-existing item(s) already in the drop-folder baseline.")
    if unrecorded:
        L.log(f"[drop] startup found {unrecorded} unrecorded/new item(s); they will upload after the stable-file delay.")


def start_drop_folder_watcher() -> None:
    if S.drop_folder_watcher_started:
        return
    S.drop_folder_watcher_started = True
    _initialize_drop_folder_seen()
    path = _drop_folder_path()
    L.log(f"Drop folder watcher ready: {path}")
    if S.drop_folder_status_var is not None:
        state = "watching" if _drop_folder_enabled() else "paused"
        S.drop_folder_status_var.set(f"Drop folder: {state}  {path}")
    _poll_drop_folder()


def _poll_drop_folder() -> None:
    try:
        if _drop_folder_enabled():
            _scan_drop_folder_once()
            _start_next_drop_folder_upload()
    finally:
        if S.root is not None:
            poll_ms = max(1, int(getattr(C.config, "DROP_FOLDER_POLL_SECONDS", 3))) * 1000
            S.root.after(poll_ms, _poll_drop_folder)


def _scan_drop_folder_once() -> None:
    folder = _drop_folder_path()
    folder.mkdir(parents=True, exist_ok=True)
    now = time.monotonic()
    stable_seconds = max(1, int(getattr(C.config, "DROP_FOLDER_STABLE_SECONDS", 5)))
    live_paths = set()
    baseline_changed = False

    try:
        children = list(folder.iterdir())
    except OSError as exc:
        L.log(f"Drop folder scan error: {exc}")
        return

    queued = {str(Path(p).resolve()) for p in S.drop_folder_queue}
    current = str(Path(S.drop_folder_current_item).resolve()) if S.drop_folder_current_item else ""

    for child in children:
        if _skip_drop_child(child):
            continue
        child_key = str(child.resolve())
        live_paths.add(child_key)
        if child_key == current or child_key in queued:
            continue

        snapshot = _path_upload_snapshot(child)
        if snapshot is None:
            continue
        if S.drop_folder_seen.get(child_key) == snapshot:
            continue

        old_inventory = S.drop_folder_inventory.get(child_key, {})
        new_inventory = _path_file_inventory(child)
        if _find_matching_drop_upload_record_for_live_item(child, snapshot, new_inventory):
            S.drop_folder_seen[child_key] = snapshot
            S.drop_folder_inventory[child_key] = new_inventory
            S.drop_folder_pending.pop(child_key, None)
            L.log(f"[drop] skipped already-uploaded item: {child}")
            continue

        removed_nested = []
        if child.is_dir() and old_inventory:
            old_files = set(old_inventory)
            new_files = set(new_inventory)
            removed_nested = sorted(old_files - new_files)
        if removed_nested:
            S.drop_folder_seen[child_key] = snapshot
            S.drop_folder_inventory[child_key] = new_inventory
            S.drop_folder_pending.pop(child_key, None)
            _handle_drop_folder_nested_delete(child, removed_nested)
            baseline_changed = True
            continue

        pending = S.drop_folder_pending.get(child_key)
        if pending is None or pending.get("snapshot") != snapshot:
            S.drop_folder_pending[child_key] = {"snapshot": snapshot, "stable_since": now}
            continue

        if now - float(pending.get("stable_since", now)) < stable_seconds:
            continue

        S.drop_folder_queue.append(child_key)
        S.drop_folder_seen[child_key] = snapshot
        S.drop_folder_inventory[child_key] = new_inventory
        S.drop_folder_pending.pop(child_key, None)
        L.log(f"[drop] queued for upload: {child}")
        if S.drop_folder_status_var is not None:
            S.drop_folder_status_var.set(f"Drop folder: queued {len(S.drop_folder_queue)} item(s)")

    for key in list(S.drop_folder_pending):
        if key not in live_paths:
            S.drop_folder_pending.pop(key, None)

    for key in list(S.drop_folder_seen):
        if key in live_paths or key == current or key in queued:
            continue
        snapshot = S.drop_folder_seen.pop(key, None)
        S.drop_folder_inventory.pop(key, None)
        S.drop_folder_pending.pop(key, None)
        _handle_drop_folder_top_level_removed(key, snapshot)
        baseline_changed = True

    if baseline_changed:
        _save_drop_folder_baseline_from_state()


def _date_from_snapshot(snapshot) -> str:
    try:
        mtime_seconds = int(snapshot[1]) / 1_000_000_000
        return datetime.datetime.fromtimestamp(mtime_seconds).date().strftime("%Y-%m-%d")
    except Exception:
        return datetime.date.today().strftime("%Y-%m-%d")


def _find_drop_upload_record(path_key: str, snapshot=None) -> dict | None:
    records = R.load_drop_upload_records()
    record = records.get(str(path_key))
    if isinstance(record, dict):
        return record

    data_tag = _derive_data_tag_from_path(Path(path_key))
    date_str = _date_from_snapshot(snapshot)
    for rec in records.values():
        if not isinstance(rec, dict):
            continue
        if str(rec.get("dataTag", "")) == data_tag and str(rec.get("date", "")) == date_str:
            return rec
    return None


def _handle_drop_folder_top_level_removed(path_key: str, snapshot=None) -> None:
    label = Path(path_key).name
    if not _drop_folder_delete_from_vk_enabled():
        L.log(
            f"[drop] local item removed: {label}. VK deletion is disabled, so no VK pieces were deleted."
        )
        if str(path_key) in R.load_drop_upload_records():
            R.update_drop_upload_record(path_key, {
                "localDeletedAt": datetime.datetime.now().astimezone().isoformat(),
                "vkDeleteSkipped": True,
                "vkDeleteSkipReason": "drop_folder_delete_from_vk disabled",
            })
        if S.drop_folder_status_var is not None:
            S.drop_folder_status_var.set(f"Drop folder: local delete only  {label}")
        return

    record = _find_drop_upload_record(path_key, snapshot)
    if not record:
        msg = (
            f"[drop] local item removed: {label}. Could not request VK deletion because no drop-upload "
            "record was found for that path/date. Only uploads completed after this feature is enabled "
            "can be automatically deleted from VKs."
        )
        L.log(msg)
        L.show_warning(
            "Drop Folder Delete",
            "The item was deleted locally, but VK deletion could not be requested.\n\n"
            "Reason: no matching drop-upload record was found for this path/date.",
        )
        if S.drop_folder_status_var is not None:
            S.drop_folder_status_var.set(f"Drop folder: delete record missing  {label}")
        return

    S.drop_folder_delete_queue.append(record)
    L.log(f"[drop] queued VK deletion for removed item: {label}")
    if S.drop_folder_status_var is not None:
        S.drop_folder_status_var.set(f"Drop folder: queued VK delete  {label}")
    _start_next_drop_folder_delete()


def _start_next_drop_folder_delete() -> None:
    if S.drop_folder_deleting or not S.drop_folder_delete_queue:
        return
    record = S.drop_folder_delete_queue.pop(0)
    S.drop_folder_deleting = True
    threading.Thread(target=_run_drop_folder_delete, args=(record,), daemon=True).start()


def _run_drop_folder_delete(record: dict) -> None:
    label = str(record.get("name") or Path(str(record.get("path", ""))).name or record.get("dataTag") or "drop item")
    path_key = str(record.get("path") or "")
    pieces = record.get("pieces") or []
    ok_count = 0
    pending_count = 0
    failures = []

    L.log(f"[drop] deleting VK pieces for removed item '{label}' ({len(pieces)} piece(s))")
    L.set_status(f"Deleting VK pieces for {label}...", "running")

    if not pieces:
        failures.append("drop-upload record has no stored piece receipts")

    for piece in pieces:
        piece_root = str(piece.get("pieceRoot") or (piece.get("privateReceipt") or {}).get("pieceRoot") or "")
        commitment_hash = _piece_commitment_hash(piece)
        try:
            # Old drop-folder records predate the authoritative journal. Import
            # their complete receipt before persisting deletion intent; never
            # run the network-only helper and lose recovery state on a crash.
            if commitment_hash and PJ.get_by_commitment(C.BASE_DIR, commitment_hash) is None:
                PJ.record_registration(
                    C.BASE_DIR,
                    piece,
                    source="legacy-drop-upload-record",
                )
            if commitment_hash:
                ok, msg = delete_vk_piece(commitment_hash=commitment_hash)
            else:
                ok, msg = delete_vk_piece(piece_root=piece_root)
        except Exception as exc:
            ok, msg = False, f"could not persist drop-folder deletion safely: {exc}"
        if ok:
            ok_count += 1
            L.log(f"[drop] VK delete ok for {piece_root[:20]}... {msg}")
        elif str(msg).startswith("deletion pending:"):
            pending_count += 1
            L.log(f"[drop] VK delete accepted for {piece_root[:20]}... {msg}")
        else:
            failures.append(f"{piece_root[:20] or 'unknown'}... {msg}")
            L.log(f"[drop] VK delete failed for {piece_root[:20]}... {msg}")

    deleted_at = datetime.datetime.now().astimezone().isoformat()
    R.update_drop_upload_record(path_key, {
        "localDeletedAt": deleted_at,
        "vkDeletedAt": deleted_at if not failures and pending_count == 0 else "",
        "vkDeleteOk": not failures,
        "vkDeleteOkCount": ok_count,
        "vkDeletePendingCount": pending_count,
        "vkDeleteFailureCount": len(failures),
        "vkDeleteFailures": failures,
    })

    def finish() -> None:
        S.drop_folder_deleting = False
        if failures:
            L.set_status("Drop-folder VK delete incomplete", "error")
            L.show_warning(
                "Drop Folder VK Delete",
                f"Local item '{label}' was deleted, but {len(failures)} VK piece deletion(s) failed.\n\n"
                "Pending deletion monitoring remains active. A dispute is submitted only if "
                "the on-chain grace deadline expires. Open the log for details.",
            )
        elif pending_count:
            L.set_status("Drop-folder VK deletion accepted", "running")
            L.show_info(
                "Drop Folder VK Delete",
                f"'{label}' was deleted locally. {pending_count} VK deletion(s) were accepted "
                "and will be confirmed asynchronously from chain state.",
            )
        else:
            L.set_status("Drop-folder VK delete completed", "done")
            L.show_info(
                "Drop Folder VK Delete",
                f"'{label}' was deleted locally and all {ok_count} VK piece(s) were deleted and verified.",
            )
        if S.drop_folder_status_var is not None:
            S.drop_folder_status_var.set(f"Drop folder: watching  {_drop_folder_path()}")
        load_policies_browser()
        load_stored_pieces_list()
        _start_next_drop_folder_delete()

    if S.root is not None:
        S.root.after(0, finish)
    else:
        finish()


def _save_drop_upload_record(path_text: str, ctx, manifest: dict) -> None:
    if not path_text or not ctx or not isinstance(manifest, dict):
        return
    try:
        record = _drop_upload_record_base(path_text, ctx)
        if not record:
            return
        record["uploadedAt"] = datetime.datetime.now().astimezone().isoformat()
        # The deletion index needs only a blinded commitment and routing
        # identity. Deletion secrets and signed receipts stay in the protected
        # lifecycle journal.
        record["pieces"] = [
            {
                "fileId": item.get("fileId", ""),
                "uploadInstanceId": item.get("uploadInstanceId", ""),
                "pieceIndex": item.get("pieceIndex", 0),
                "pieceRoot": item.get("pieceRoot", ""),
                "commitmentHash": item.get("commitmentHash", ""),
            }
            for item in manifest.get("pieces", [])
            if isinstance(item, dict)
        ]
        path_key = str(Path(path_text).resolve())
        R.save_drop_upload_record(path_key, record)
        L.log(f"[drop] saved upload delete index for {record['name']} ({len(record['pieces'])} piece(s))")
    except Exception as exc:
        L.log(f"[drop] could not save upload delete index: {exc}")


def _drop_upload_record_base(path_text: str, ctx) -> dict:
    if not path_text or not ctx:
        return {}
    file_id, file_id_hex, _do_input, policy_name, data_tag, date_str, ts = ctx
    path = Path(path_text)
    return {
        "path": str(path.resolve()),
        "name": path.name,
        "policyName": policy_name,
        "policyId": file_id_hex,
        "dataTag": data_tag,
        "date": date_str,
        "timestamp": int(ts),
        "snapshot": list(_path_upload_snapshot(path) or []),
        "inventory": _path_file_inventory(path) if path.exists() else {},
    }


def _save_drop_existing_batch_record(path_text: str, ctx, reason: str) -> None:
    try:
        record = _drop_upload_record_base(path_text, ctx)
        if not record:
            return
        record.update({
            "uploadSkipped": True,
            "uploadSkipReason": reason,
            "recordedAt": datetime.datetime.now().astimezone().isoformat(),
            "pieces": [],
        })
        R.save_drop_upload_record(record["path"], record)
        L.log(f"[drop] saved existing-batch reference for {record['name']}: {reason}")
    except Exception as exc:
        L.log(f"[drop] could not save existing-batch reference: {exc}")


def _derive_data_tag_from_path(path: Path) -> str:
    raw = path.name if path.is_dir() else path.stem
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in raw).strip("._")
    return (safe or "upload")[:80]


def _modified_date_from_path(path: Path) -> str:
    snapshot = _path_upload_snapshot(path)
    if snapshot is None:
        return datetime.date.today().strftime("%Y-%m-%d")
    mtime_seconds = int(snapshot[1]) / 1_000_000_000
    return datetime.datetime.fromtimestamp(mtime_seconds).date().strftime("%Y-%m-%d")


def _apply_drop_item_context(path: Path) -> bool:
    restore_latest_upload_settings()
    if S.entry_device_id is not None:
        _set_entry_text(S.entry_device_id, _derive_data_tag_from_path(path))
    if S.selected_datetime_var is not None:
        S.selected_datetime_var.set(_modified_date_from_path(path))
    refresh_file_id_preview()
    return set_selected_file(str(path))


def _start_next_drop_folder_upload() -> None:
    if S.drop_folder_uploading or not S.drop_folder_queue:
        return
    next_item = S.drop_folder_queue.pop(0)
    S.drop_folder_uploading = True
    S.drop_folder_current_item = next_item
    if S.drop_folder_status_var is not None:
        S.drop_folder_status_var.set(f"Drop folder: uploading {Path(next_item).name}")
    threading.Thread(target=_run_drop_folder_upload, args=(next_item,), daemon=True).start()


def _run_drop_folder_upload(path_text: str) -> None:
    path = Path(path_text)
    L.log(f"[drop] preparing upload: {path}")
    if not path.exists():
        L.log(f"[drop] skipped missing item: {path}")
        _finish_drop_folder_upload(False)
        return
    if path.is_dir() and not _path_file_inventory(path):
        L.log(f"[drop] skipped empty directory: {path}")
        if str(path.resolve()) in S.drop_folder_seen:
            _save_drop_folder_baseline_from_state()
        _finish_drop_folder_upload(False)
        return
    if not _apply_drop_item_context(path):
        _finish_drop_folder_upload(False)
        return
    run_all()


def _finish_drop_folder_upload(success: bool) -> None:
    item = S.drop_folder_current_item
    if item:
        label = Path(item).name
        L.log(f"[drop] {'completed' if success else 'stopped'}: {label}")
    if success:
        _save_drop_folder_baseline_from_state()
    S.drop_folder_uploading = False
    S.drop_folder_current_item = ""
    if S.drop_folder_status_var is not None:
        if S.drop_folder_queue:
            S.drop_folder_status_var.set(f"Drop folder: queued {len(S.drop_folder_queue)} item(s)")
        else:
            S.drop_folder_status_var.set(f"Drop folder: watching  {_drop_folder_path()}")
    if S.root is not None:
        S.root.after(0, _start_next_drop_folder_upload)


def select_datetime():
    import calendar as _cal
    import customtkinter as ctk

    today = datetime.date.today()
    try:
        current = datetime.datetime.strptime(S.selected_datetime_var.get(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        current = today

    # ── palette (mirrors do_ui tokens) ────────────────────────────────────────
    _BG  = "#1F2641"; _SRF = "#2A3355"; _BASE = "#232840"
    _ACC = "#FFD700"; _ACH = "#e6c200"; _ACS  = "#2f3a5e"; _ACSH = "#374468"
    _T1  = "#FFFFFF"; _T2  = "#8899cc"; _MUT  = "#3E497A"; _MUTH = "#4a578e"
    _FNT = "Catamaran"

    popup = tk.Toplevel(S.root)
    popup.title("Select Date")
    popup.resizable(False, False)
    popup.configure(bg=_BG)
    popup.after(50, popup.grab_set)   # delay until window is actually viewable

    card = ctk.CTkFrame(popup, fg_color=_SRF, corner_radius=16)
    card.pack(padx=20, pady=20)

    state = {"year": current.year, "month": current.month, "sel": current, "btns": []}
    month_var = tk.StringVar()

    # ── nav header ─────────────────────────────────────────────────────────────
    hdr = ctk.CTkFrame(card, fg_color="transparent")
    hdr.grid(row=0, column=0, columnspan=7, sticky="ew", padx=12, pady=(14, 6))
    hdr.grid_columnconfigure(1, weight=1)

    ctk.CTkButton(hdr, text="‹", width=28, height=28,
        fg_color=_MUT, hover_color=_ACS, text_color=_T1,
        font=(_FNT, 14), corner_radius=6,
        command=lambda: (_step(-1), _render()),
    ).grid(row=0, column=0)
    ctk.CTkLabel(hdr, textvariable=month_var,
        font=(_FNT, 13), text_color=_T1,
    ).grid(row=0, column=1)
    ctk.CTkButton(hdr, text="›", width=28, height=28,
        fg_color=_MUT, hover_color=_ACS, text_color=_T1,
        font=(_FNT, 14), corner_radius=6,
        command=lambda: (_step(+1), _render()),
    ).grid(row=0, column=2)

    # ── weekday header ─────────────────────────────────────────────────────────
    for i, wd in enumerate(("Mo", "Tu", "We", "Th", "Fr", "Sa", "Su")):
        ctk.CTkLabel(card, text=wd, width=38,
            font=(_FNT, 9), text_color=_T2,
        ).grid(row=1, column=i, padx=2, pady=(0, 2))

    # ── confirm ────────────────────────────────────────────────────────────────
    def _confirm():
        S.selected_datetime_var.set(state["sel"].strftime("%Y-%m-%d"))
        refresh_file_id_preview()
        popup.destroy()

    ctk.CTkButton(card, text="Confirm", width=230, height=32,
        fg_color=_ACC, hover_color=_ACH, text_color="#1F2641",
        font=(_FNT, 11), corner_radius=8,
        command=_confirm,
    ).grid(row=9, column=0, columnspan=7, padx=12, pady=(6, 14))

    # ── helpers ────────────────────────────────────────────────────────────────
    def _step(delta):
        m = state["month"] + delta
        if m < 1:  state["month"] = 12; state["year"] -= 1
        elif m > 12: state["month"] = 1; state["year"] += 1
        else: state["month"] = m

    def _pick(day):
        state["sel"] = datetime.date(state["year"], state["month"], day)
        _render()

    def _render():
        for b in state["btns"]:
            b.destroy()
        state["btns"].clear()

        y, m = state["year"], state["month"]
        month_var.set(f"{_cal.month_name[m]}  {y}")
        first_wd, num_days = _cal.monthrange(y, m)

        row, col = 2, first_wd
        for day in range(1, num_days + 1):
            d = datetime.date(y, m, day)
            if d == state["sel"]:
                fg, fg_h, txt = _ACC, _ACH, "#1F2641"
            elif d == today:
                fg, fg_h, txt = _ACS, _ACSH, _ACC
            else:
                fg, fg_h, txt = _BASE, _MUT, _T1
            btn = ctk.CTkButton(card, text=str(day), width=38, height=30,
                fg_color=fg, hover_color=fg_h, text_color=txt,
                font=(_FNT, 10), corner_radius=6,
                command=lambda d=day: _pick(d),
            )
            btn.grid(row=row, column=col, padx=2, pady=2)
            state["btns"].append(btn)
            col += 1
            if col > 6:
                col = 0; row += 1

    _render()

    # centre over main window once fully rendered
    def _centre():
        popup.update_idletasks()
        px = S.root.winfo_rootx() + (S.root.winfo_width()  - popup.winfo_width())  // 2
        py = S.root.winfo_rooty() + (S.root.winfo_height() - popup.winfo_height()) // 2
        popup.wm_geometry(f"+{px}+{py}")

    popup.after(10, _centre)


def run_upload_vaultmesh_compat():
    return run_upload_vaultmesh()


def continue_unfinished_uploads() -> None:
    """Pick up where an interrupted upload stopped, on a worker thread.

    The keepers come from the job records, never from the window: each
    unfinished piece already has a keeper it negotiated with and paid, and
    after a restart nothing is selected in the Vault Keepers tab -- which is
    why resuming used to stop at "select at least one Vault Keeper".
    """
    from . import do_transfer_manager as transfer_manager
    transfer_manager.resume_uploads()

    try:
        jobs = transfer_manager.unfinished_upload_jobs(C.BASE_DIR)
    except Exception as exc:
        L.log(f"[transfer] could not read the unfinished uploads: {exc}")
        return
    if not jobs:
        return

    upload_ids = {
        str(j.get("uploadInstanceId", "") or "").strip().lower() for j in jobs
    }
    upload_ids.discard("")
    ctx = get_current_file_context(show_errors=False)
    current_id = ""
    if ctx:
        _fid, file_id_hex, _do_input, _pol, data_tag, _date, ts = ctx
        current_id = HX.derive_upload_instance_id(file_id_hex, data_tag, ts)

    # Resuming under a different Policy Name, Data Tag or Date would not
    # continue that upload -- it would start a second one beside it, paying
    # again for pieces already paid for. Stop instead, and say what to set.
    if not current_id or current_id not in upload_ids:
        L.show_error(
            "Continue upload",
            "The unfinished pieces belong to a different upload than the one "
            "set in the Dashboard.\n\nSet the same Policy Name, Data Tag and "
            "Date as the interrupted upload, then continue.",
        )
        L.log(
            "[transfer] not resuming: the dashboard describes upload "
            f"{current_id[:16] or 'nothing'}, the unfinished pieces belong to "
            f"{', '.join(sorted(i[:16] for i in upload_ids))}"
        )
        return

    peers = transfer_manager.resumable_upload_peers(C.BASE_DIR, current_id)
    if not peers:
        L.show_error(
            "Continue upload",
            "The unfinished pieces have no Vault Keeper recorded, so there is "
            "nothing to continue them on.",
        )
        return

    def _work() -> None:
        L.log(
            f"[transfer] continuing {len(jobs)} unfinished piece(s) on "
            f"{len(peers)} recorded keeper(s)"
        )
        # The same bar a fresh upload draws, minus the phases a resume has
        # already been through. The pieces that arrived before the
        # interruption are counted by the storing loop like any other, so the
        # bar opens where the upload stopped instead of at zero.
        PROG.start("Continuing upload", [
            ("pieces stored", 0.85),
            ("registered on chain", 0.15),
        ])
        done = False
        try:
            if run_upload_vaultmesh(peers=peers, resuming=len(jobs)):
                run_upload_cids()
                done = True
        except Exception as exc:
            L.log(f"[transfer] could not continue: {exc}")
        finally:
            if PROG.is_running():
                if done:
                    PROG.step("registered on chain", 1, 1)
                    PROG.finish("Upload complete")
                else:
                    PROG.finish("Upload did not finish", ok=False)

    threading.Thread(target=_work, daemon=True, name="resume-uploads").start()


def offer_unfinished_upload_resume() -> None:
    """On start-up, say what was left unfinished and ask once whether to go on.

    Asked rather than done, because continuing costs gas and the user may have
    stopped on purpose. Asked ONCE -- a dialog that returns every thirty seconds
    teaches people to dismiss it without reading.

    Nothing is re-sent that already arrived: the keeper keeps the partial piece
    and reports how many bytes it holds, and the uploader seeks to that offset.
    A gigabyte cut at 500 MB continues at 500 MB.
    """
    from . import do_transfer_manager as transfer_manager
    try:
        jobs = transfer_manager.unfinished_upload_jobs(C.BASE_DIR)
    except Exception as exc:
        L.log(f"[transfer] could not read the unfinished uploads: {exc}")
        return
    if not jobs:
        return

    files = {str(j.get("fileName") or Path(str(j.get("filePath", ""))).name or "?")
             for j in jobs}
    files.discard("")
    named = ", ".join(sorted(files)[:3]) + (" …" if len(files) > 3 else "")
    piece_word = "piece" if len(jobs) == 1 else "pieces"
    L.log(
        f"[transfer] {len(jobs)} unfinished {piece_word} found from a previous "
        f"run: {named or 'unknown file'}"
    )

    if not messagebox.askyesno(
        "Continue the unfinished upload?",
        f"{len(jobs)} {piece_word} from an earlier run did not finish:\n"
        f"    {named or 'unknown file'}\n\n"
        "Continuing picks up each piece where it stopped -- what already "
        "reached a keeper is not sent again.\n\n"
        "Continue now?",
    ):
        # The offer returns the next time the window opens, which is the only
        # honest thing to promise now that there is no play button.
        L.log("[transfer] left unfinished; this will be offered again next time "
              "the app starts")
        L.set_status(f"{len(jobs)} unfinished {piece_word} waiting", "waiting")
        return

    continue_unfinished_uploads()


def pause_vaultmesh_uploads():
    from . import do_transfer_manager as transfer_manager
    count = transfer_manager.pause_uploads()
    L.log(f"[transfer] upload pause requested; active transfers={count}")
    L.set_status("VaultMesh uploads paused", "waiting")


def resume_vaultmesh_uploads():
    """Lift the pause flag. Kept because the transfer manager still has one.

    No button reaches this now: continuing an interrupted upload is offered on
    start-up instead, and it resumes from the exact byte.
    """
    from . import do_transfer_manager as transfer_manager
    transfer_manager.resume_uploads()
    L.log("[transfer] uploads un-paused")
    L.set_status("Uploads un-paused", "ready")


# ── automatic retry of pending transfers ───────────────────────────────────────
#
# A TransferPending is a condition that clears on its own: the piece is stored
# and registered, only its on-chain proof has not been confirmed yet. Until now
# the upload stopped there and waited for a human to press Resume, so an
# unattended run — a load test, a machine nobody is watching — left the upload
# unfinished forever with every piece already paid for.
#
# TransferPaused is deliberately NOT retried. That one means the operator chose
# to stop, and a background thread must not undo an explicit decision.
_AUTO_RETRY_DELAYS = (20, 40, 80, 160, 320)
_auto_retry_lock = threading.Lock()
_auto_retry_active = False


def _schedule_pending_upload_retry():
    """Retry a self-clearing pending transfer on a bounded backoff."""
    global _auto_retry_active
    with _auto_retry_lock:
        if _auto_retry_active:
            return          # one retry chain at a time; a second adds no information
        _auto_retry_active = True

    def _retry():
        global _auto_retry_active
        from . import do_transfer_manager as transfer_manager
        try:
            for attempt, delay in enumerate(_AUTO_RETRY_DELAYS, start=1):
                time.sleep(delay)
                if transfer_manager.uploads_paused():
                    L.log("[transfer] auto-retry stopped: uploads are paused")
                    return
                L.log(
                    f"[transfer] auto-retry {attempt}/{len(_AUTO_RETRY_DELAYS)} "
                    f"for pending VaultMesh transfer"
                )
                try:
                    finished = run_upload_vaultmesh(raise_on_pending=True)
                except VM.XFER.TransferPending as exc:
                    L.log(f"[transfer] still pending after auto-retry {attempt}: {exc}")
                    continue
                except VM.XFER.TransferPaused:
                    L.log("[transfer] auto-retry stopped: uploads are paused")
                    return
                except Exception as exc:                 # a retry must never kill the app
                    L.log(f"[transfer] auto-retry {attempt} failed: {exc}")
                    continue
                if finished:
                    L.log("[transfer] auto-retry completed the pending transfer")
                    run_upload_cids()
                    return
            L.log(
                "[transfer] auto-retry gave up after "
                f"{len(_AUTO_RETRY_DELAYS)} attempts; press Resume to keep trying"
            )
            L.set_status("VaultMesh transfer still pending; resume required", "waiting")
        finally:
            with _auto_retry_lock:
                _auto_retry_active = False

    threading.Thread(target=_retry, daemon=True).start()


def _stable_file_sha256(path: str | os.PathLike) -> tuple[str, int]:
    """Hash a local recovery input and reject concurrent replacement."""
    resolved = Path(path).resolve()
    before = resolved.stat()
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    after = resolved.stat()
    identity_before = (
        int(before.st_size), int(before.st_mtime_ns), int(before.st_ctime_ns),
        int(getattr(before, "st_ino", 0)),
    )
    identity_after = (
        int(after.st_size), int(after.st_mtime_ns), int(after.st_ctime_ns),
        int(getattr(after, "st_ino", 0)),
    )
    if identity_before != identity_after:
        raise RuntimeError(f"recovery source changed while it was read: {resolved}")
    return digest.hexdigest(), int(after.st_size)


def _validated_rida_piece_set(
    pieces_dir: str | os.PathLike,
    *,
    expected_n: int,
    expected_m: int,
) -> dict[int, Path]:
    """Return an exact, coherent RIDA generation keyed by one-based index."""
    root = Path(pieces_dir).resolve()
    if not root.is_dir():
        raise RuntimeError("the durable pieces directory is missing")
    entries = list(root.iterdir())
    if len(entries) != int(expected_n):
        raise RuntimeError(
            "the durable RIDA generation is incomplete or contains extra files "
            f"(expected {expected_n}, found {len(entries)})"
        )

    by_index: dict[int, Path] = {}
    original_size: int | None = None
    payload_size: int | None = None
    pattern = re.compile(r"_p(\d+)_of_(\d+)$")
    for entry in entries:
        try:
            entry.resolve().relative_to(root)
        except ValueError as exc:
            raise RuntimeError(
                f"RIDA piece escapes the protected directory: {entry.name}"
            ) from exc
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError(
                f"unexpected non-regular file in the RIDA directory: {entry.name}"
            )
        match = pattern.search(entry.name)
        if not match:
            raise RuntimeError(f"invalid RIDA piece filename: {entry.name}")
        filename_index = int(match.group(1))
        filename_n = int(match.group(2))
        if filename_n != int(expected_n):
            raise RuntimeError(f"RIDA piece count changed: {entry.name}")
        with entry.open("rb") as handle:
            header = handle.read(16)
        if len(header) != 16 or header[:4] != b"RIDA":
            raise RuntimeError(f"invalid RIDA header: {entry.name}")
        version, header_n, header_m, zero_index = header[4:8]
        (header_size,) = struct.unpack(">Q", header[8:16])
        if version != 1 or header_n != expected_n or header_m != expected_m:
            raise RuntimeError(f"RIDA profile changed: {entry.name}")
        if filename_index != int(zero_index) + 1:
            raise RuntimeError(f"RIDA piece index mismatch: {entry.name}")
        if filename_index in by_index:
            raise RuntimeError(f"duplicate RIDA piece index {filename_index}")
        current_payload_size = int(entry.stat().st_size) - 16
        if current_payload_size < 0:
            raise RuntimeError(f"truncated RIDA piece: {entry.name}")
        if original_size is None:
            original_size = int(header_size)
            payload_size = current_payload_size
        elif original_size != int(header_size) or payload_size != current_payload_size:
            raise RuntimeError("RIDA pieces do not belong to one coherent generation")
        by_index[filename_index] = entry

    expected_indices = set(range(1, int(expected_n) + 1))
    if set(by_index) != expected_indices:
        raise RuntimeError("the durable RIDA generation has missing piece indices")
    return by_index


def _reuse_current_dispersal_if_safe(
    file_path: str,
    *,
    n: int,
    m: int,
    use_aes: bool,
) -> bool:
    """Reuse an interrupted upload's exact pieces, or fail closed.

    False means no durable generation exists and a new dispersal is permitted.
    True means the existing generation was fully authenticated and must be
    reused. Any durable conflict raises before a file can be deleted.
    """
    from . import do_transfer_manager as transfer_manager

    ctx = get_current_file_context(show_errors=False)
    if not ctx:
        raise RuntimeError(
            "cannot identify the current upload while durable pieces exist"
        )
    _file_id, file_id_hex, _do_input, _policy, data_tag, _date, ts = ctx
    upload_instance_id = HX.derive_upload_instance_id(file_id_hex, data_tag, ts)
    if C.file_registration_sc is None:
        raise RuntimeError(
            "FileRegistrationSC is unavailable; durable pieces cannot be "
            "matched to the current chain"
        )
    chain_namespace = {
        "chainId": int(C.w3.eth.chain_id),
        "fileRegistrationContract": str(C.file_registration_sc.address).lower(),
    }
    snapshot = transfer_manager.storage_piece_recovery_snapshot(
        C.BASE_DIR,
        C.PIECES_DIR,
        file_id=file_id_hex,
        upload_instance_id=upload_instance_id,
        chain_namespace=chain_namespace,
    )
    conflicts = snapshot["conflictingPeerJobs"]
    if conflicts:
        states = sorted({str(job.get("status", "unknown")) for job in conflicts})
        raise RuntimeError(
            "the shared pieces directory is still required by "
            f"{len(conflicts)} other durable storage obligation(s) "
            f"(states: {', '.join(states)}); refusing to overwrite it"
        )

    logical_jobs = snapshot["logicalJobs"]
    peer_jobs = snapshot["peerJobs"]
    if not logical_jobs and not peer_jobs:
        return False
    if not logical_jobs:
        raise RuntimeError(
            "current durable peer jobs exist without their logical piece records"
        )

    pieces = _validated_rida_piece_set(
        C.PIECES_DIR,
        expected_n=n,
        expected_m=m,
    )
    logical_by_index: dict[int, dict] = {}
    for job in logical_jobs:
        index = int(job.get("pieceIndex", 0) or 0)
        if index not in pieces:
            raise RuntimeError(
                f"durable logical job refers to missing RIDA piece {index}"
            )
        previous = logical_by_index.get(index)
        if previous is not None and (
            str(previous.get("logicalJobId", ""))
            != str(job.get("logicalJobId", ""))
        ):
            raise RuntimeError(
                f"multiple durable logical generations exist for piece {index}"
            )
        logical_by_index[index] = job

    durable_records = list(logical_jobs) + list(peer_jobs)
    for job in durable_records:
        index = int(job.get("pieceIndex", 0) or 0)
        expected_path = pieces.get(index)
        if expected_path is None:
            raise RuntimeError(f"durable job has invalid piece index {index}")
        raw_path = str(job.get("filePath", "") or "").strip()
        if not raw_path or Path(raw_path).resolve() != expected_path.resolve():
            raise RuntimeError(
                f"durable job path no longer identifies RIDA piece {index}"
            )
        digest, size = _stable_file_sha256(expected_path)
        if int(job.get("fileSize", -1)) != size:
            raise RuntimeError(f"durable RIDA piece {index} size changed")
        if str(job.get("fileDigest", "") or "").lower() != digest.lower():
            raise RuntimeError(f"durable RIDA piece {index} content changed")

    source_digest, source_size = _stable_file_sha256(file_path)
    with tempfile.TemporaryDirectory(prefix="filetrust-rida-recovery-") as tmp:
        reconstructed = Path(tmp) / "reconstructed.bin"
        ida_reconstruct_file(
            str(reconstructed),
            [str(pieces[index]) for index in sorted(pieces)[:m]],
        )
        comparison_path = reconstructed
        if use_aes:
            source = Path(file_path)
            key_path = Path(C.BASE_DIR) / f"{source.stem}_enc_keys.json"
            if not key_path.is_file():
                raise RuntimeError(
                    "the AES key needed to authenticate the durable pieces is missing"
                )
            plaintext = Path(tmp) / "reconstructed-plaintext.bin"
            decrypt_file(str(reconstructed), str(plaintext), str(key_path))
            comparison_path = plaintext
        recovered_digest, recovered_size = _stable_file_sha256(comparison_path)

    if recovered_size != source_size or recovered_digest != source_digest:
        raise RuntimeError(
            "durable RIDA pieces do not reconstruct to the currently selected file"
        )

    L.log(
        "Reusing authenticated durable RIDA pieces for interrupted upload "
        f"{upload_instance_id[:16]}...; no encryption or dispersal was repeated"
    )
    L.set_status("Reusing durable IDA pieces", "running")
    refresh_pieces_list()
    return True


def run_disperse():
    file_path = S.selected_file_var.get().strip()

    if not file_path:
        L.show_error("Input error", "Please select a file first.")
        L.set_status("Select a file first", "error")
        return False

    try:
        n = int(S.entry_n.get())
        m = int(S.entry_t.get())
    except ValueError:
        L.show_error("Input error", "Please enter integer values for IDA n and IDA t.")
        return False

    use_aes = S.chk_var.get()

    L.log("=== Disperse started ===")
    L.set_status("Splitting file into IDA pieces...", "running")
    L.log(f"Source file: {file_path}")
    L.log(f"IDA n (pieces): {n}")
    L.log(f"IDA t (threshold): {m}")
    L.log(f"AES enabled: {use_aes}")

    try:
        input_for_ida = file_path

        if os.path.isdir(C.PIECES_DIR):
            if _reuse_current_dispersal_if_safe(
                file_path, n=n, m=m, use_aes=bool(use_aes)
            ):
                L.log("=== Disperse recovery done ===\n")
                return True
            for _old in os.listdir(C.PIECES_DIR):
                _old_path = os.path.join(C.PIECES_DIR, _old)
                if os.path.isfile(_old_path):
                    os.remove(_old_path)
            L.log(f"Cleared previous pieces from: {C.PIECES_DIR}")

        if use_aes:
            L.set_status("Encrypting source file with AES...", "running")
            L.log("AES encryption in progress...")
            enc_path, key_json_path = encrypt_with_default_paths(file_path)
            L.log(f"Encrypted file: {enc_path}")
            L.log(f"AES key info: {key_json_path}")
            input_for_ida = enc_path

        L.log("IDA dispersal in progress...")
        L.set_status("Creating IDA pieces...", "running")
        ida_disperse_file(input_for_ida, C.PIECES_DIR, n, m)

        L.log(f"Pieces stored in: {C.PIECES_DIR}")
        L.log("=== Disperse done ===\n")
        L.set_status("IDA pieces created", "done")

        refresh_pieces_list()
        return True

    except Exception as e:
        L.show_error("Disperse error", str(e))
        L.log(f"Error during disperse: {e}")
        L.set_status("Disperse error", "error")
        return False


def _piece_file_count() -> int:
    """How many pieces this file was split into, from the pieces directory."""
    try:
        return sum(1 for entry in os.scandir(C.PIECES_DIR) if entry.is_file())
    except OSError:
        return 0


def run_upload_vaultmesh(
    *,
    raise_on_pending: bool = False,
    peers: list | None = None,
    resuming: int = 0,
):
    L.log("=== Upload VaultMesh started ===")
    L.log(f"Using pieces directory: {C.PIECES_DIR}")
    L.set_status("Uploading pieces to VaultMesh...", "running")

    ctx = get_current_file_context(show_errors=False)
    if not ctx:
        L.show_error("VaultMesh error", "Please set Policy Name, Data Tag, and Date first.")
        L.log("VaultMesh error: missing current file context.")
        L.set_status("VaultMesh upload needs file context", "error")
        return False

    _file_id, file_id_hex, _do_input, _policy_name, _data_tag, _date_str, _ts = ctx
    upload_instance_id = HX.derive_upload_instance_id(
        file_id_hex, _data_tag, _ts
    )

    # A resume supplies the keepers from its own job records; a fresh upload
    # takes them from the Vault Keepers tab.
    peers = list(peers) if peers else N.get_selected_vk_peers()
    if not peers:
        L.show_error(
            "VaultMesh Peer Error",
            "Please select at least one registered Vault Keeper or enter a Vault Keeper peer multiaddr."
        )
        L.set_status("Select a Vault Keeper first", "error")
        return False

    try:
        json_output = R.share_cids_path()
        service_days = N.get_service_duration_days()
        # Solidity enforces service windows with block.timestamp. Derive the
        # agreement endpoint from the same clock instead of the workstation
        # clock, which may differ from the validator even when local NTP is healthy.
        chain_now = VM.latest_chain_timestamp()
        service_end = int(chain_now + service_days * 86400)
        _fmt = "rida-v1"
        L.log(f"Selected Vault Keepers: {len(peers)}")
        L.log(f"VaultMesh serviceEnd: {service_end} ({datetime.datetime.fromtimestamp(service_end).astimezone().isoformat()})")
        PROG.step("keepers chosen", len(peers), len(peers))
        if resuming:
            # A resume is counted in the pieces it still owes, not in the
            # keepers of the whole file: "storing on 6 keepers" after asking
            # to finish 2 pieces describes work that is not happening.
            total_pieces = _piece_file_count() or resuming
            L.set_status(
                f"Continuing {resuming} of {total_pieces} piece(s)...", "running"
            )
        else:
            L.set_status(f"Storing pieces on {len(peers)} Vault Keeper(s)...", "running")
        receipts_output = R.vaultmesh_piece_receipts_path()
        manifest = VM.store_shares_in_vaultmesh(
            C.PIECES_DIR,
            file_id_hex,
            peers,
            json_output,
            service_end=service_end,
            file_format=_fmt,
            upload_instance_id=upload_instance_id,
            private_json_output=receipts_output,
        )
        for item in manifest.get("pieces", []):
            if item.get("fileRegFullyVerified") is not True:
                VM.queue_storage_verification(item, str(receipts_output))

        for item in manifest.get("pieces", []):
            L.log(
                f"piece {item['pieceIndex']} | {item['name']} -> "
                "storage receipt and on-chain proof verified"
            )
            attempts = item.get("attemptHistory") or []
            if len(attempts) > 1:
                attempt_chain = " -> ".join(
                    f"{a.get('peerId','?')}:{a.get('status','?')}" for a in attempts
                )
                L.log(f"piece {item['pieceIndex']} retry path: {attempt_chain}")

        L.log(f"VaultMesh encrypted-payload source saved to: {json_output}")
        L.log(f"VaultMesh full local piece receipts saved to: {receipts_output}")
        L.log("=== Upload VaultMesh done ===\n")

        L.log("=== VK Receipt Verification Summary ===")
        for item in manifest.get("pieces", []):
            r = item.get("privateReceipt")
            if not r:
                L.log(f"  piece {item['pieceIndex']}: no receipt")
                continue
            se = r.get("serviceEnd", 0)
            try:
                se_str = datetime.datetime.fromtimestamp(se).astimezone().strftime("%Y-%m-%d %H:%M %Z")
            except Exception:
                se_str = str(se)
            L.log(
                f"  piece {item['pieceIndex']}: verified; "
                f"size={int(r.get('pieceSize', 0) or 0):,} bytes; "
                f"serviceEnd={se_str}"
            )
        L.log("=== End VK Receipt Verification Summary ===\n")
        R.save_file_upload_record(
            _policy_name, _data_tag, _date_str, _ts, manifest.get("pieces", []),
            file_id=manifest.get("fileId", "") or ctx.get("file_id", ""),
        )

        # Leave each keeper a sealed copy of this upload's records. It is the
        # only route back to the signed receipts after a reinstall, and it has
        # to happen here, while they are still in hand. Best effort by design:
        # an upload that succeeded is not reported as failed because a keeper
        # would not take a backup.
        try:
            from . import do_sealed_copy as SEAL

            SEAL.distribute(
                manifest.get("fileId", "") or ctx.get("file_id", ""),
                manifest.get("uploadInstanceId", "") or ctx.get("upload_instance_id", ""),
                manifest.get("pieces", []),
            )
        except Exception as exc:
            L.log(f"[Sealed copy] skipped: {exc}")
        if S.drop_folder_current_item:
            _save_drop_upload_record(S.drop_folder_current_item, ctx, manifest)
        S.root.after(0, load_policies_browser)
        verification = manifest.get("storageVerification") or {}
        if verification.get("status") != "verified":
            raise VM.XFER.TransferPending(
                "VaultMesh storage returned before every piece was fully verified"
            )
        L.set_status("VaultMesh pieces verified", "done")
        return True

    except VM.XFER.TransferPaused as e:
        L.log(f"VaultMesh upload paused: {e}")
        L.set_status("VaultMesh uploads paused", "waiting")
        return False
    except VM.XFER.TransferPending as e:
        L.log(f"VaultMesh durable transfer pending: {e}")
        if raise_on_pending:
            L.set_status("VaultMesh transfer pending; resume required", "waiting")
            raise
        # Retrying is the app's job, not the operator's: this state clears by
        # itself. No dialog — a popup here interrupts a wait that resolves in
        # seconds, and the retry line in the log already reports progress.
        L.set_status("VaultMesh transfer pending; retrying automatically...", "waiting")
        _schedule_pending_upload_retry()
        return False
    except Exception as e:
        L.show_error("VaultMesh error", str(e))
        L.log(f"VaultMesh error: {e}")
        L.set_status("VaultMesh upload error", "error")
        return False


@TM.serialized_account(lambda *args, **kwargs: C.DO_ACCOUNT.address)
def _existing_matching_datavault_batch(
    *,
    file_id,
    file_id_hex,
    data_tag,
    timestamp,
    ida_n,
    ida_t,
    key_epoch,
    minimum_record_count,
):
    """Return an already-complete matching batch, or fail closed on conflict."""
    exists, batch_id = C.dv.functions.getBatchIdForFileData(
        file_id, data_tag, int(timestamp)
    ).call()
    if not exists or int(batch_id) <= 0:
        return None

    (
        stored_file_id,
        stored_owner,
        stored_data_tag,
        stored_timestamp,
        stored_n,
        stored_t,
        stored_key_epoch,
        cid_indices,
    ) = C.dv.functions.getBatch(int(batch_id)).call()

    expected_file_id = C.w3.to_hex(file_id).lower()
    actual_file_id = C.w3.to_hex(stored_file_id).lower()
    mismatches = []
    if actual_file_id != expected_file_id:
        mismatches.append("fileId")
    if str(stored_owner).lower() != str(C.DO_ACCOUNT.address).lower():
        mismatches.append("owner")
    if str(stored_data_tag) != str(data_tag):
        mismatches.append("dataId")
    if int(stored_timestamp) != int(timestamp):
        mismatches.append("timestamp")
    if int(stored_n) != int(ida_n) or int(stored_t) != int(ida_t):
        mismatches.append("IDA profile")
    if int(stored_key_epoch) != int(key_epoch):
        mismatches.append("key epoch")
    if len(cid_indices) < max(1, int(minimum_record_count)):
        mismatches.append("encrypted record count")
    if mismatches:
        raise RuntimeError(
            "Existing DataVault batch conflicts with this durable upload "
            f"({', '.join(mismatches)}); refusing to overwrite or duplicate "
            f"fileId={file_id_hex}"
        )
    return {
        "batch_id": int(batch_id),
        "record_count": len(cid_indices),
        "key_epoch": int(stored_key_epoch),
    }


def run_upload_cids():
    L.set_status("Preparing encrypted PieceRoot upload...", "running")
    if not C.w3.is_connected():
        L.show_error("Blockchain error", "Web3 is not connected. Please start the node.")
        L.log("ERROR: Web3 is not connected.")
        L.set_status("Blockchain not connected", "error")
        return False

    ctx = get_current_file_context()
    if not ctx:
        L.set_status("PieceRoot upload needs file context", "error")
        return False

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx
    S.ACTIVE_FILE_ID = file_id
    S.ACTIVE_FILE_ID_HEX = file_id_hex

    try:
        if C.POLICY_DKG_MODE == "ZKDKG_V2":
            L.set_status("Loading finalized V2 public key...", "running")
            from .do_crypto import get_finalized_v2_public_key
            PK, S.KEY_EPOCH, _share_version = get_finalized_v2_public_key(file_id)
            S.PKX_VALUE, S.PKY_VALUE = PK
            L.log(f"Loaded ZKDKG_V2 Baby Jubjub PK (epoch={S.KEY_EPOCH}) for current policyId.")
        else:
            if not CH.load_pk_json(expected_file_id_hex=file_id_hex):
                L.show_error(
                    "Missing DKG key",
                    "No DKG key found locally or on-chain for this policy.\n\nRun Key Gen first."
                )
                L.log("ERROR: no DKG key found locally or on-chain for current policyId. Run Key Gen first.")
                return False
            L.log(f"Loaded PK (epoch={S.KEY_EPOCH}) for current policyId.")

    except Exception as e:
        L.show_error("DKG key error", str(e))
        L.log(f"ERROR: DKG key error for current policyId: {e}")
        L.set_status("DKG key error", "error")
        return False

    if S.KEY_EPOCH is None or S.KEY_EPOCH == 0:
        L.show_error("Error", "Key epoch not set. Run Key Gen and wait for DKG first.")
        L.log("ERROR: KEY_EPOCH not set.")
        L.set_status("Run KeyGen first", "error")
        return False

    L.log("=== Upload VaultMesh PieceRoot payloads (encrypt + on-chain) ===")
    L.set_status("Encrypting VaultMesh PieceRoots...", "running")
    L.log(f"policyId={file_id_hex}")

    use_aes = S.chk_var.get()
    L.log(f"AES enabled for file: {use_aes}")

    cids_json_path = R.share_cids_path()

    src = S.selected_file_var.get().strip()
    key_name = "data_enc_keys.json"
    file_format = "bin"

    if src:
        _, base = os.path.split(src)
        name, ext = os.path.splitext(base)
        key_name = f"{name}_enc_keys.json"
        file_format = ext.lstrip(".") if ext else "bin"

    enc_key_json_path = os.path.join(C.BASE_DIR, key_name)
    enc_cids_out_path = R.enc_cids_path()

    if not os.path.isfile(cids_json_path):
        L.show_error("Error", f"share_cids.json not found in {C.CID_RECORDS_DIR}")
        L.log(f"ERROR: share_cids.json missing in {C.CID_RECORDS_DIR}.")
        L.set_status("Missing VaultMesh PieceRoot manifest", "error")
        return False

    if use_aes and not os.path.isfile(enc_key_json_path):
        L.show_error("Error", f"{key_name} not found in {C.BASE_DIR}")
        L.log(f"ERROR: {key_name} missing.")
        return False

    try:
        from .do_crypto import xor_stream_encrypt, telg_encrypt_str_ec
        from .do_config import v2_batch_encryption_secret, v2_encrypt_with_shared

        payload_items = VM.load_vaultmesh_payloads(cids_json_path)

        n = int(S.entry_n.get().strip())
        t = int(S.entry_t.get().strip())

        if n <= 0 or t <= 0 or t > n:
            L.show_error("Error", "IDA values must satisfy n > 0, t > 0, and t <= n.")
            return False

        data_piece_count = len([x for x in payload_items if int(x["pieceIndex"]) != C.META_PIECE_INDEX])
        if n != data_piece_count:
            L.log(f"[WARN] IDA n={n}, but share_cids.json has {data_piece_count} VaultMesh piece entries.")

        existing_batch = _existing_matching_datavault_batch(
            file_id=file_id,
            file_id_hex=file_id_hex,
            data_tag=data_tag,
            timestamp=ts,
            ida_n=n,
            ida_t=t,
            key_epoch=int(S.KEY_EPOCH),
            minimum_record_count=data_piece_count,
        )
        if existing_batch is not None:
            L.log(
                "DataVault batch already exists and matches this durable upload; "
                f"reusing batchId={existing_batch['batch_id']} with "
                f"{existing_batch['record_count']} encrypted record(s)."
            )
            L.set_status("Encrypted PieceRoot records already verified on-chain", "success")
            return True

        PK = (S.PKX_VALUE, S.PKY_VALUE)
        is_v2 = C.POLICY_DKG_MODE == "ZKDKG_V2"
        v2_batch_c1 = None
        v2_batch_shared = None
        if is_v2:
            v2_batch_c1, v2_batch_shared = v2_batch_encryption_secret(PK)
        enc_list = []

        for item in payload_items:
            label = item["label"]
            piece_index = int(item["pieceIndex"])
            payload_obj = item["payload"]
            # Only store the two fields the requester needs to locate the piece.
            # All other fields (storage, identifier, name, size, pieceIndex, rootAlg)
            # are never read back after decryption — confirmed in req_actions.py.
            payload_bytes = json.dumps(
                {"peerId": payload_obj.get("peerId", ""), "pieceRoot": payload_obj.get("pieceRoot", "")},
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")

            K_bytes = secrets.token_bytes(32)
            K_hex = K_bytes.hex()

            ct_sym_bytes = xor_stream_encrypt(payload_bytes, K_bytes)
            if is_v2:
                C1 = v2_batch_c1
                C2 = v2_encrypt_with_shared(v2_batch_shared, K_hex.encode("utf-8"))
            else:
                C1, C2 = telg_encrypt_str_ec(PK, K_hex)
            C1x, C1y = C1

            enc_list.append(
                {
                    "label": label,
                    "pieceIndex": piece_index,
                    "payloadType": "vaultmesh_piece",
                    "payloadPreview": {
                        "pieceIndex": piece_index,
                        "pieceRoot": payload_obj.get("pieceRoot", ""),
                        "peerId": VM.short_peer(payload_obj.get("peerId", "")),
                    },
                    "C1x": str(C1x),
                    "C1y": str(C1y),
                    "C2_hex": C2.hex(),
                    "ctSym_hex": ct_sym_bytes.hex(),
                }
            )

        L.set_status("Writing encrypted PieceRoot records locally...", "running")
        if use_aes:
            with open(enc_key_json_path, "r", encoding="utf-8") as f:
                aes_info_obj = json.load(f)

            aes_info_str = json.dumps(aes_info_obj, sort_keys=True, separators=(",", ":"))
            aes_bytes = aes_info_str.encode("utf-8")

            K_bytes = secrets.token_bytes(32)
            K_hex = K_bytes.hex()

            ct_sym_aes = xor_stream_encrypt(aes_bytes, K_bytes)
            if is_v2:
                C1_aes = v2_batch_c1
                C2_aes = v2_encrypt_with_shared(v2_batch_shared, K_hex.encode("utf-8"))
            else:
                C1_aes, C2_aes = telg_encrypt_str_ec(PK, K_hex)
            C1x_aes, C1y_aes = C1_aes

            enc_list.append(
                {
                    "label": "__AES_INFO__",
                    "pieceIndex": C.META_PIECE_INDEX,
                    "payloadType": "aes_info",
                    "C1x": str(C1x_aes),
                    "C1y": str(C1y_aes),
                    "C2_hex": C2_aes.hex(),
                    "ctSym_hex": ct_sym_aes.hex(),
                }
            )

        with open(enc_cids_out_path, "w", encoding="utf-8") as f:
            json.dump(enc_list, f, indent=2)

        L.log(f"Encrypted VaultMesh payloads written to: {enc_cids_out_path}")
        L.log(f"Using account: {C.DO_ACCOUNT.address}")
        L.log(f"dataId={data_tag}, date={date_str}")

        nonce = TM.pending_nonce(C.w3, C.DO_ACCOUNT.address)
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="getTransactionCount",
            actor_address=C.DO_ACCOUNT.address,
            status="success",
            nonce=nonce,
            flow="data_vault_upload",
        )

        batch_id = 0
        batch_upload_done = False
        combined_batch_done = False

        combined_upload_enabled = bool(getattr(C.config, "DATAVAULT_COMBINED_V2_BATCH_UPLOAD", True))
        if combined_upload_enabled and is_v2 and v2_batch_c1 is not None and enc_list:
            combined_tx_submitted = False
            try:
                L.set_status(
                    f"Creating V2 DataVault batch and storing {len(enc_list)} encrypted PieceRoot records in one tx...",
                    "running",
                )
                piece_indices = [int(entry["pieceIndex"]) for entry in enc_list]
                C1xs = [int(entry["C1x"]) for entry in enc_list]
                C1ys = [int(entry["C1y"]) for entry in enc_list]
                C2s = [bytes.fromhex(entry["C2_hex"]) for entry in enc_list]
                ctSyms = [bytes.fromhex(entry["ctSym_hex"]) for entry in enc_list]
                combined_function_name = str(
                    getattr(C.config, "DATA_VAULT_COMBINED_V2_BATCH_FUNCTION", "createV2BatchWithCids")
                    or "createV2BatchWithCids"
                )
                fn_combined = getattr(C.dv.functions, combined_function_name)(
                    file_id,
                    data_tag,
                    ts,
                    n,
                    t,
                    int(S.KEY_EPOCH),
                    int(v2_batch_c1[0]),
                    int(v2_batch_c1[1]),
                    piece_indices,
                    C1xs,
                    C1ys,
                    C2s,
                    ctSyms,
                )
                gas_est_combined = fn_combined.estimate_gas({"from": C.DO_ACCOUNT.address})
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=C.dv.address,
                    actor_address=C.DO_ACCOUNT.address,
                    status="success",
                    gas_estimate=gas_est_combined,
                    target_function=combined_function_name,
                    flow="data_vault_upload",
                    record_count=len(enc_list),
                )
                gas_price_combined = C.gas_price_wei()
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="gasPrice",
                    actor_address=C.DO_ACCOUNT.address,
                    status="success",
                    result=gas_price_combined,
                    target_function=combined_function_name,
                    flow="data_vault_upload",
                    record_count=len(enc_list),
                )
                tx_combined = fn_combined.build_transaction(
                    {
                        "from": C.DO_ACCOUNT.address,
                        "nonce": nonce,
                        "gas": gas_est_combined + 150_000,
                        "gasPrice": gas_price_combined,
                    }
                )
                signed_combined = C.DO_ACCOUNT.sign_transaction(tx_combined)
                tx_hash_combined = C.w3.eth.send_raw_transaction(signed_combined.raw_transaction)
                combined_tx_submitted = True
                receipt_combined = C.w3.eth.wait_for_transaction_receipt(tx_hash_combined)
                exists_combined, batch_id_combined = C.dv.functions.getBatchIdForFileData(file_id, data_tag, ts).call()
                TX.log_contract_transaction(
                    C,
                    C.w3,
                    actor_address=C.DO_ACCOUNT.address,
                    contract_name="DataVault",
                    function_name=combined_function_name,
                    contract_address=C.dv.address,
                    tx=tx_combined,
                    tx_hash=tx_hash_combined,
                    receipt=receipt_combined,
                    file_id=file_id_hex,
                    data_id=data_tag,
                    timestamp=ts,
                    batch_id=int(batch_id_combined) if exists_combined else 0,
                    record_count=len(enc_list),
                )
                if receipt_combined.status != 1:
                    L.log(f"[FAILED] {combined_function_name} tx: {tx_hash_combined.hex()}")
                    return False
                if not exists_combined or batch_id_combined == 0:
                    L.log(f"ERROR: batch not found after {combined_function_name}.")
                    return False
                batch_id = batch_id_combined
                nonce += 1
                combined_batch_done = True
                batch_upload_done = True
                L.log(f"V2 batch, C1, and {len(enc_list)} encrypted PieceRoot records uploaded in one tx: {tx_hash_combined.hex()}")
                L.log(f"Using batchId={batch_id}")
            except Exception as e:
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=C.dv.address,
                    actor_address=C.DO_ACCOUNT.address,
                    status="failed",
                    error=str(e),
                    target_function=str(getattr(C.config, "DATA_VAULT_COMBINED_V2_BATCH_FUNCTION", "createV2BatchWithCids") or "createV2BatchWithCids"),
                    flow="data_vault_upload",
                    record_count=len(enc_list),
                )
                if combined_tx_submitted:
                    L.log("Combined V2 transaction was already submitted; not falling back to avoid duplicate batch creation.")
                    return False
                L.log(f"Combined V2 batch upload unavailable; using legacy three-step upload path: {e}")

        if not combined_batch_done:
            L.set_status("Creating DataVault batch on-chain...", "running")
            fn_batch = C.dv.functions.createBatch(
                file_id,
                data_tag,
                ts,
                n,
                t,
                int(S.KEY_EPOCH),
            )

            gas_est_batch = fn_batch.estimate_gas({"from": C.DO_ACCOUNT.address})
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=C.dv.address,
                actor_address=C.DO_ACCOUNT.address,
                status="success",
                gas_estimate=gas_est_batch,
                target_function="createBatch",
                flow="data_vault_upload",
            )
            gas_price_batch = C.gas_price_wei()
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="gasPrice",
                actor_address=C.DO_ACCOUNT.address,
                status="success",
                result=gas_price_batch,
                target_function="createBatch",
                flow="data_vault_upload",
            )
            tx_batch = fn_batch.build_transaction(
                {
                    "from": C.DO_ACCOUNT.address,
                    "nonce": nonce,
                    "gas": gas_est_batch + 50_000,
                    "gasPrice": gas_price_batch,
                }
            )

            signed_batch = C.DO_ACCOUNT.sign_transaction(tx_batch)
            tx_hash_batch = C.w3.eth.send_raw_transaction(signed_batch.raw_transaction)
            receipt_batch = C.w3.eth.wait_for_transaction_receipt(tx_hash_batch)
            TX.log_contract_transaction(
                C,
                C.w3,
                actor_address=C.DO_ACCOUNT.address,
                contract_name="DataVault",
                function_name="createBatch",
                contract_address=C.dv.address,
                tx=tx_batch,
                tx_hash=tx_hash_batch,
                receipt=receipt_batch,
                file_id=file_id_hex,
                data_id=data_tag,
                timestamp=ts,
            )

            if receipt_batch.status != 1:
                L.log(f"[FAILED] createBatch tx: {tx_hash_batch.hex()}")
                return False

            L.log(f"Batch created, tx: {tx_hash_batch.hex()}")
            nonce += 1

            exists, batch_id = C.dv.functions.getBatchIdForFileData(file_id, data_tag, ts).call()
            if not exists or batch_id == 0:
                L.log("ERROR: batch not found after createBatch.")
                return False

            L.log(f"Using batchId={batch_id}")

            if is_v2 and v2_batch_c1 is not None:
                L.set_status("Setting V2 batch C1 on-chain...", "running")
                fn_c1 = C.dv.functions.setV2BatchC1(batch_id, int(v2_batch_c1[0]), int(v2_batch_c1[1]))
                try:
                    gas_est_c1 = fn_c1.estimate_gas({"from": C.DO_ACCOUNT.address})
                    TX.log_eth_call(
                        C,
                        contract_name="eth",
                        function_name="estimateGas",
                        contract_address=C.dv.address,
                        actor_address=C.DO_ACCOUNT.address,
                        status="success",
                        gas_estimate=gas_est_c1,
                        target_function="setV2BatchC1",
                        batch_id=int(batch_id),
                    )
                    gas_price_c1 = C.gas_price_wei()
                    TX.log_eth_call(
                        C,
                        contract_name="eth",
                        function_name="gasPrice",
                        actor_address=C.DO_ACCOUNT.address,
                        status="success",
                        result=gas_price_c1,
                        target_function="setV2BatchC1",
                        batch_id=int(batch_id),
                    )
                    tx_c1 = fn_c1.build_transaction(
                        {
                            "from": C.DO_ACCOUNT.address,
                            "nonce": nonce,
                            "gas": gas_est_c1 + 50_000,
                            "gasPrice": gas_price_c1,
                        }
                    )
                    signed_c1 = C.DO_ACCOUNT.sign_transaction(tx_c1)
                    tx_hash_c1 = C.w3.eth.send_raw_transaction(signed_c1.raw_transaction)
                    receipt_c1 = C.w3.eth.wait_for_transaction_receipt(tx_hash_c1)
                    TX.log_contract_transaction(
                        C,
                        C.w3,
                        actor_address=C.DO_ACCOUNT.address,
                        contract_name="DataVault",
                        function_name="setV2BatchC1",
                        contract_address=C.dv.address,
                        tx=tx_c1,
                        tx_hash=tx_hash_c1,
                        receipt=receipt_c1,
                        batch_id=int(batch_id),
                    )
                    if receipt_c1.status != 1:
                        L.log(f"[FAILED] setV2BatchC1 tx: {tx_hash_c1.hex()}")
                        return False
                    L.log(f"V2 batch C1 set, tx: {tx_hash_c1.hex()}")
                    nonce += 1
                except Exception as e:
                    L.log(f"ERROR: failed to set V2 batch C1: {e}")
                    return False

            batch_upload_done = False
            if is_v2 and enc_list:
                try:
                    L.set_status(f"Storing {len(enc_list)} encrypted PieceRoot records on blockchain...", "running")
                    piece_indices = [int(entry["pieceIndex"]) for entry in enc_list]
                    C1xs = [int(entry["C1x"]) for entry in enc_list]
                    C1ys = [int(entry["C1y"]) for entry in enc_list]
                    C2s = [bytes.fromhex(entry["C2_hex"]) for entry in enc_list]
                    ctSyms = [bytes.fromhex(entry["ctSym_hex"]) for entry in enc_list]
                    fn_many = C.dv.functions.addManyEncCidsToBatch(batch_id, piece_indices, C1xs, C1ys, C2s, ctSyms)
                    gas_est_many = fn_many.estimate_gas({"from": C.DO_ACCOUNT.address})
                    TX.log_eth_call(
                        C,
                        contract_name="eth",
                        function_name="estimateGas",
                        contract_address=C.dv.address,
                        actor_address=C.DO_ACCOUNT.address,
                        status="success",
                        gas_estimate=gas_est_many,
                        target_function="addManyEncCidsToBatch",
                        batch_id=int(batch_id),
                        record_count=len(enc_list),
                    )
                    gas_price_many = C.gas_price_wei()
                    TX.log_eth_call(
                        C,
                        contract_name="eth",
                        function_name="gasPrice",
                        actor_address=C.DO_ACCOUNT.address,
                        status="success",
                        result=gas_price_many,
                        target_function="addManyEncCidsToBatch",
                        batch_id=int(batch_id),
                        record_count=len(enc_list),
                    )
                    tx_many = fn_many.build_transaction(
                        {
                            "from": C.DO_ACCOUNT.address,
                            "nonce": nonce,
                            "gas": gas_est_many + 100_000,
                            "gasPrice": gas_price_many,
                        }
                    )
                    signed_many = C.DO_ACCOUNT.sign_transaction(tx_many)
                    tx_hash_many = C.w3.eth.send_raw_transaction(signed_many.raw_transaction)
                    receipt_many = C.w3.eth.wait_for_transaction_receipt(tx_hash_many)
                    TX.log_contract_transaction(
                        C,
                        C.w3,
                        actor_address=C.DO_ACCOUNT.address,
                        contract_name="DataVault",
                        function_name="addManyEncCidsToBatch",
                        contract_address=C.dv.address,
                        tx=tx_many,
                        tx_hash=tx_hash_many,
                        receipt=receipt_many,
                        batch_id=int(batch_id),
                        record_count=len(enc_list),
                    )
                    if receipt_many.status != 1:
                        L.log(f"[FAILED] batch encrypted CID upload tx: {tx_hash_many.hex()}")
                        return False
                    L.log(f"Uploaded {len(enc_list)} encrypted PieceRoot records in one batch tx: {tx_hash_many.hex()}")
                    nonce += 1
                    batch_upload_done = True
                except Exception as e:
                    L.log(f"Batch encrypted PieceRoot upload unavailable or failed; falling back to per-record uploads: {e}")

        if not batch_upload_done:
            L.set_status(f"Storing {len(enc_list)} encrypted PieceRoot records one by one...", "running")
            for entry in enc_list:
                label = entry["label"]
                piece_index = int(entry["pieceIndex"])
                C1x = int(entry["C1x"])
                C1y = int(entry["C1y"])
                C2 = bytes.fromhex(entry["C2_hex"])
                ctSym = bytes.fromhex(entry["ctSym_hex"])

                fn = C.dv.functions.addEncCidToBatch(batch_id, piece_index, C1x, C1y, C2, ctSym)

                try:
                    gas_est = fn.estimate_gas({"from": C.DO_ACCOUNT.address})
                except Exception as e:
                    TX.log_eth_call(
                        C,
                        contract_name="eth",
                        function_name="estimateGas",
                        contract_address=C.dv.address,
                        actor_address=C.DO_ACCOUNT.address,
                        status="failed",
                        error=str(e),
                        target_function="addEncCidToBatch",
                        batch_id=int(batch_id),
                        piece_index=piece_index,
                    )
                    L.log(f"[SKIP] {label}: estimate_gas failed ({e})")
                    continue
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=C.dv.address,
                    actor_address=C.DO_ACCOUNT.address,
                    status="success",
                    gas_estimate=gas_est,
                    target_function="addEncCidToBatch",
                    batch_id=int(batch_id),
                    piece_index=piece_index,
                )
                gas_price = C.gas_price_wei()
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="gasPrice",
                    actor_address=C.DO_ACCOUNT.address,
                    status="success",
                    result=gas_price,
                    target_function="addEncCidToBatch",
                    batch_id=int(batch_id),
                    piece_index=piece_index,
                )

                tx = fn.build_transaction(
                    {
                        "from": C.DO_ACCOUNT.address,
                        "nonce": nonce,
                        "gas": gas_est + 50_000,
                        "gasPrice": gas_price,
                    }
                )

                signed = C.DO_ACCOUNT.sign_transaction(tx)
                tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = C.w3.eth.wait_for_transaction_receipt(tx_hash)
                TX.log_contract_transaction(
                    C,
                    C.w3,
                    actor_address=C.DO_ACCOUNT.address,
                    contract_name="DataVault",
                    function_name="addEncCidToBatch",
                    contract_address=C.dv.address,
                    tx=tx,
                    tx_hash=tx_hash,
                    receipt=receipt,
                    batch_id=int(batch_id),
                    piece_index=piece_index,
                    label=label,
                )

                if receipt.status == 1:
                    L.log(f"Uploaded {label}, pieceIndex={piece_index}, tx: {tx_hash.hex()}")
                    L.set_status(f"Stored encrypted PieceRoot piece {piece_index}", "running")
                else:
                    L.log(f"[FAILED] {label}, pieceIndex={piece_index}, tx: {tx_hash.hex()}")

                nonce += 1

        L.log("\n=== On-chain records for this batch ===")
        L.set_status("Verifying DataVault records...", "running")

        try:
            (
                fileId_onchain,
                owner_onchain,
                dataId_onchain,
                ts_onchain,
                n_onchain,
                t_onchain,
                keyEpoch_onchain,
                cid_indices,
            ) = C.dv.functions.getBatch(batch_id).call()

            ts_dt = datetime.datetime.fromtimestamp(ts_onchain).astimezone()

            L.log(f"BatchId: {batch_id}")
            L.log(f"policyId: {fileId_onchain.hex()}")
            L.log(f"owner: {owner_onchain}")
            L.log(f"dataId: {dataId_onchain}")
            L.log(f"ts: {ts_onchain} ({ts_dt.isoformat()})")
            L.log(f"IDA n: {n_onchain}")
            L.log(f"IDA t: {t_onchain}")
            L.log(f"keyEpoch: {keyEpoch_onchain}")
            L.log(f"#valid items: {len(cid_indices)}")

            for idx_pos, cid_index in enumerate(cid_indices):
                try:
                    C1x_on, C1y_on, C2_on, ctSym_on, batch_id_on, piece_index_on, valid_on, replaced_by_on = C.dv.functions.getEncCidV2(cid_index).call()
                    label = enc_list[idx_pos]["label"] if idx_pos < len(enc_list) else "<unknown>"
                    L.log(f"EncCid index {cid_index} ({label})")
                    L.log(f"  pieceIndex: {piece_index_on}")
                    L.log(f"  valid: {valid_on}, replacedBy: {replaced_by_on}")
                    L.log(f"  C1x: {C1x_on}")
                    L.log(f"  C1y: {C1y_on}")
                    L.log(f"  C2 len: {len(C2_on)} bytes")
                    L.log(f"  ctSym len: {len(ctSym_on)} bytes")
                except Exception:
                    C1x_on, C1y_on, C2_on, ctSym_on = C.dv.functions.getEncCid(cid_index).call()
                    label = enc_list[idx_pos]["label"] if idx_pos < len(enc_list) else "<unknown>"
                    L.log(f"EncCid index {cid_index} ({label})")
                    L.log(f"  C1x: {C1x_on}")
                    L.log(f"  C1y: {C1y_on}")
                    L.log(f"  C2 len: {len(C2_on)} bytes")
                    L.log(f"  ctSym len: {len(ctSym_on)} bytes")

        except Exception as e:
            L.log(f"ERROR reading batch back: {e}")

        L.log("=== Upload VaultMesh PieceRoot payloads done ===\n")
        L.set_status("File upload complete", "done")

        if getattr(S, "auto_quiet_info", False):
            S.auto_quiet_info = False
            L.show_info(
                "Auto Upload Complete",
                "Key generated, best Guardians and Vault Keepers selected, and upload completed successfully.\n\n"
                "You can now assign a requester to this policy from the Requester tab.",
            )
        else:
            L.show_info(
                "Upload PieceRoots",
                "Encrypted VaultMesh PieceRoot payloads and AES metadata, if enabled, were uploaded successfully.",
            )
        return True

    except Exception as e:
        S.auto_quiet_info = False
        L.show_error("Upload PieceRoots error", str(e))
        L.log(f"ERROR in run_upload_cids: {e}")
        L.set_status("PieceRoot upload error", "error")
        return False


def run_withdraw_dkg_credits():
    if getattr(C,'DKG_ATTEMPT_PROTOCOL',0)!=1:
        return L.show_info('DKG credits','Select the recovery deployment to withdraw its escrow credits')
    from .do_dkg_ui import claim_credits
    return claim_credits()


def run_keygen_request():
    if getattr(C, 'DKG_ATTEMPT_PROTOCOL', 0) == 1:
        from .do_dkg_ui import start
        return start('fresh')
    L.log("=== KeyGen request ===")
    L.set_status("Requesting key generation...", "running")

    try:
        ctx = get_current_file_context()
        if not ctx:
            L.set_status("KeyGen waiting for file context", "waiting")
            return

        file_id, file_id_hex, do_input, policy_name, data_tag_ctx, date_str_ctx, ts = ctx
        S.ACTIVE_FILE_ID = file_id
        S.ACTIVE_FILE_ID_HEX = file_id_hex

        exists, active, _, policy_t, policy_guardians = C.acl.functions.getFilePolicy(file_id).call()

        if not exists:
            L.log("No file policy found. Creating it from selected Guardians...")
            if not create_or_update_file_policy():
                L.log("KeyGen stopped: file policy was not created.")
                L.set_status("KeyGen stopped: policy missing", "error")
                return
            exists, active, _, policy_t, policy_guardians = C.acl.functions.getFilePolicy(file_id).call()

        S.LAST_PKX_VALUE = S.PKX_VALUE
        S.LAST_PKY_VALUE = S.PKY_VALUE

        is_do = C.acl.functions.isDataOwner(C.DO).call()

        L.log(f"DO isDataOwner: {is_do}")
        L.log(f"policyId: {file_id_hex}")
        L.log(f"policy active: {active}")
        L.log(f"guardian threshold: {policy_t}")
        L.log(f"policy guardians: {len(policy_guardians)}")

        CH.ensure_v2_policy_escrow(file_id)

        L.set_status("Submitting KeyGen request on-chain...", "running")
        fn = C.acl.functions.requestKeyGenForFile(file_id)
        CH.send_signed_tx(fn, C.DO_ACCOUNT, "KeyGen request sent")

        L.set_status("KeyGen requested; waiting for Guardians...", "waiting")
        L.log("Waiting for DKG key generation for this policyId...")
        S.root.after(5000, poll_dkg_for_key)

    except Exception as e:
        S.auto_upload_pending = False
        S.auto_quiet_info = False
        L.show_error("KeyGen error", str(e))
        L.log(f"KeyGen error: {e}")
        L.set_status("KeyGen error", "error")

    L.log("=== KeyGen request submitted ===\n")


# The guardian key exchange, as its own operation. Inside an upload these two
# phases already exist under the upload's weights, so the bar is never restarted.
_GUARDIAN_KEY_PHASES = [
    ("guardian commitments", 0.5),
    ("guardian shares", 0.5),
]


def poll_dkg_for_key():
    if getattr(C, 'DKG_ATTEMPT_PROTOCOL', 0) == 1:
        from .do_dkg_ui import start_reconciler
        return start_reconciler()
    try:
        if S.ACTIVE_FILE_ID is None:
            ctx = get_current_file_context(show_errors=False)
            if not ctx:
                L.log_state(("do-dkg-poll", "no-active-file"), True, "No active policyId for DKG polling.")
                return
            S.ACTIVE_FILE_ID, S.ACTIVE_FILE_ID_HEX, _do_input, policy_name, data_tag, date_str, ts = ctx

        exists, active, owner, policy_t, policy_guardians = C.acl.functions.getFilePolicy(
            S.ACTIVE_FILE_ID
        ).call()

        if not exists:
            L.log_state(("do-dkg-poll", "no-policy", S.ACTIVE_FILE_ID_HEX), True, "No policy found for this policyId.")
            L.set_status("Waiting for policy before KeyGen...", "waiting")
            S.root.after(5000, poll_dkg_for_key)
            return

        if not active:
            L.log_state(("do-dkg-poll", "inactive-policy", S.ACTIVE_FILE_ID_HEX), True, "File policy is not active.")
            L.set_status("Waiting: policy is inactive", "waiting")
            S.root.after(5000, poll_dkg_for_key)
            return

        active_t = int(policy_t)
        active_n = len(policy_guardians)

        if C.POLICY_DKG_MODE == "ZKDKG_V2":
            if CH.poll_zkdkg_v2_for_key(S.ACTIVE_FILE_ID, S.ACTIVE_FILE_ID_HEX, owner, active_t, active_n):
                _resume_auto_upload_after_key()
                return
            S.root.after(5000, poll_dkg_for_key)
            return

        key_exists, data_owner, _stored_t, _stored_n, _PKx, _PKy, last_epoch = C.dkg.functions.getKeyForFile(
            S.ACTIVE_FILE_ID
        ).call()

        has_req = C.acl.functions.hasRequestedKeyGenForFile(S.ACTIVE_FILE_ID).call()

        if has_req:
            target_epoch = int(last_epoch) + 1 if key_exists else 1

            if not CH.dkg_material_ready(S.ACTIVE_FILE_ID, target_epoch, active_n):
                c_done, s_done, c_req, s_req = CH.dkg_material_progress(S.ACTIVE_FILE_ID, target_epoch, active_n)
                PROG.ensure("Guardian key setup", _GUARDIAN_KEY_PHASES)
                PROG.step("guardian commitments", c_done, c_req)
                PROG.step("guardian shares", s_done, s_req)
                L.set_status(f"Waiting for Guardian DKG material {c_done}/{c_req}", "waiting")
                L.log_state(
                    ("do-dkg-material", S.ACTIVE_FILE_ID_HEX, target_epoch),
                    (c_done, s_done, c_req, s_req),
                    f"Waiting for Guardian DKG material on-chain for epoch={target_epoch}: "
                    f"commitments={c_done}/{c_req}, encryptedShares={s_done}/{s_req}"
                )
                S.root.after(5000, poll_dkg_for_key)
                return

            key_exists2, data_owner2, _t2, _n2, _pkx2, _pky2, last_epoch2 = C.dkg.functions.getKeyForFile(
                S.ACTIVE_FILE_ID
            ).call()

            if not key_exists2 or int(last_epoch2) < target_epoch:
                L.set_status(f"Waiting for DKG finalization epoch {target_epoch}", "waiting")
                L.log_state(
                    ("do-dkg-auto-finalize", S.ACTIVE_FILE_ID_HEX, target_epoch),
                    True,
                    f"DKG material is complete for epoch={target_epoch}. "
                    "Waiting for DKG.sol auto-finalization..."
                )
                S.root.after(5000, poll_dkg_for_key)
                return

            key_exists = key_exists2
            data_owner = data_owner2
            last_epoch = last_epoch2
            target_epoch = int(last_epoch2)

        elif key_exists and int(last_epoch) > 0:
            target_epoch = int(last_epoch)
        else:
            L.log_every(("do-dkg-no-finalized", S.ACTIVE_FILE_ID_HEX), "No finalized DKG epoch yet, checking again...", seconds=30)
            L.set_status("Waiting for finalized DKG epoch...", "waiting")
            S.root.after(5000, poll_dkg_for_key)
            return

        if not CH.dkg_material_ready(S.ACTIVE_FILE_ID, target_epoch, active_n):
            c_done, s_done, c_req, s_req = CH.dkg_material_progress(S.ACTIVE_FILE_ID, target_epoch, active_n)
            PROG.ensure("Guardian key setup", _GUARDIAN_KEY_PHASES)
            PROG.step("guardian commitments", c_done, c_req)
            PROG.step("guardian shares", s_done, s_req)
            L.set_status(f"Waiting for finalized DKG material {c_done}/{c_req}", "waiting")
            L.log_state(
                ("do-dkg-finalized-material", S.ACTIVE_FILE_ID_HEX, target_epoch),
                (c_done, s_done, c_req, s_req),
                f"Waiting for Guardian DKG material on-chain for finalized epoch={target_epoch}: "
                f"commitments={c_done}/{c_req}, encryptedShares={s_done}/{s_req}"
            )
            S.root.after(5000, poll_dkg_for_key)
            return

        pk_data = CH.compute_pk_cache_from_chain(
            S.ACTIVE_FILE_ID_HEX,
            target_epoch,
            owner,
            active_t,
            active_n,
        )

        S.PKX_VALUE = int(pk_data["PKx"])
        S.PKY_VALUE = int(pk_data["PKy"])
        S.LAST_PKX_VALUE = S.PKX_VALUE
        S.LAST_PKY_VALUE = S.PKY_VALUE
        S.KEY_EPOCH = int(pk_data["keyEpoch"])

        R.save_pk_cache(pk_data, write_legacy=True)
        # Only when the key exchange was the whole operation: inside an upload
        # the bar belongs to the upload and has four phases still to run.
        if PROG.running_operation() == "Guardian key setup":
            PROG.finish("Key generated and saved")
        L.set_status("Key generated and saved", "done")

        L.log("=== KeyGen result finalized on-chain ===")
        L.log(f"policyId: {S.ACTIVE_FILE_ID_HEX}")
        L.log(f"dataOwner: {owner}")
        L.log(f"guardian threshold t: {active_t}")
        L.log(f"guardian n: {active_n}")
        L.log(f"PKx: {S.PKX_VALUE}")
        L.log(f"PKy: {S.PKY_VALUE}")
        L.log(f"keyEpoch: {S.KEY_EPOCH}")
        L.log("DKG.sol auto-finalized the epoch. DO did not send a finalize transaction.")
        L.log(f"Saved latest PK to: {R.pk_latest_path(S.ACTIVE_FILE_ID_HEX)}")
        L.log(f"Saved epoch PK to: {R.pk_epoch_path(S.ACTIVE_FILE_ID_HEX, S.KEY_EPOCH)}\n")

        L.show_info("Key Generated", "DKG epoch finalized on-chain and PK saved locally.")
        _resume_auto_upload_after_key()

    except Exception as e:
        L.log_state(("do-dkg-poll-error",), str(e), f"DKG auto-finalizer polling error: {e}")
        L.set_status("DKG polling error; retrying...", "error")
        S.root.after(5000, poll_dkg_for_key)


def run_same_pk_refresh_request():
    """Request V2 same-PK share resharing after DO updates the Guardian policy."""
    if getattr(C, 'DKG_ATTEMPT_PROTOCOL', 0) == 1:
        from .do_dkg_ui import start
        return start('refresh')
    L.log("=== ZKDKG_V2 Same-PK Share Refresh request ===")
    L.set_status("Preparing V2 Same-PK refresh...", "running")

    try:
        if C.POLICY_DKG_MODE != "ZKDKG_V2":
            L.show_error("Same-PK Refresh", "This app is configured for V2-only DKG.")
            L.set_status("Same-PK refresh needs V2", "error")
            return

        if C.coordinator_v2 is None:
            L.show_error("Same-PK Refresh", "ZKDKG_V2 coordinator contract is not configured.")
            L.set_status("Missing V2 coordinator", "error")
            return

        ctx = get_current_file_context()
        if not ctx:
            L.set_status("Refresh needs file context", "error")
            return

        file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx
        S.ACTIVE_FILE_ID = file_id
        S.ACTIVE_FILE_ID_HEX = file_id_hex

        exists, active, owner, policy_t, current_guardians = C.acl.functions.getFilePolicy(file_id).call()
        if not exists or not active:
            L.show_error("Policy error", "Current file policy does not exist or is inactive.")
            L.set_status("Refresh needs active policy", "error")
            return

        (
            key_exists,
            key_finalized,
            data_owner,
            old_t,
            old_n,
            key_epoch,
            active_share_version,
            _pkx,
            _pky,
        ) = C.coordinator_v2.functions.getV2Key(file_id).call()

        if not key_exists or not key_finalized or int(key_epoch) <= 0:
            L.show_error("DKG error", "No finalized ZKDKG_V2 key exists for this file policy. Run Fresh KeyGen first.")
            L.set_status("Run V2 KeyGen before refresh", "error")
            return

        key_epoch = int(key_epoch)
        active_share_version = int(active_share_version)
        old_t = int(old_t)
        old_n = int(old_n)
        S.KEY_EPOCH = key_epoch

        try:
            (
                pending_exists,
                pending_finalized,
                pending_share_version,
                pending_old_share_version,
                pending_old_t,
                pending_old_n,
                pending_new_t,
                pending_new_n,
                _pending_old_guardians,
                _pending_new_guardians,
                _pending_old_participant_indices,
            ) = C.coordinator_v2.functions.getPendingV2Refresh(file_id, key_epoch).call()

            if pending_exists:
                S.ACTIVE_REFRESH_TARGET_VERSION = int(pending_share_version)
                S.ACTIVE_REFRESH_FROM_VERSION = int(pending_old_share_version)

                if active_share_version >= int(pending_share_version):
                    L.log(
                        f"ZKDKG_V2 Same-PK refresh is already finalized on-chain, "
                        f"keyEpoch={key_epoch}, shareVersion={int(pending_share_version)}."
                    )
                    L.set_status("V2 Same-PK refresh already finalized", "done")
                    return

                if pending_finalized:
                    # The legacy coordinator also sets finalized on expiry.
                    # Never reuse that attempt's material or advertise it as
                    # installed merely because its request was closed.
                    L.log("Previous refresh ended without activating its shares. A new isolated attempt is required.")
                    L.set_status("Previous refresh did not complete; recovery required", "waiting")
                    return

                L.log(
                    f"Pending ZKDKG_V2 Same-PK refresh already exists, "
                    f"keyEpoch={key_epoch}, shareVersion={int(pending_share_version)}. "
                    "Waiting for Guardian V2 refresh material..."
                )
                L.set_status("Waiting for pending V2 Same-PK refresh...", "waiting")
                if S.root is not None:
                    S.root.after(1000, poll_same_pk_refresh_finalize)
                return
        except Exception as e:
            raise RuntimeError(
                "ZKDKG_V2 coordinator does not expose getPendingV2Refresh(...). "
                "Deploy the updated ZkDkgCoordinatorV2 before using Same-PK Refresh."
            ) from e

        old_guardians = CH._read_v2_share_version_guardians(
            file_id,
            key_epoch,
            active_share_version,
            old_n,
        )

        if old_t == int(policy_t) and CH._guardian_lists_equal(old_guardians, current_guardians):
            L.log(
                f"No V2 Same-PK refresh needed: active shareVersion={active_share_version} "
                "already matches the current Guardian policy."
            )
            L.show_info("Same-PK Refresh", "No refresh needed. Current policy already matches the active share version.")
            L.set_status("No V2 Same-PK refresh needed", "done")
            return

        current_set = {C.w3.to_checksum_address(g).lower() for g in current_guardians}
        old_participant_indices = []

        for i, g in enumerate(old_guardians, start=1):
            if C.w3.to_checksum_address(g).lower() in current_set:
                old_participant_indices.append(i)

        if len(old_participant_indices) < old_t:
            L.show_error(
                "Refresh impossible",
                f"Not enough old active Guardians remain for same-PK refresh.\n\n"
                f"Required old threshold: {old_t}\n"
                f"Available old participants: {len(old_participant_indices)}"
            )
            L.log("ZKDKG_V2 Same-PK refresh stopped: not enough old participants remain.")
            L.set_status("V2 Same-PK refresh impossible", "error")
            return

        S.ACTIVE_REFRESH_FROM_VERSION = active_share_version
        S.ACTIVE_REFRESH_TARGET_VERSION = active_share_version + 1

        L.log(f"policyId: {file_id_hex}")
        L.log(f"keyEpoch: {key_epoch}")
        L.log(f"old active shareVersion: {active_share_version}")
        L.log(f"target shareVersion: {S.ACTIVE_REFRESH_TARGET_VERSION}")
        L.log(f"old threshold: {old_t}")
        L.log(f"new threshold: {int(policy_t)}")
        L.log(f"old participant indices: {old_participant_indices}")
        L.log(f"new guardians: {len(current_guardians)}")

        fn = C.coordinator_v2.functions.requestV2SamePkShareRefresh(
            file_id,
            key_epoch,
            old_participant_indices,
        )
        L.set_status("Submitting V2 Same-PK refresh request...", "running")
        CH.send_signed_tx(fn, C.DO_ACCOUNT, "ZKDKG_V2 Same-PK share refresh requested")

        L.set_status("V2 Same-PK refresh requested; waiting for Guardians...", "waiting")
        if S.root is not None:
            S.root.after(1000, poll_same_pk_refresh_finalize)

    except Exception as e:
        L.show_error("Same-PK refresh error", str(e))
        L.log(f"ZKDKG_V2 Same-PK refresh error: {e}")
        L.set_status("V2 Same-PK refresh error", "error")


def poll_same_pk_refresh_finalize():
    if getattr(C, 'DKG_ATTEMPT_PROTOCOL', 0) == 1:
        from .do_dkg_ui import start_reconciler
        return start_reconciler()
    try:
        if C.coordinator_v2 is None:
            L.log_state(("do-v2-refresh-poll", "no-coordinator"), True, "ZKDKG_V2 coordinator is not configured.")
            L.set_status("Missing V2 coordinator", "error")
            return

        if S.ACTIVE_FILE_ID is None:
            ctx = get_current_file_context(show_errors=False)
            if not ctx:
                L.log_state(("do-v2-refresh-poll", "no-active-file"), True, "No active policyId for V2 Same-PK refresh polling.")
                L.set_status("Refresh waiting for file context", "waiting")
                return
            S.ACTIVE_FILE_ID, S.ACTIVE_FILE_ID_HEX, _do_input, _policy_name, _data_tag, _date_str, _ts = ctx

        (
            key_exists,
            key_finalized,
            _data_owner,
            _stored_t,
            _stored_n,
            key_epoch_chain,
            active_share_version,
            _pkx,
            _pky,
        ) = C.coordinator_v2.functions.getV2Key(S.ACTIVE_FILE_ID).call()

        if not key_exists or not key_finalized or int(key_epoch_chain) <= 0:
            L.log_state(("do-v2-refresh-poll", "no-v2-key", S.ACTIVE_FILE_ID_HEX), True, "No finalized ZKDKG_V2 key for same-PK refresh status check.")
            L.set_status("Refresh waiting for V2 key", "waiting")
            return

        key_epoch = int(S.KEY_EPOCH or key_epoch_chain)
        active_share_version = int(active_share_version)
        target_version = int(S.ACTIVE_REFRESH_TARGET_VERSION or 0)

        (
            refresh_exists,
            refresh_finalized,
            share_version,
            old_share_version,
            old_t,
            old_n,
            new_t,
            new_n,
            old_guardians,
            new_guardians,
            old_participant_indices,
        ) = C.coordinator_v2.functions.getPendingV2Refresh(S.ACTIVE_FILE_ID, key_epoch).call()

        if not refresh_exists:
            if target_version > 0 and active_share_version >= target_version:
                L.log("=== ZKDKG_V2 Same-PK Share Refresh finalized on-chain ===")
                L.log(f"policyId: {S.ACTIVE_FILE_ID_HEX}")
                L.log(f"keyEpoch: {key_epoch}")
                L.log(f"active shareVersion: {active_share_version}")
                L.log("ZkDkgCoordinatorV2 finalized the refresh. DO did not send a finalize transaction.\n")
                S.ACTIVE_REFRESH_TARGET_VERSION = None
                S.ACTIVE_REFRESH_FROM_VERSION = None
                L.set_status("V2 Same-PK refresh finalized", "done")
                L.show_info("Same-PK Refresh", "Share refresh finalized on-chain. The public key is unchanged.")
                return

            L.log_state(
                ("do-v2-refresh-poll", "no-pending", S.ACTIVE_FILE_ID_HEX, key_epoch),
                active_share_version,
                "No pending ZKDKG_V2 same-PK refresh found. No refresh finalization is currently required."
            )
            L.set_status("No pending V2 Same-PK refresh", "ready")
            return

        share_version = int(share_version)

        if active_share_version >= share_version:
            L.log("=== ZKDKG_V2 Same-PK Share Refresh finalized on-chain ===")
            L.log(f"policyId: {S.ACTIVE_FILE_ID_HEX}")
            L.log(f"keyEpoch: {key_epoch}")
            L.log(f"active shareVersion: {active_share_version}")
            L.log(f"target shareVersion: {share_version}")
            L.log(f"new guardian threshold: {int(new_t)}")
            L.log(f"new guardian count: {int(new_n)}")
            L.log("ZkDkgCoordinatorV2 finalized the refresh. DO did not send a finalize transaction.\n")
            S.ACTIVE_REFRESH_TARGET_VERSION = None
            S.ACTIVE_REFRESH_FROM_VERSION = None
            L.set_status("V2 Same-PK refresh finalized", "done")
            L.show_info("Same-PK Refresh", "Share refresh finalized on-chain. The public key is unchanged.")
            return

        if refresh_finalized:
            S.ACTIVE_REFRESH_TARGET_VERSION = None
            S.ACTIVE_REFRESH_FROM_VERSION = None
            L.log("Refresh request closed without activating new shares; the previous share version remains active.")
            L.set_status("Refresh ended without new shares; check settlement", "waiting")
            return

        try:
            (
                commitment_count,
                encrypted_share_count,
                required_commitments,
                required_encrypted_shares,
                _finalized,
            ) = C.coordinator_v2.functions.getV2RefreshProgress(S.ACTIVE_FILE_ID, key_epoch, share_version).call()

            L.log_state(
                ("do-v2-refresh-progress", S.ACTIVE_FILE_ID_HEX, key_epoch, share_version),
                (int(commitment_count), int(encrypted_share_count), int(required_commitments), int(required_encrypted_shares)),
                f"Waiting for ZKDKG_V2 refresh finalization, keyEpoch={key_epoch}, "
                f"shareVersion={share_version}... "
                f"commitments={int(commitment_count)}/{int(required_commitments)}, "
                f"encryptedShares={int(encrypted_share_count)}/{int(required_encrypted_shares)}"
            )
            L.set_status(
                f"Waiting for V2 refresh material {int(commitment_count)}/{int(required_commitments)}",
                "waiting",
            )
        except Exception:
            L.log_every(
                ("do-v2-refresh-progress-fallback", S.ACTIVE_FILE_ID_HEX, key_epoch, share_version),
                f"Waiting for ZKDKG_V2 refresh finalization, keyEpoch={key_epoch}, shareVersion={share_version}...",
                seconds=30,
            )
            L.set_status("Waiting for V2 Same-PK refresh finalization...", "waiting")

        try:
            requested_at = int(C.coordinator_v2.functions.getRefreshRequestedAt(S.ACTIVE_FILE_ID, key_epoch).call())
            deadline = int(C.coordinator_v2.functions.dkgKeyGenDeadline().call())
            chain_now = CH.latest_chain_timestamp()
            if requested_at > 0 and chain_now > requested_at + deadline:
                if CH.settle_v2_refresh_onchain(S.ACTIVE_FILE_ID, S.ACTIVE_FILE_ID_HEX, key_epoch, share_version):
                    S.ACTIVE_REFRESH_TARGET_VERSION = None
                    S.ACTIVE_REFRESH_FROM_VERSION = None
                    L.set_status("V2 refresh settled — escrow refunded, retry when ready", "waiting")
                    return
        except Exception as exc:
            L.log_state(("do-v2-refresh-deadline-check-error",), str(exc), f"Could not check refresh deadline: {exc}")

        if S.root is not None:
            S.root.after(5000, poll_same_pk_refresh_finalize)

    except Exception as e:
        L.log_state(("do-v2-refresh-poll-error",), str(e), f"ZKDKG_V2 Same-PK refresh status check error: {e}")
        L.set_status("V2 Same-PK refresh polling error; retrying...", "error")
        if S.root is not None:
            S.root.after(5000, poll_same_pk_refresh_finalize)


def run_all():
    success = False
    try:
        # include_requester_entry: this is what the Save Setup button added over
        # the automatic save -- a requester typed into the box but never Added.
        # With the button gone, an upload has to carry it, or that address is
        # silently dropped at the moment it matters.
        save_latest_upload_settings(include_requester_entry=True)
        success = bool(_run_all_impl())
        return success
    finally:
        # Close the bar on the way out whatever happened, so a failed upload
        # leaves it stopped where it stopped rather than running for ever.
        if PROG.is_running():
            if success:
                PROG.step("registered on chain", 1, 1)
                PROG.finish("Upload complete")
            else:
                PROG.finish("Upload did not finish", ok=False)
        if S.drop_folder_current_item and not S.auto_upload_pending:
            _finish_drop_folder_upload(success)


def _run_all_impl():
    # Weighted by effort, not by step count: waiting for five guardians is the
    # long pole, and storing pieces is the second. A bar that gave each step an
    # equal share would race to 75% and then appear to hang.
    PROG.start("Uploading", [
        ("guardian commitments", 0.20),
        ("guardian shares", 0.15),
        ("keepers chosen", 0.10),
        ("pieces stored", 0.40),
        ("registered on chain", 0.15),
    ])
    L.set_status("Checking upload pre-conditions...", "running")

    file_path = S.selected_file_var.get().strip() if S.selected_file_var else ""
    if not file_path or file_path == "No file selected":
        L.show_error(
            "Step 1 — No file selected",
            "Please select a file using the 'Select File…' button in the Dashboard tab.",
        )
        L.set_status("Select a file first", "error")
        return

    ctx = get_current_file_context()
    if not ctx:
        L.set_status("Fill in Policy Name, Data Tag, and Date", "error")
        return

    file_id, file_id_hex, do_input, policy_name, data_tag, date_str, ts = ctx
    S.ACTIVE_FILE_ID = file_id
    S.ACTIVE_FILE_ID_HEX = file_id_hex

    if _auto_select_enabled():
        if not _auto_prepare_for_upload(file_id, file_id_hex, policy_name):
            return
    auto_quiet_started = bool(getattr(S, "auto_quiet_info", False))

    try:
        int(S.entry_n.get())
        int(S.entry_t.get())
    except ValueError:
        S.auto_quiet_info = False
        L.show_error(
            "Step 3 — Invalid IDA parameters",
            "IDA Pieces (n) and IDA Threshold (t) must be integers.\n"
            "Set them in the Dashboard tab.",
        )
        L.set_status("Fix IDA n / t in Dashboard", "error")
        return

    try:
        exists, active, _, _, guardians = C.acl.functions.getFilePolicy(file_id).call()
    except Exception as e:
        S.auto_quiet_info = False
        L.show_error("Policy check error", str(e))
        L.log(f"ERROR checking file policy: {e}")
        L.set_status("Policy check error", "error")
        return

    if not exists:
        S.auto_quiet_info = False
        L.show_error(
            "Step 4 — No policy created",
            f"No on-chain policy found for '{policy_name}'.\n\n"
            "Go to the Guardians tab:\n"
            "  1. Select Guardians from the table\n"
            "  2. Click 'Create / Update Policy'",
        )
        L.set_status("Create policy in Guardians tab", "error")
        return

    if len(guardians) == 0:
        S.auto_quiet_info = False
        L.show_error(
            "Step 5 — No Guardians in policy",
            f"Policy '{policy_name}' has no Guardians.\n\n"
            "Go to the Guardians tab, select Guardians, and click 'Add Selected'.",
        )
        L.set_status("Add Guardians in Guardians tab", "error")
        return

    if not active:
        S.auto_quiet_info = False
        L.show_error(
            "Step 5 — Policy is inactive",
            f"Policy '{policy_name}' is inactive.\n\n"
            "Go to the Guardians tab and click 'Activate'.",
        )
        L.set_status("Activate policy in Guardians tab", "error")
        return

    try:
        has_key = CH.load_pk_json(expected_file_id_hex=file_id_hex)
    except Exception:
        has_key = False

    if not has_key or S.PKX_VALUE is None or S.PKY_VALUE is None:
        S.auto_quiet_info = False
        L.show_error(
            "Step 6 — No encryption key (Key Gen needed)",
            f"No DKG public key found for policy '{policy_name}'.\n\n"
            "Go to the Guardians tab and click 'Key Gen', then wait for\n"
            "Guardians to complete the DKG protocol.",
        )
        L.log("ERROR: no DKG key found locally or on-chain. Run Key Gen first.")
        L.set_status("Run Key Gen in Guardians tab", "error")
        return

    L.log(f"Loaded PK (epoch={S.KEY_EPOCH}) for current policyId.")

    peers = N.get_selected_vk_peers()
    if not peers:
        S.auto_quiet_info = False
        L.show_error(
            "Step 7 — No Vault Keepers selected",
            "No Vault Keepers are assigned to this upload.\n\n"
            "Go to the Vault Keepers tab:\n"
            "  1. Select VKs from the table\n"
            "  2. Click 'Use for Upload' to confirm",
        )
        L.set_status("Select Vault Keepers first", "error")
        return

    if CH.batch_exists_onchain(data_tag, date_str):
        if S.drop_folder_current_item:
            _save_drop_existing_batch_record(
                S.drop_folder_current_item,
                ctx,
                "batch already exists on-chain",
            )
        S.auto_quiet_info = False
        L.set_status("Batch already exists on-chain", "waiting")
        return

    L.log("All checks passed. Running: Disperse → Upload VaultMesh → Upload encrypted payloads\n")
    L.set_status("Checks passed; starting upload...", "running")

    if not run_disperse():
        if auto_quiet_started:
            S.auto_quiet_info = False
        return

    if not run_upload_vaultmesh():
        if auto_quiet_started:
            S.auto_quiet_info = False
        return

    return bool(run_upload_cids())


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b} {unit}" if unit == "B" else f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def refresh_pieces_list():
    """Fill every pieces view there is: the dashboard's, and the pop-out window."""
    trees = [
        t for t in (S.pieces_listbox, getattr(S, "pieces_window_tree", None))
        if t is not None
    ]
    if not trees:
        return

    # Read the directory once, then paint it everywhere, rather than walking the
    # disk again for each view that happens to be open.
    if not os.path.isdir(C.PIECES_DIR):
        rows = [("", "[pieces/ not found]", "")]
    else:
        files = sorted(
            f for f in os.listdir(C.PIECES_DIR)
            if os.path.isfile(os.path.join(C.PIECES_DIR, f))
        )
        rows = [
            (f, f, _fmt_size(os.path.getsize(os.path.join(C.PIECES_DIR, f))))
            for f in files
        ] or [("", "[no files]", "")]

    for tree in trees:
        try:
            for iid in tree.get_children():
                tree.delete(iid)
            for iid, name, size in rows:
                if iid:
                    tree.insert("", tk.END, iid=iid, values=(name, size))
                else:
                    tree.insert("", tk.END, values=(name, size))
        except Exception:
            # A window can close between the check above and this line; the
            # other views still have to be filled.
            continue


def open_piece_directory():
    """Open the pieces directory in the OS file manager (cross-platform)."""
    import subprocess, sys
    path = C.PIECES_DIR
    if not os.path.isdir(path):
        return
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as exc:
        L.log(f"Could not open directory: {exc}")


def init_pk_from_file():
    pk_json_path = R.pk_any_latest_path()

    if not pk_json_path:
        L.log("No PK file found, request key generation first.")
        return

    try:
        CH.load_pk_json()
        L.log(f"Loaded PK (epoch={S.KEY_EPOCH}) from {pk_json_path}")
        if S.ACTIVE_FILE_ID_HEX:
            L.log(f"PK policyId: {S.ACTIVE_FILE_ID_HEX}")
    except Exception as e:
        L.log(f"Failed to load PK JSON: {e}")


def delete_all_pieces():
    if not os.path.isdir(C.PIECES_DIR):
        L.show_error("Error", f"Directory not found: {C.PIECES_DIR}")
        return

    for name in os.listdir(C.PIECES_DIR):
        path = os.path.join(C.PIECES_DIR, name)
        if os.path.isfile(path):
            os.remove(path)

    refresh_pieces_list()
    L.log("All piece files deleted.")


def clear_output():
    if S.result_text is not None:
        S.result_text.delete("1.0", tk.END)


def reset_inputs():
    S.entry_n.delete(0, tk.END)
    S.entry_n.insert(0, "6")

    S.entry_t.delete(0, tk.END)
    S.entry_t.insert(0, "4")

    if S.entry_guardian_n is not None:
        S.entry_guardian_n.delete(0, tk.END)
        S.entry_guardian_n.insert(0, "5")

    if S.entry_guardian_t is not None:
        S.entry_guardian_t.delete(0, tk.END)
        S.entry_guardian_t.insert(0, "3")

    if S.entry_service_days is not None:
        S.entry_service_days.delete(0, tk.END)
        S.entry_service_days.insert(0, "30")

    S.entry_device_id.delete(0, tk.END)
    S.entry_device_id.insert(0, new_data_tag())

    S.chk_var.set(False)
    S.selected_file_var.set("")
    S.selected_datetime_var.set(datetime.date.today().strftime("%Y-%m-%d"))

    N.clear_guardian_selection()
    N.clear_vault_keeper_selection()
    N.clear_policy_vks()
    S.staged_guardians = []
    _update_staged_g_status()
    refresh_pieces_list()
    refresh_file_id_preview()
    N.set_policy_status_text("Policy: not loaded")


def exit_app():
    try:
        from . import do_tray as T

        T.stop_tray_icon()
    except Exception:
        pass
    S.root.destroy()


def _policy_name_values() -> list:
    recs = R.load_policies_record()
    names = [rec.get("policyName", key) for key, rec in recs.items()]
    if not names or "Policy01" not in names:
        names = ["Policy01"] + [n for n in names if n != "Policy01"]
    return names


def _own_policy_ids(page_size: int = 200) -> list:
    """The file ids this Data Owner created, read as current state.

    This is the path a Data Owner takes to recover what it owns after losing its
    local records, or after being offline long enough for them to be incomplete.
    It has to work on a chain that is years old, so it cannot be a replay: the
    contract keeps a per-owner list, and this walks it in pages.

    Falls back to replaying creation events for a deployment predating the list.
    """
    if hasattr(C.acl.functions, "getOwnerPolicyPage"):
        ids = []
        offset = 0
        while True:
            page = C.acl.functions.getOwnerPolicyPage(C.DO, offset, page_size).call()
            if not page:
                break
            ids.extend(page)
            offset += len(page)
            if len(page) < page_size:
                break
        return ids

    L.log("[sync] registry predates the owner index; falling back to replaying events")
    return [
        evt["args"]["fileId"]
        for evt in _collect_logs_windowed(C.acl.events.FilePolicyCreated, {"dataOwner": C.DO})
    ]


def sync_policies_from_chain(silent: bool = False) -> int:
    """Recover this DO's file policies from the chain and merge into policies.json."""
    try:
        file_ids = _own_policy_ids()
    except Exception as e:
        if not silent:
            S.root.after(0, lambda: L.log(f"Chain sync error: {e}"))
        return 0

    recs = R.load_policies_record()
    known_ids = {
        HX.strip_hex_prefix(rec.get("policyId", "")).lower()
        for rec in recs.values()
    }

    added = 0
    for file_id_bytes in file_ids:
        if isinstance(file_id_bytes, str):
            file_id_bytes = HX.hex_to_bytes(file_id_bytes, expected_bytes=32, field="fileId")
        file_id_hex = file_id_bytes.hex()
        if file_id_hex.lower() in known_ids:
            continue
        try:
            exists, active, owner, threshold, guardians = C.acl.functions.getFilePolicy(
                file_id_bytes
            ).call()
            key = f"onchain_{file_id_hex[:16]}"
            recs[key] = {
                "policyName": f"0x{file_id_hex[:14]}...",
                "policyId": f"0x{file_id_hex}",
                "guardians": [C.w3.to_checksum_address(g) for g in guardians],
                "threshold": int(threshold),
                "created": "on-chain",
                "updated": "on-chain",
                "files": [],
                "requesters": [],
            }
            known_ids.add(file_id_hex.lower())
            added += 1
        except Exception:
            pass

    if added > 0:
        Path(R.policies_record_path()).write_text(json.dumps(recs, indent=2), encoding="utf-8")

    return added


def start_pending_dkg_reconciler() -> None:
    """Continuously finish or settle DKG requests after UI restarts/outages."""
    if getattr(C, 'DKG_ATTEMPT_PROTOCOL', 0) == 1:
        from .do_dkg_ui import start_reconciler
        return start_reconciler()
    global _PENDING_DKG_RECONCILE_JOB
    if S.root is None or _PENDING_DKG_RECONCILE_JOB is not None:
        return

    def schedule_next(delay_ms: int = 30_000) -> None:
        global _PENDING_DKG_RECONCILE_JOB
        if S.root is not None:
            _PENDING_DKG_RECONCILE_JOB = S.root.after(delay_ms, poll)

    def finish(results: list[dict] | None, error: Exception | None) -> None:
        global _PENDING_DKG_RECONCILE_RUNNING
        _PENDING_DKG_RECONCILE_RUNNING = False
        if error is not None:
            L.log_every(
                ("pending-dkg-reconcile-error",),
                f"[DKG recovery] blockchain unavailable or reconciliation failed; "
                f"pending state was preserved: {error}",
                seconds=60,
            )
        else:
            for result in results or []:
                state = str(result.get("state", ""))
                fid = str(result.get("file_id_hex", ""))
                detail = str(result.get("error", "") or "")
                L.log_state(
                    ("pending-dkg-reconcile", fid),
                    (state, detail),
                    f"[DKG recovery] {fid[:18]}... state={state}"
                    + (f" error={detail}" if detail else ""),
                )
        schedule_next()

    def worker() -> None:
        try:
            active_hex = str(S.ACTIVE_FILE_ID_HEX or "")
            results = CH.reconcile_known_v2_dkg_requests(
                skip_file_id_hex=active_hex
            )
            error = None
        except Exception as exc:
            results = None
            error = exc
        if S.root is not None:
            S.root.after(0, lambda: finish(results, error))

    def poll() -> None:
        global _PENDING_DKG_RECONCILE_JOB, _PENDING_DKG_RECONCILE_RUNNING
        _PENDING_DKG_RECONCILE_JOB = None
        if _PENDING_DKG_RECONCILE_RUNNING:
            schedule_next()
            return
        _PENDING_DKG_RECONCILE_RUNNING = True
        threading.Thread(target=worker, daemon=True).start()

    schedule_next(1_000)


def _bg_sync_policies(show_log: bool = False):
    try:
        if show_log:
            S.root.after(0, lambda: L.log("Syncing policies from chain..."))
        added = sync_policies_from_chain(silent=not show_log)
        # Then put back any upload this computer finished but did not file --
        # free, local, and the common case after a crash or a bad record.
        listed = 0
        try:
            from . import do_recovery as RECOVER

            rebuilt = RECOVER.rebuild_from_local_jobs()
            # And list every upload each policy has on chain. The data tag,
            # the date and the piece count are public, so a policy's files
            # can be shown for nothing; only opening their addresses costs.
            for record in R.load_policies_record().values():
                policy_id = str(record.get("policyId", "") or "")
                if not policy_id:
                    continue
                try:
                    listed += RECOVER.record_policy_files(policy_id)
                except Exception as exc:
                    L.log(f"Could not list files of {policy_id[:14]}...: {exc}")
        except Exception as exc:
            rebuilt = 0
            L.log(f"Local rebuild skipped: {exc}")
        if listed and show_log:
            S.root.after(0, lambda: L.log(
                f"Found {listed} file(s) of your policies on chain. Select one "
                f"and press Recover to get its pieces and keepers."
            ))
        if rebuilt and show_log:
            S.root.after(0, lambda: L.log(
                f"Rebuilt {rebuilt} file(s) from this computer's upload records."
            ))
        S.root.after(0, load_policies_browser)
        if show_log:
            msg = (f"Chain sync: {added} new policy(ies) added." if added > 0
                   else "Chain sync: no new policies found on chain.")
            S.root.after(0, lambda: L.log(msg))
            S.root.after(0, lambda: L.set_status("Chain sync done", "done"))
    finally:
        S._chain_sync_running = False


def run_sync_policies_from_chain():
    """Button handler — always runs a visible sync from chain in a background thread."""
    if S._chain_sync_running:
        L.log("Chain sync already in progress...")
        return
    S._chain_sync_running = True
    L.set_status("Syncing policies from chain...", "running")
    threading.Thread(target=lambda: _bg_sync_policies(show_log=True), daemon=True).start()


def load_policies_browser():
    if S.policies_tree is None:
        return
    if S.entry_policy_name is not None and hasattr(S.entry_policy_name, "configure"):
        S.entry_policy_name.configure(values=_policy_name_values())
    for iid in S.policies_tree.get_children():
        S.policies_tree.delete(iid)
    recs = R.load_policies_record()
    if not recs and not S._chain_sync_running:
        S._chain_sync_running = True
        threading.Thread(target=lambda: _bg_sync_policies(show_log=False), daemon=True).start()
    for key, rec in recs.items():
        fid = rec.get("policyId", "")
        S.policies_tree.insert("", tk.END, iid=key, values=(
            rec.get("policyName", key),
            (fid[:18] + "...") if len(fid) > 18 else fid,
            len(rec.get("guardians", [])),
            len(rec.get("files", [])),
            rec.get("created", ""),
        ))


def _selected_policy_id() -> str:
    """The policyId of the row chosen in the policy browser, or ""."""
    if S.policies_tree is None:
        return ""
    selection = S.policies_tree.selection()
    if not selection:
        return ""
    record = R.load_policies_record().get(selection[0]) or {}
    return str(record.get("policyId", "") or "")


def recover_selected_policy_file() -> None:
    """Rebuild one policy's pieces and keepers from the network.

    For the install that arrives with nothing: a key, a list of policies read
    from the chain, and no idea which keeper holds what. The guardians can
    open that, because it is their own job for a requester, and the owner is
    allowed to ask about its own file.

    Confirmed first, with the price named, because it spends money -- and run
    off the window thread, because the guardians answer when they answer.
    """
    policy_id = _selected_policy_id()
    if not policy_id:
        L.show_error(
            "Recover from network",
            "Select a policy in the browser first, then press Recover.",
        )
        return

    # Which file inside it. A policy holds many, each costing its own fee, so
    # recovering "the policy" would spend money on files nobody asked for.
    upload_id = str(S.selected_upload_instance_id or "")
    if not upload_id:
        rows = (S.policy_files_tree.get_children()
                if S.policy_files_tree is not None else ())
        if len(rows) == 1:
            upload_id = str(rows[0])
        elif rows:
            L.show_error(
                "Recover from network",
                "This policy has more than one file. Select the one to "
                "recover -- each is a separate request to the guardians, and "
                "each is charged.",
            )
            return
        else:
            L.show_error(
                "Recover from network",
                "No files are listed for this policy yet. Press Sync from "
                "Chain first: it lists them for free, then pick one.",
            )
            return

    from . import do_recovery as RECOVER

    try:
        if not RECOVER.owns_file(policy_id):
            L.show_error(
                "Recover from network",
                "This account does not own that policy, so its key cannot be "
                "recovered here.",
            )
            return
    except Exception as exc:
        L.show_error("Recover from network", f"The chain could not be read: {exc}")
        return

    if not messagebox.askyesno(
        "Recover from network",
        "Rebuild this policy's files, pieces and keepers from the network?\n\n"
        "The guardians are asked for your own file's key, which costs the "
        "usual access fee, and it can take a minute while they answer.\n\n"
        "Nothing already in this app is overwritten.",
    ):
        return

    def report(text: str) -> None:
        if S.root is not None:
            S.root.after(0, lambda: L.set_status(f"Recovery: {text}", "running"))

    def work() -> None:
        try:
            entry = RECOVER.recover_file(policy_id, on_step=report,
                                         upload_id=upload_id)
        except Exception as exc:          # recovery, chain, network, anything
            # Bound to a plain name first: `exc` is unbound once the except
            # block ends, so a lambda that closes over it raises NameError at
            # the moment it runs -- which replaces the real message with a
            # misleading one, exactly when the user needs the real one.
            message = str(exc)
            if not isinstance(exc, RECOVER.RecoveryError):
                L.log(f"[Recovery] unexpected failure: {message}")
                message = f"Recovery stopped: {message}"
            if S.root is not None:
                S.root.after(0, lambda: L.set_status("Recovery failed", "error"))
                S.root.after(0, lambda: L.show_error("Recover from network", message))
            return

        count = len(entry.get("pieces", []))

        def finish() -> None:
            L.set_status("Recovery done", "done")
            load_policies_browser()
            # Reloading the browser clears every selection, and the pieces are
            # only shown for a selected file -- so a finished recovery left
            # all three tables blank. Put the user back where they were.
            _reselect_policy_file(policy_id, str(entry.get("uploadInstanceId", "")))
            L.show_info(
                "Recover from network",
                f"Recovered {count} piece(s) for data tag "
                f"{entry.get('dataTag', '')}.\n\n"
                "Their keepers are listed now. Ask each keeper for its signed "
                "receipt before disputing one.",
            )

        if S.root is not None:
            S.root.after(0, finish)

    L.set_status("Recovery: starting", "running")
    threading.Thread(target=work, daemon=True, name="policy-recovery").start()


def repair_recovered_pieces_once() -> None:
    """Finish what an older recovery left half-written, at startup.

    Local, and nothing to do with the chain -- which is why it does not sit
    behind Sync from Chain, where it was before. It reads this app's own
    piece records and works the missing parts out from the account key.
    """
    def work() -> None:
        try:
            from . import do_recovery as RECOVER

            RECOVER.repair_recovered_pieces()
        except Exception as exc:
            L.log(f"[Recovery] piece records could not be checked: {exc}")

    threading.Thread(target=work, daemon=True, name="recovery-repair").start()


def retry_unsent_admission_disputes_once() -> None:
    """Send again, at startup, the admission complaints that never went out.

    On a thread because it talks to the chain, and the window must not wait
    on an RPC that may be the very thing that was down when these were
    written.
    """
    def work() -> None:
        try:
            sent = VM.retry_unsent_admission_disputes()
            if sent:
                L.set_status(f"Sent {sent} admission complaint(s) that were waiting", "ok")
        except Exception as exc:
            L.log(f"[admission] waiting complaints could not be checked: {exc}")

    threading.Thread(target=work, daemon=True, name="admission-retry").start()


def _reselect_policy_file(policy_id: str, upload_id: str) -> None:
    """Select a policy and one of its files again, as a click would."""
    if S.policies_tree is None:
        return
    wanted = str(policy_id or "").strip().lower()
    records = R.load_policies_record()
    for key, record in records.items():
        if str(record.get("policyId", "")).strip().lower() != wanted:
            continue
        if key not in S.policies_tree.get_children():
            continue
        S.policies_tree.selection_set(key)
        S.policies_tree.see(key)
        show_policy_detail()
        break
    if (upload_id and S.policy_files_tree is not None
            and upload_id in S.policy_files_tree.get_children()):
        S.policy_files_tree.selection_set(upload_id)
        S.policy_files_tree.see(upload_id)
        on_policy_file_selected()


def refresh_policies_tab() -> None:
    """Reload everything the Policies tab shows, from one button."""
    load_policies_browser()
    load_stored_pieces_list()


def show_policy_detail(event=None):
    if S.policies_tree is None or S.policy_detail_text is None:
        return
    sel = S.policies_tree.selection()
    if not sel:
        return
    iid = sel[0]
    recs = R.load_policies_record()
    rec = recs.get(iid)
    if not rec:
        return

    lines = []
    lines.append(f"Policy : {rec.get('policyName', iid)}")
    lines.append(f"PolicyId: {rec.get('policyId', '')}")
    lines.append(f"Created: {rec.get('created', '')}   Updated: {rec.get('updated', '')}")
    lines.append(f"Guardian Threshold: {rec.get('threshold', '')}")
    lines.append("")
    gs = rec.get("guardians", [])
    lines.append(f"Guardians ({len(gs)}):")
    for g in gs:
        lines.append(f"  {g}")
    lines.append("")
    reqs = rec.get("requesters", [])
    lines.append(f"Requesters ({len(reqs)}):")
    for r in reqs:
        lines.append(f"  {r}")
    lines.append("")
    files = rec.get("files", [])
    lines.append(f"Uploaded Files: {len(files)}  (listed below)")

    S.policy_detail_text.configure(state="normal")
    S.policy_detail_text.delete("1.0", tk.END)
    S.policy_detail_text.insert("1.0", "\n".join(lines))
    S.policy_detail_text.configure(state="disabled")

    _fill_policy_files_list(files)


def _fill_policy_files_list(files: list) -> None:
    """List the files of the selected policy, one row each.

    Keyed by uploadInstanceId because that is what the piece journal records
    against every piece, so a row here maps exactly onto the pieces it produced
    -- which is what the pieces table filters by and what a file-level delete
    has to act on.
    """
    if S.policy_files_tree is None:
        return
    for iid in S.policy_files_tree.get_children():
        S.policy_files_tree.delete(iid)
    S.selected_upload_instance_id = None

    for entry in files:
        upload_id = str(entry.get("uploadInstanceId", "") or "")
        if not upload_id:
            continue
        pieces = entry.get("pieces", []) or []
        keepers = {str(p.get("vkAddress", "") or "") for p in pieces}
        keepers.discard("")
        S.policy_files_tree.insert("", "end", iid=upload_id, values=(
            entry.get("dataTag", ""),
            entry.get("date", ""),
            str(entry.get("uploaded", ""))[:19],
            len(pieces),
            len(keepers),
        ))

    # Nothing selected yet, so the pieces table empties: a new policy's files
    # are listed, and the pieces appear once one of them is chosen.
    load_stored_pieces_list()


def on_policy_file_selected(event=None) -> None:
    """Narrow the pieces table to the file just selected."""
    if S.policy_files_tree is None:
        return
    sel = S.policy_files_tree.selection()
    S.selected_upload_instance_id = sel[0] if sel else None
    load_stored_pieces_list()


def load_stored_pieces_list() -> None:
    """Populate Stored VK Pieces from the authoritative lifecycle journal.

    Shows the pieces of the file selected above, and nothing until a file is
    selected: policy -> file -> pieces. A table listing every piece this owner
    ever stored is not the thing the delete button next to it acts on.

    This runs on the UI thread and never touches the chain. Every row is read
    from the journal, which is local. It used to ask the chain about each
    piece with a deletion in flight, which is one round trip per piece: six
    pieces of a file whose delete had failed meant six of them on every click
    on the policy, and the window froze each time. The background monitor
    does that work, and refreshes this table when it learns anything.
    """
    if S.stored_pieces_tree is None:
        return
    for iid in S.stored_pieces_tree.get_children():
        S.stored_pieces_tree.delete(iid)

    manifest_path, manifest, pieces = _load_stored_piece_manifest()
    if manifest is None:
        return
    visible = {id(p) for p in _pieces_for_selected_file(pieces, require_selection=True)}

    for p in pieces:
        if _piece_marked_deleted(p):
            continue
        if id(p) not in visible:
            continue

        receipt = p.get("privateReceipt") or {}
        piece_root = str(p.get("pieceRoot", ""))
        commitment_hash = str(p.get("commitmentHash", "") or receipt.get("commitmentHash", ""))
        vk_peer = str(p.get("peerId", "") or p.get("vkPeer", "") or p.get("resolvedMultiaddr", ""))
        se = int(p.get("serviceEnd", 0) or receipt.get("serviceEnd", 0) or 0)
        try:
            se_str = datetime.datetime.fromtimestamp(se).astimezone().strftime("%Y-%m-%d")
        except Exception:
            se_str = str(se)
        idx = str(int(p.get("pieceIndex", 0)))
        row_id = str(commitment_hash or piece_root)
        S.stored_pieces_tree.insert("", "end", iid=row_id, values=(
            idx,
            piece_root[:24] + "..." if len(piece_root) > 27 else piece_root,
            vk_peer[:24] + "..." if len(vk_peer) > 27 else vk_peer,
            se_str,
            commitment_hash[:24] + "..." if len(commitment_hash) > 27 else commitment_hash,
        ))
    # Startup/UI refresh reconstructs the monitor from the durable journal.
    _schedule_pending_deletion_reconciliation()
    _close_finished_deletion_progress()


def _close_finished_deletion_progress() -> None:
    """Never leave a deletion bar running when no deletion is outstanding.

    The journal is the authority on whether a deletion is still in flight, so
    it also decides when the bar stops -- otherwise one missed hand-off leaves
    "waiting for the chain" on screen for ever over work that finished.
    """
    if not PROG.running_operation().startswith("Deleting"):
        return
    try:
        if PJ.unresolved_deletions(C.BASE_DIR):
            return
    except Exception:
        return
    PROG.finish("all deletions confirmed on-chain")

def _pieces_for_selected_file(pieces: list, require_selection: bool = False) -> list:
    """Only the pieces of the file selected in the policy detail, if any.

    With *require_selection*, no file selected means no pieces, rather than
    every piece.
    """
    upload_id = str(S.selected_upload_instance_id or "")
    if not upload_id:
        return [] if require_selection else pieces
    return [
        p for p in pieces
        if str(p.get("uploadInstanceId", "") or "") == upload_id
    ]


def _load_stored_piece_manifest() -> tuple[str, dict | list | None, list]:
    manifest = PJ.load_manifest(C.BASE_DIR, include_deleted=True)
    pieces = manifest.get("pieces", [])
    return str(PJ.journal_path(C.BASE_DIR)), manifest, pieces


def _save_stored_piece_manifest(manifest_path: str, manifest: dict | list | None) -> None:
    """Compatibility merge; journal records are never replaced wholesale."""
    if manifest is None:
        return
    try:
        pieces = manifest.get("pieces", []) if isinstance(manifest, dict) else manifest
        if not isinstance(pieces, list):
            raise PJ.PieceJournalError("piece lifecycle projection has invalid pieces")
        PJ.record_many(C.BASE_DIR, pieces, source="lifecycle-projection-merge")
    except Exception as exc:
        L.log(f"[deletion] failed to save receipts manifest: {exc}")
        raise


def _piece_commitment_hash(item: dict) -> str:
    receipt = item.get("privateReceipt") or {}
    return str(item.get("commitmentHash", "") or receipt.get("commitmentHash", "")).strip()


def _current_registration_namespace() -> tuple[int, str]:
    """Return the exact chain/contract whose lifecycle may be mutated."""
    if C.w3 is None or C.file_registration_sc is None:
        raise RuntimeError(
            "current FileRegistrationSC chain namespace is unavailable"
        )
    chain_id = int(C.w3.eth.chain_id)
    if chain_id <= 0:
        raise RuntimeError("current blockchain returned an invalid chainId")
    contract = HX.prefixed_hex(
        C.file_registration_sc.address,
        expected_bytes=20,
        field="current FileRegistrationSC",
    ).lower()
    return chain_id, contract


def _journal_scope_for_current_chain(item: dict) -> dict:
    """Validate a journal row before using the configured blockchain.

    New records are explicitly namespaced.  A legacy unscoped record is
    accepted only after its signed receipt is verified against the currently
    configured FileRegistrationSC, so a network switch can never delete or
    settle stale storage accidentally.
    """
    current_chain, current_contract = _current_registration_namespace()
    stored_chain_raw = item.get("chainId", "")
    stored_contract_raw = str(item.get("fileRegistrationContract", "") or "")
    has_chain = stored_chain_raw not in (None, "", 0, "0")
    has_contract = bool(stored_contract_raw.strip())
    if has_chain != has_contract:
        raise RuntimeError("piece journal contains a partial chain namespace")
    if has_chain:
        stored_chain = int(stored_chain_raw)
        stored_contract = HX.prefixed_hex(
            stored_contract_raw,
            expected_bytes=20,
            field="journal FileRegistrationSC",
        ).lower()
        if stored_chain != current_chain or stored_contract != current_contract:
            raise RuntimeError(
                "piece belongs to a different blockchain or FileRegistrationSC"
            )
        return {
            "chain_id": current_chain,
            "file_registration_contract": current_contract,
        }

    receipt = item.get("privateReceipt")
    if not isinstance(receipt, dict) or not receipt:
        raise RuntimeError(
            "legacy piece has no signed receipt for chain-namespace recovery"
        )
    receipt_chain = int(receipt.get("chainId", 0) or 0)
    if receipt_chain and receipt_chain != current_chain:
        raise RuntimeError("legacy piece receipt belongs to a different blockchain")
    commitment_hash = _piece_commitment_hash(item)
    verified, reason = VM.verify_file_registration_onchain(
        commitment_hash, receipt
    )
    if not verified:
        raise RuntimeError(
            "legacy piece cannot be bound to the current FileRegistrationSC: "
            + str(reason)
        )
    # The row remains in its legacy empty namespace; the authoritative chain
    # check above makes operating on that exact record safe.
    return {}


def _resolve_piece_for_current_chain(
    *,
    commitment_hash: str = "",
    piece_root: str = "",
    include_deleted: bool = True,
) -> dict | None:
    """Resolve an exact current-namespace row, with verified legacy fallback."""
    current_chain, current_contract = _current_registration_namespace()
    item = PJ.resolve_piece_reference(
        C.BASE_DIR,
        commitment_hash=commitment_hash,
        piece_root=piece_root,
        include_deleted=include_deleted,
        chain_id=current_chain,
        file_registration_contract=current_contract,
    )
    if item is not None:
        return item

    commitment_norm = str(commitment_hash or "").strip().lower()
    root_norm = str(piece_root or "").strip().lower()
    legacy_matches = []
    for candidate in PJ.list_pieces(
        C.BASE_DIR, include_deleted=include_deleted
    ):
        if candidate.get("chainId") not in (None, "", 0, "0"):
            continue
        if str(candidate.get("fileRegistrationContract", "") or "").strip():
            continue
        if commitment_norm:
            matches = (
                _piece_commitment_hash(candidate).lower() == commitment_norm
            )
        else:
            matches = (
                str(candidate.get("pieceRoot", "") or "").strip().lower()
                == root_norm
            )
        if matches:
            legacy_matches.append(candidate)
    if len(legacy_matches) > 1:
        raise PJ.AmbiguousPieceReference(
            "legacy piece reference matches multiple registrations; "
            "commitmentHash and chain migration are required"
        )
    if not legacy_matches:
        return None
    _journal_scope_for_current_chain(legacy_matches[0])
    return legacy_matches[0]


def _settle_piece_transfer_after_confirmed_deletion(
    item: dict,
    commitment_hash: str,
) -> None:
    """Settle only the exact transfer represented by the deleted commitment."""
    VM.XFER.settle_piece_job_after_confirmed_deletion(
        C.BASE_DIR,
        commitment_hash=commitment_hash,
        transfer_id=str(item.get("transferId", "") or ""),
        winning_peer_id=str(
            item.get("peerId") or item.get("resolvedMultiaddr") or ""
        ),
        logical_job_id=str(item.get("logicalJobId", "") or ""),
    )


def _valid_bytes32_hex(value: str) -> bool:
    return HX.is_fixed_hex(value, size=32)


def _piece_marked_deleted(item: dict) -> bool:
    status = str(item.get("deletionStatus", "") or item.get("deleteStatus", "")).strip().lower()
    return bool(item.get("deleted")) or status in {"confirmed", "deleted", "deletion_confirmed"}


_DELETION_IN_FLIGHT_STATUSES = frozenset(
    {"requested", "pending", "failed", "blocked", "declared"}
)


def _piece_deletion_in_flight(item: dict) -> bool:
    """Whether this piece has a deletion the chain may have moved on.

    Matches the journal statuses the background monitor treats as unresolved,
    so the two agree on which pieces are worth a chain read.
    """
    status = str(
        item.get("deletionStatus", "") or item.get("deleteStatus", "")
    ).strip().lower()
    return status in _DELETION_IN_FLIGHT_STATUSES


def _piece_deleted_onchain(item: dict) -> bool:
    commitment_hash = _piece_commitment_hash(item)
    status = _read_deletion_status_quiet(commitment_hash)
    return bool(status.get("ok"))


def _read_deletion_status_quiet(commitment_hash: str) -> dict:
    result = {"declared": False, "confirmed": False, "confirmed_at": 0, "ok": False, "error": ""}
    if C.file_registration_sc is None or not _valid_bytes32_hex(commitment_hash):
        return result
    try:
        ch_bytes = HX.hex_to_bytes(
            commitment_hash, expected_bytes=32, field="commitmentHash"
        )
        result["declared"] = bool(C.file_registration_sc.functions.isDeletionDeclared(ch_bytes).call())
        result["confirmed"] = bool(C.file_registration_sc.functions.isDeletionConfirmed(ch_bytes).call())
        if result["confirmed"]:
            result["confirmed_at"] = int(C.file_registration_sc.functions.getDeletionConfirmedAt(ch_bytes).call())
        result["ok"] = result["declared"] and result["confirmed"]
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _mark_piece_deleted(item: dict, *, summary: str = "", chain_status: dict | None = None) -> None:
    item["deleted"] = True
    item["deletionStatus"] = "confirmed"
    item["deletionUpdatedAt"] = datetime.datetime.now().astimezone().isoformat()
    if summary:
        item["deletionSummary"] = summary
    if chain_status:
        item["deletionDeclared"] = bool(chain_status.get("declared"))
        item["deletionConfirmed"] = bool(chain_status.get("confirmed"))
        confirmed_at = int(chain_status.get("confirmed_at", 0) or 0)
        if confirmed_at:
            item["deletionConfirmedAt"] = confirmed_at
            item["deletionConfirmedAtIso"] = datetime.datetime.fromtimestamp(confirmed_at).astimezone().isoformat()


def _mark_piece_deletion_pending(item: dict, summary: str, chain_status: dict | None = None) -> None:
    item["deleted"] = False
    item["deletionStatus"] = "pending"
    item["deletionUpdatedAt"] = datetime.datetime.now().astimezone().isoformat()
    item["deletionSummary"] = summary
    if chain_status:
        item["deletionDeclared"] = bool(chain_status.get("declared"))
        item["deletionDeclaredAt"] = int(chain_status.get("declared_at", 0) or 0)
        item["deletionGraceSeconds"] = int(chain_status.get("grace_seconds", 0) or 0)


def _mark_piece_pending_in_manifest(commitment_hash: str, summary: str) -> bool:
    item = PJ.get_by_commitment(C.BASE_DIR, commitment_hash)
    if item is None:
        return False
    scope = _journal_scope_for_current_chain(item)
    status = CH.verify_deletion_onchain(commitment_hash)
    PJ.mark_deletion_pending(
        C.BASE_DIR,
        commitment_hash,
        summary=summary,
        chain_status=status,
        **scope,
    )
    return True


def _redrive_accepted_queued_deletion(
    item: dict, commitment_hash: str, piece_root: str, chain_status: dict
) -> tuple[str, str]:
    """F.1: re-send a secret-bearing deletion request for an accepted-but-undeclared
    deletion so the VK can declare it once this operation becomes the durable FIFO
    owner of its partition.

    The VK holds accepted_queued deletions it cannot declare on its own (an authorized
    deletion needs the request-supplied secret, which the VK never persists). This
    re-drive supplies the secret again from DO-side durable state only.

    Classification is delegated to the pure, structured classifier (do_deletion_redrive)
    so that transport failures, timeouts, RPC errors, malformed responses, temporary VK
    errors, and busy conditions are all retryable, and ONLY an explicit permanent VK
    rejection is terminal. Returns (state, summary) where state is:
      'pending'   — accepted_queued / declared_pending / transient: keep monitoring
                    (secret re-drive continues only while not yet declared);
      'confirmed' — the deletion is confirmed on-chain;
      'failed'    — an explicit permanent VK rejection: stop, do NOT dispute (never
                    declared).

    The deletion secret is read only from durable DO state and is never logged, placed in
    metrics, or returned in the summary.
    """
    receipt = item.get("privateReceipt") or _load_vk_receipt_for_piece(
        piece_root, commitment_hash
    )
    vk_peer = _vk_peer_for_delete_item(item, receipt)
    if not vk_peer:
        return "pending", "deletion re-drive deferred: VK peer address unavailable"
    deletion_auth_secret = str(
        item.get("deletionAuthSecret", "")
        or (receipt or {}).get("deletionAuthSecret", "")
        or (item.get("privateReceipt") or {}).get("deletionAuthSecret", "")
    ).strip()
    # One re-drive per operation per monitor tick. The monitor is single-threaded and
    # journal-driven, so at most one re-drive is in flight per deletion at a time; the
    # VK acceptance/declaration path is idempotent, so an overlap with the original
    # request is harmless.
    resp = CH.redrive_deletion_request(vk_peer, commitment_hash, deletion_auth_secret)
    decision, summary = DR.classify_redrive(resp, chain_status)
    if decision == DR.REDRIVE_CONFIRMED:
        return "confirmed", summary
    if decision == DR.REDRIVE_TERMINAL:
        return "failed", summary
    # REDRIVE_CONTINUE (keep re-driving) and REDRIVE_DECLARED (stop secret re-drive but
    # keep polling for confirmation) both remain durably pending; the next tick's
    # authoritative verify_deletion_onchain drives declared/confirmed transitions, and its
    # `not declared` guard stops the secret-bearing re-drive once declaration lands.
    return "pending", summary


def reconcile_pending_piece_deletions() -> list[dict]:
    """Reconcile durable pending deletions against authoritative chain state."""
    pieces = PJ.unresolved_deletions(C.BASE_DIR)
    confirmed_events = CH.recent_deletion_confirmation_events()
    updates = []
    for item in pieces:
        commitment_hash = _piece_commitment_hash(item)
        try:
            scope = _journal_scope_for_current_chain(item)
        except Exception as exc:
            L.log(
                "[deletion] skipping lifecycle record outside the current "
                f"chain namespace commitment={commitment_hash[:20]}...: {exc}"
            )
            continue
        status = CH.verify_deletion_onchain(commitment_hash)
        status["confirmation_event_observed"] = commitment_hash.lower() in confirmed_events
        piece_root = str(item.get("pieceRoot", ""))
        if status.get("ok"):
            summary = CH._verified_deletion_summary(status)
            # Say so. The click reports "pending: awaiting chain observation",
            # because the declaration is not mined yet at that instant, and
            # until now nothing was written when it did land -- so a deletion
            # that completed a minute later still read as stuck forever.
            L.log(
                f"[deletion] confirmed on-chain  commitment={commitment_hash[:24]}...  {summary}"
            )
            PJ.mark_deletion_confirmed(
                C.BASE_DIR,
                commitment_hash,
                summary=summary,
                chain_status=status,
                **scope,
            )
            _settle_piece_transfer_after_confirmed_deletion(
                item, commitment_hash
            )
            updates.append({
                "pieceRoot": piece_root,
                "commitmentHash": commitment_hash,
                "state": "confirmed",
                "status": status,
            })
        elif status.get("declared") and status.get("grace_expired"):
            dispute_ok = False
            dispute_summary = ""
            if item.get("deletionDisputeSubmitted"):
                dispute_ok = True
                dispute_summary = str(
                    item.get("deletionDisputeSummary")
                    or "deletion dispute previously submitted"
                )
            else:
                receipt = item.get("privateReceipt") or _load_vk_receipt_for_piece(
                    piece_root, commitment_hash
                )
                dispute_ok, dispute_summary = _auto_dispute_deletion_failure(
                    item,
                    receipt,
                    piece_root,
                    "VK declared deletion on-chain but confirmation is missing.",
                )
            if dispute_ok:
                PJ.mark_deletion_disputed(
                    C.BASE_DIR,
                    commitment_hash,
                    summary="VK deletion grace period expired without confirmation",
                    dispute_summary=dispute_summary,
                    **scope,
                )
            else:
                PJ.mark_deletion_failed(
                    C.BASE_DIR,
                    commitment_hash,
                    summary="VK deletion grace period expired without confirmation",
                    extra={
                        "deletionDisputeSubmitted": False,
                        "deletionDisputeSummary": dispute_summary,
                        "deletionDeclared": bool(status.get("declared")),
                        "deletionLastChainError": str(status.get("error", "") or ""),
                    },
                    **scope,
                )
            updates.append({
                "pieceRoot": piece_root, "commitmentHash": commitment_hash,
                "state": "disputed" if dispute_ok else "failed", "status": status,
                "disputeSubmitted": dispute_ok, "disputeSummary": dispute_summary,
            })
        else:
            # Not confirmed, and not (declared & grace-expired). Two sub-cases:
            #   - already declared on-chain (declared_pending): only monitor for
            #     confirmation; do NOT re-drive (the VK has the obligation).
            #   - not yet declared and chain is reachable: the VK is holding an
            #     accepted_queued deletion it can declare only once this op becomes the
            #     FIFO owner AND a secret-bearing request arrives. Re-drive (F.1).
            state = "pending"
            summary = str(
                item.get("deletionSummary")
                or status.get("error")
                or "deletion awaiting authoritative confirmation"
            )
            if not status.get("declared") and not status.get("error"):
                state, summary = _redrive_accepted_queued_deletion(
                    item, commitment_hash, piece_root, status
                )
            if state == "failed":
                PJ.mark_deletion_failed(
                    C.BASE_DIR,
                    commitment_hash,
                    summary=summary,
                    extra={
                        "deletionDisputeSubmitted": False,
                        "deletionDeclared": False,
                        "deletionLastChainError": str(status.get("error", "") or ""),
                    },
                    **scope,
                )
                updates.append({
                    "pieceRoot": piece_root, "commitmentHash": commitment_hash,
                    "state": "failed", "status": status,
                })
            else:
                # 'pending' (keep re-driving) or 'confirmed' (authoritative confirm is
                # picked up on the next tick's verify_deletion_onchain).
                PJ.mark_deletion_pending(
                    C.BASE_DIR,
                    commitment_hash,
                    summary=summary,
                    chain_status=status,
                    **scope,
                )
    return updates


def _schedule_pending_deletion_reconciliation() -> None:
    """Start one restart-safe monitor independent of the original VK connection."""
    global _PENDING_DELETION_MONITOR_RUNNING
    with _PENDING_DELETION_MONITOR_LOCK:
        if _PENDING_DELETION_MONITOR_RUNNING:
            return
        if not PJ.unresolved_deletions(C.BASE_DIR):
            return
        _PENDING_DELETION_MONITOR_RUNNING = True

    def monitor() -> None:
        global _PENDING_DELETION_MONITOR_RUNNING
        # Every confirmation this monitor sees, not only the ones in its last
        # pass. Six pieces confirmed over two passes reported "5 deletions
        # confirmed", because the first had landed in the pass before.
        seen_confirmed = 0
        try:
            while True:
                updates = reconcile_pending_piece_deletions()
                seen_confirmed += len(updates or [])
                if updates and S.root is not None and S.stored_pieces_tree is not None:
                    S.root.after(0, load_stored_pieces_list)
                if not PJ.unresolved_deletions(C.BASE_DIR):
                    # Replace the status the click left behind. It reads
                    # "5 pending on-chain confirmation" -- true at that instant,
                    # and still on screen long after every one of them landed,
                    # which is how a finished deletion looks stuck.
                    # The bar's second half belongs to the chain, and this is
                    # the moment it lands. It is closed whether or not this
                    # pass is the one that recorded the confirmations: another
                    # path may have recorded them first, and the bar used to
                    # stay on screen for ever when it did -- a finished
                    # deletion reading as "waiting for the chain".
                    confirmed = seen_confirmed
                    if confirmed:
                        PROG.step("confirmed on chain", confirmed, confirmed)
                        word = "deletion" if confirmed == 1 else "deletions"
                        text = f"{confirmed} {word} confirmed on-chain"
                    else:
                        text = "all deletions confirmed on-chain"
                    PROG.finish(text)
                    L.log(f"[deletion] all pending work is finished: {text}")
                    if S.root is not None:
                        S.root.after(0, L.set_status, text, "done")
                    return
                interval = max(
                    1.0, float(getattr(C.config, "DO_DELETION_MONITOR_SECONDS", 30.0))
                )
                time.sleep(interval)
        finally:
            with _PENDING_DELETION_MONITOR_LOCK:
                _PENDING_DELETION_MONITOR_RUNNING = False

    threading.Thread(
        target=monitor, name="filetrust-deletion-monitor", daemon=True
    ).start()


def _mark_piece_deleted_in_manifest(
    commitment_hash: str,
    summary: str,
    *,
    item: dict | None = None,
    scope: dict | None = None,
) -> bool:
    if item is None:
        item = _resolve_piece_for_current_chain(
            commitment_hash=commitment_hash,
            include_deleted=True,
        )
    if item is None:
        return False
    scope = dict(scope) if scope is not None else _journal_scope_for_current_chain(item)
    chain_status = CH.reconcile_deletion_onchain(commitment_hash)

    if not chain_status.get("ok"):
        if chain_status.get("error"):
            L.log(f"[deletion] post-delete verification failed for {commitment_hash[:20]}...: {chain_status['error']}")
        return False

    PJ.mark_deletion_confirmed(
        C.BASE_DIR,
        commitment_hash,
        summary=summary,
        chain_status=chain_status,
        **scope,
    )
    _settle_piece_transfer_after_confirmed_deletion(item, commitment_hash)
    return True


def delete_selected_file_from_vks() -> None:
    """Delete every piece of the selected file, from every keeper holding one.

    A policy can hold many files, so this deliberately acts on the file chosen
    in the policy detail rather than on the policy: deleting a policy would take
    files the user never looked at with it.

    Confirmed first, with the counts, because this is the one action in the app
    that removes data from other machines and cannot be undone.
    """
    upload_id = str(S.selected_upload_instance_id or "")
    if not upload_id:
        L.show_error(
            "Delete file",
            "Select a policy, then a file inside it, before deleting.",
        )
        return

    _path, manifest, pieces = _load_stored_piece_manifest()
    if manifest is None:
        L.show_error("Delete file", "No piece journal was found for this app.")
        return

    live = [
        p for p in _pieces_for_selected_file(pieces)
        if not _piece_marked_deleted(p)
    ]
    if not live:
        L.show_info("Delete file", "This file has no pieces left to delete.")
        return

    keepers = {str(p.get("vkPeer", "") or p.get("vkAddress", "") or "") for p in live}
    keepers.discard("")
    label = ""
    if S.policy_files_tree is not None and S.policy_files_tree.exists(upload_id):
        label = str(S.policy_files_tree.item(upload_id, "values")[0])

    if not messagebox.askyesno(
        "Delete file from all Vault Keepers",
        f"Delete {label or 'this file'} from the network?\n\n"
        f"{len(live)} piece(s) on {len(keepers)} keeper(s) will be deleted.\n\n"
        "This cannot be undone. Anyone you shared the file with will no longer "
        "be able to download it.",
        icon="warning",
    ):
        L.log("[deletion] file deletion cancelled by the user")
        return

    L.log(f"[deletion] deleting {len(live)} piece(s) of {label or upload_id}")
    # Two phases, because that is what a deletion really is: the keepers accept
    # straight away, the chain confirms a minute later. Reporting only the first
    # is what made a working deletion look stuck at "pending".
    PROG.start(f"Deleting {label or 'file'}", [
        ("asked the keepers", 0.5),
        ("confirmed on chain", 0.5),
    ])
    PROG.step("asked the keepers", 0, len(live))
    done = 0
    pending = 0
    failed = 0
    first_failure = ""
    for piece in live:
        commitment_hash = _piece_commitment_hash(piece)
        if not commitment_hash:
            failed += 1
            continue
        try:
            ok, summary = delete_vk_piece(
                commitment_hash=commitment_hash, quiet=True)
        except Exception as exc:
            failed += 1
            first_failure = first_failure or str(exc)
            L.log(f"[deletion] piece {commitment_hash[:20]}... failed: {exc}")
            continue
        if ok:
            done += 1
        elif "pending" in str(summary).lower():
            pending += 1
        else:
            failed += 1
            first_failure = first_failure or str(summary)
        PROG.step("asked the keepers", done + pending + failed, len(live))
        PROG.step("confirmed on chain", done, len(live))

    load_stored_pieces_list()
    # Worded so the normal case does not read as a failure. Every keeper accepts
    # first and declares on chain a moment later, so a correct delete reports
    # "0 confirmed, 5 pending" at this instant -- which looked like nothing had
    # worked, when in fact all five were confirmed within ninety seconds.
    parts = []
    if done:
        parts.append(f"{done} confirmed")
    if pending:
        parts.append(f"{pending} accepted by the keeper, waiting for the chain")
    if failed:
        parts.append(f"{failed} failed")
    summary_line = ", ".join(parts) or "nothing to delete"
    L.log(f"[deletion] {label or upload_id}: {summary_line}")
    if failed and not pending:
        PROG.finish(summary_line, ok=False)
    elif not pending:
        PROG.finish(summary_line)
    else:
        # Leave the bar running: the monitor closes it when the chain confirms.
        PROG.step("asked the keepers", len(live), len(live), note=summary_line)
    if pending:
        L.show_info(
            "Delete file",
            f"{summary_line}.\n\nPending pieces are still being confirmed on "
            "the blockchain; the app keeps checking and the list updates itself.",
        )
    elif failed:
        # One box for the whole file. Each piece used to raise its own, so a
        # file that failed the same way six times took six clicks to dismiss
        # before the summary was even reached.
        L.show_error(
            "Delete file",
            f"{summary_line}.\n\n{first_failure}" if first_failure else summary_line,
        )


def delete_vk_piece_selected() -> None:
    """Read the selected row from the Stored VK Pieces treeview and delete it from VK."""
    if S.stored_pieces_tree is None:
        return
    sel = S.stored_pieces_tree.selection()
    if not sel:
        L.show_error("Delete from VK", "Please select a piece from the Stored VK Pieces list first.")
        return
    commitment_hash = sel[0]
    ok, msg = delete_vk_piece(commitment_hash=commitment_hash)
    if ok:
        load_stored_pieces_list()


_DISPUTE_TITLE = "Dispute Deletion Failure"


def dispute_deletion_failure_selected() -> None:
    """Dispute a deletion a keeper never completed.

    One button, and the selection decides what it covers: a selected piece
    disputes that piece, and a selected file with no piece chosen disputes
    every piece of that file the chain still shows as asked-for but not
    confirmed. The contract has no file-level dispute -- it is one transaction
    per piece -- so the work runs off the UI thread with the progress bar.
    """
    if S.stored_pieces_tree is None:
        return

    sel = S.stored_pieces_tree.selection()
    if sel:
        _start_dispute([str(sel[0])], "the selected piece", single=True)
        return

    upload_id = str(S.selected_upload_instance_id or "")
    if not upload_id:
        L.show_error(
            _DISPUTE_TITLE,
            "Select a file in the policy, or one piece of it, before disputing.",
        )
        return

    _path, manifest, pieces = _load_stored_piece_manifest()
    if manifest is None:
        L.show_error(_DISPUTE_TITLE, "No piece journal was found for this app.")
        return

    hashes = [
        h for h in (
            _piece_commitment_hash(p)
            for p in _pieces_for_selected_file(pieces, require_selection=True)
        ) if h
    ]
    if not hashes:
        L.show_info(_DISPUTE_TITLE, "This file has no pieces to dispute.")
        return

    label = "this file"
    if S.policy_files_tree is not None and S.policy_files_tree.exists(upload_id):
        label = str(S.policy_files_tree.item(upload_id, "values")[0]) or label
    _start_dispute(hashes, label, single=False)


def _start_dispute(commitment_hashes: list, label: str, single: bool) -> None:
    threading.Thread(
        target=lambda: _run_dispute(commitment_hashes, label, single),
        daemon=True,
    ).start()


def _run_dispute(commitment_hashes: list, label: str, single: bool) -> None:
    total = len(commitment_hashes)
    L.log(f"[dispute] checking {total} piece(s) of {label} for deletion failure")
    PROG.start(f"Disputing {label}", [
        ("checked on chain", 0.3),
        ("disputed", 0.7),
    ])
    filed = skipped = failed = 0
    last_skip = ""
    for index, commitment_hash in enumerate(commitment_hashes, start=1):
        PROG.step("checked on chain", index, total)
        state, message = _dispute_one_piece(commitment_hash)
        L.log(f"[dispute] {commitment_hash[:20]}... {state}: {message}")
        if state == "filed":
            filed += 1
        elif state == "skipped":
            skipped += 1
            last_skip = message
        else:
            failed += 1
        PROG.step("disputed", filed, total)

    parts = []
    if filed:
        parts.append(f"{filed} disputed")
    if skipped:
        parts.append(f"{skipped} with nothing to dispute")
    if failed:
        parts.append(f"{failed} failed")
    summary = ", ".join(parts) or "nothing to dispute"
    L.log(f"[dispute] {label}: {summary}")
    PROG.finish(summary, ok=not failed)

    if S.root is not None:
        S.root.after(0, load_stored_pieces_list)
    # One piece gives one reason, and saying it is more use than a count.
    if single and not filed:
        L.show_info(_DISPUTE_TITLE, last_skip or summary)


def _dispute_one_piece(commitment_hash: str) -> tuple[str, str]:
    """Dispute one piece. Returns (filed | skipped | failed, reason)."""
    try:
        item = PJ.get_by_commitment(C.BASE_DIR, commitment_hash)
    except Exception as exc:
        return "failed", f"could not read the lifecycle journal: {exc}"
    if item is None:
        return "failed", "this piece is not in the lifecycle journal"
    try:
        _journal_scope_for_current_chain(item)
    except Exception as exc:
        return "failed", str(exc)

    # A deletion failure only exists between "I asked" and "the chain says it
    # is gone". Outside that window there is nothing for the contract to judge.
    status = _read_deletion_status_quiet(commitment_hash)
    if status.get("error"):
        return "failed", f"could not read the deletion status: {status['error']}"
    if not status.get("declared"):
        return "skipped", "deletion was never requested for this piece"
    if status.get("confirmed"):
        return "skipped", "this piece is already deleted and confirmed on chain"

    receipt = item.get("privateReceipt") or {}
    commitment_nonce = str(item.get("commitmentNonce", "") or "")
    if not receipt or not commitment_nonce:
        return "failed", "missing receipt or commitmentNonce — cannot dispute"

    try:
        ok, message = CH.submit_deletion_failure_dispute(receipt, commitment_nonce)
    except Exception as exc:
        return "failed", f"dispute error: {exc}"
    return ("filed" if ok else "failed"), message


def _load_vk_receipt_for_piece(
    piece_root: str,
    commitment_hash: str = "",
) -> dict:
    if commitment_hash:
        try:
            clean_commitment = HX.normalize_hex(
                commitment_hash, expected_bytes=32, field="commitmentHash"
            )
            exact = Path(R.vk_receipts_dir()) / f"receipt_{clean_commitment}.json"
            if exact.is_file():
                value = json.loads(exact.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    return value
        except Exception:
            return {}
    try:
        clean = HX.normalize_hex(piece_root, expected_bytes=32, field="pieceRoot")
    except ValueError:
        return {}
    candidates = list(Path(R.vk_receipts_dir()).glob("receipt_*.json"))
    seen = set()
    matches: list[dict] = []
    for path in candidates:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        try:
            stored_root = HX.normalize_hex(
                data.get("pieceRoot", ""), expected_bytes=32, field="stored pieceRoot"
            )
        except ValueError:
            continue
        if stored_root == clean:
            matches.append(data)
    # A root can legitimately be registered more than once. Never guess which
    # receipt owns a deletion when the commitment identity is unavailable.
    return matches[0] if len(matches) == 1 else {}


def _vk_peer_for_delete_item(item: dict, receipt: dict) -> str:
    for key in ("resolvedMultiaddr", "multiaddr", "vkPeer"):
        value = str(item.get(key, "") or "").strip()
        if "/p2p/" in value:
            return value

    peer_id = str(item.get("peerId", "") or item.get("vkPeer", "") or "").strip()
    vk_addr = str(receipt.get("vkAddress", "") or item.get("vkAddress", "")).strip()

    if peer_id and "/p2p/" in peer_id:
        return peer_id

    if vk_addr:
        for row in S.vault_keeper_rows.values():
            if str(row.get("address", "")).lower() == vk_addr.lower() and row.get("multiaddr"):
                return str(row["multiaddr"]).strip()

    if peer_id and vk_addr:
        multiaddr, _source, _location, _lat, _lon = N.resolve_vk_multiaddr(peer_id, vk_addr)
        if multiaddr:
            return multiaddr

    if vk_addr:
        try:
            event_peer_id, _metadata_uri = N._get_vk_peer_from_events(vk_addr)
            normalized_peer = N._normalize_registry_peer(event_peer_id)
            if normalized_peer:
                multiaddr, _source, _location, _lat, _lon = N.resolve_vk_multiaddr(normalized_peer, vk_addr)
                if multiaddr:
                    return multiaddr
        except Exception as exc:
            L.log(f"[deletion] VK peer resolution failed for {vk_addr}: {exc}")

    try:
        peers = N.get_selected_vk_peers()
        if peers:
            return peers[0]
    except Exception:
        pass

    return ""


def _commitment_nonce_for_delete_item(item: dict, receipt: dict) -> str:
    return str(
        item.get("commitmentNonce", "")
        or receipt.get("commitmentNonce", "")
        or (item.get("privateReceipt") or {}).get("commitmentNonce", "")
        or ""
    ).strip()


def _delete_failure_has_missing_proof(delete_summary: str) -> bool:
    summary = str(delete_summary or "")
    return (
        "FileRegistrationSC shows no declaration on-chain" in summary
        or "confirmation is missing" in summary
    )


def _auto_dispute_deletion_failure(item: dict, receipt: dict, piece_root: str, delete_summary: str) -> tuple[bool, str]:
    if not _delete_failure_has_missing_proof(delete_summary):
        msg = "auto dispute skipped: delete proof was not checked/missing"
        L.log(f"[dispute] {msg}  pieceRoot={piece_root[:20]}...  reason={delete_summary}")
        return False, msg

    if not receipt:
        receipt = item.get("privateReceipt") or {}
    if not receipt:
        receipt = _load_vk_receipt_for_piece(
            piece_root, str(item.get("commitmentHash", "") or "")
        )

    commitment_nonce = _commitment_nonce_for_delete_item(item, receipt)
    if not receipt or not commitment_nonce:
        msg = "auto dispute skipped: missing receipt or commitmentNonce"
        L.log(f"[dispute] {msg}  pieceRoot={piece_root[:20]}...")
        return False, msg

    L.log(
        f"[dispute] auto-submitting deletion failure dispute  "
        f"pieceRoot={piece_root[:20]}...  reason={delete_summary}"
    )
    L.set_status("Submitting deletion failure dispute...", "running")
    ok, msg = CH.submit_deletion_failure_dispute(receipt, commitment_nonce)
    if ok:
        L.set_status("Deletion failure dispute submitted", "ok")
        return True, f"auto dispute submitted: {msg}"

    L.set_status("Auto dispute failed - see log", "error")
    return False, f"auto dispute failed: {msg}"


def _delete_vk_piece_item(item: dict, *, auto_dispute: bool = True) -> tuple[bool, str]:
    receipt = item.get("privateReceipt") or {}
    piece_root = str(item.get("pieceRoot", "") or receipt.get("pieceRoot", "")).strip()
    if not piece_root:
        return False, "pieceRoot not found"
    if not receipt:
        receipt = _load_vk_receipt_for_piece(
            piece_root, str(item.get("commitmentHash", "") or "")
        )

    commitment_hash = str(
        item.get("commitmentHash", "") or receipt.get("commitmentHash", "")
    ).strip()
    if not commitment_hash:
        return False, "commitmentHash not found in receipt — cannot delete"

    vk_peer = _vk_peer_for_delete_item(item, receipt)
    if not vk_peer:
        return False, "VK peer address not found"

    deletion_auth_secret = str(
        item.get("deletionAuthSecret", "")
        or receipt.get("deletionAuthSecret", "")
        or (item.get("privateReceipt") or {}).get("deletionAuthSecret", "")
    ).strip()

    L.log(f"[deletion] requesting deletion  commitmentHash={commitment_hash[:20]}...  peer={vk_peer[:40]}...")
    L.set_status("Requesting VK piece deletion...", "running")

    ok, summary = CH.request_file_deletion(vk_peer, commitment_hash, deletion_auth_secret)
    if ok:
        L.log(f"[deletion] success: {summary}")
        L.set_status("Piece deletion completed", "ok")
    elif summary.startswith("deletion pending:"):
        L.log(f"[deletion] pending: {summary}")
        L.set_status("Piece deletion pending on-chain confirmation", "running")
    else:
        L.log(f"[deletion] failed: {summary}")
        # Initial response failure is not deadline evidence. Only the durable
        # chain monitor may submit a dispute, after block-time grace expiry.
        L.set_status("Piece deletion request pending reconciliation", "error")
    return ok, summary


def delete_vk_piece(
    piece_root: str = "",
    *,
    commitment_hash: str = "",
    quiet: bool = False,
) -> tuple[bool, str]:
    """Durably request deletion; authoritative completion is asynchronous.

    Loads the piece's stored receipt to find the VK peer and commitmentHash,
    then calls request_file_deletion(). The pending journal and background
    monitor confirm completion or submit a post-deadline dispute later.

    Args:
        piece_root: hex piece root identifying the piece to delete.
                    If empty, tries to read from the GUI state.

    With *quiet*, nothing is shown on screen and the caller reports. Deleting
    a whole file calls this once per piece, and six pieces that fail the same
    way meant six message boxes to dismiss before the one summary appeared.

    Returns:
        (ok, message) — suitable for display in the GUI log.
    """
    def problem(message: str) -> None:
        L.log(f"[deletion] {message}")
        if not quiet:
            L.show_error("Delete Piece", message)

    if not commitment_hash and not piece_root:
        problem("commitmentHash or pieceRoot is required")
        return False, "commitmentHash or pieceRoot required"

    try:
        item = _resolve_piece_for_current_chain(
            commitment_hash=commitment_hash,
            piece_root=piece_root,
            include_deleted=True,
        )
    except PJ.AmbiguousPieceReference as exc:
        problem(str(exc))
        return False, str(exc)
    except Exception as exc:
        problem(f"Lifecycle journal error: {exc}")
        return False, f"lifecycle journal error: {exc}"

    if item is None:
        reference = commitment_hash or piece_root
        problem(f"Piece not found:\n{reference[:40]}...")
        return False, f"piece not found in lifecycle journal: {reference[:20]}..."
    if _piece_marked_deleted(item):
        return True, "deletion already confirmed in the lifecycle journal"

    # A piece recovered before the app knew to derive its secrets has none,
    # and the keeper refuses an empty one. Working it out costs nothing, so
    # it is done here rather than failing and asking the user to restart.
    if not str(item.get("deletionAuthSecret", "") or "").strip():
        try:
            from . import do_recovery as RECOVER

            if RECOVER.repair_missing_secrets():
                item = _resolve_piece_for_current_chain(
                    commitment_hash=_piece_commitment_hash(item),
                    include_deleted=True,
                ) or item
        except Exception as exc:
            L.log(f"[deletion] the piece's secrets could not be rebuilt: {exc}")

    try:
        scope = _journal_scope_for_current_chain(item)
    except Exception as exc:
        return False, f"piece chain namespace is not current: {exc}"

    commitment_hash = _piece_commitment_hash(item)
    piece_root = str(item.get("pieceRoot", "") or piece_root)
    if not commitment_hash:
        return False, "commitmentHash not found in lifecycle journal — cannot delete"

    # Persist intent before any network call.  A timeout, crash, or malformed
    # response can no longer erase the cleanup obligation.
    try:
        item = PJ.begin_deletion(
            C.BASE_DIR,
            commitment_hash,
            summary="DO requested VK piece deletion",
            **scope,
        )
    except Exception as exc:
        return False, f"could not persist deletion request safely: {exc}"

    ok, summary = _delete_vk_piece_item(item)
    if ok:
        marked = _mark_piece_deleted_in_manifest(
            commitment_hash,
            summary,
            item=item,
            scope=scope,
        )
        if marked:
            L.log(
                f"[deletion] confirmed lifecycle tombstone  "
                f"commitmentHash={commitment_hash[:20]}..."
            )
        else:
            ok = False
            summary = (
                "deletion response received but authoritative confirmation "
                "could not be persisted"
            )
            PJ.mark_deletion_pending(
                C.BASE_DIR,
                commitment_hash,
                summary=summary,
                chain_status=CH.verify_deletion_onchain(commitment_hash),
                **scope,
            )
    else:
        chain_status = CH.verify_deletion_onchain(commitment_hash)
        if chain_status.get("ok"):
            summary = CH._verified_deletion_summary(chain_status)
            PJ.mark_deletion_confirmed(
                C.BASE_DIR,
                commitment_hash,
                summary=summary,
                chain_status=chain_status,
                **scope,
            )
            ok = True
        elif summary.startswith("deletion pending:") or chain_status.get("declared") or chain_status.get("error"):
            PJ.mark_deletion_pending(
                C.BASE_DIR,
                commitment_hash,
                summary=summary,
                chain_status=chain_status,
                **scope,
            )
        else:
            PJ.mark_deletion_failed(
                C.BASE_DIR,
                commitment_hash,
                summary=summary,
                extra={
                    "deletionDeclared": bool(chain_status.get("declared")),
                    "deletionLastChainError": str(chain_status.get("error", "") or ""),
                },
                **scope,
            )

        if ok:
            _settle_piece_transfer_after_confirmed_deletion(
                item, commitment_hash
            )

    if not ok:
        _schedule_pending_deletion_reconciliation()
    if not ok and "VK peer" in summary:
        problem("VK peer address not found. Please select the Vault Keeper.")
    return ok, summary
