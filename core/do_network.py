# do_network.py — Guardian and VK registry loading, sorting, selection.

import os
import re
import json
import math
import time
import datetime
import threading
import urllib.parse
import urllib.request
import tkinter as tk
from tkinter import ttk
from pathlib import Path

from . import do_config as C
from . import do_state as S
from . import do_log as L
from . import do_records as R
from . import do_directory as D


# ── VK sort constants ─────────────────────────────────────────────────────────
_VK_NUMERIC_COLS = {"rep", "stake", "done", "fail", "fee", "max_days", "max_piece", "served"}
_VK_COL_HEADINGS = {
    "status": "Status", "eligible": "Eligible", "rep": "Rep", "stake": "Stake FTU",
    "done": "Disputes", "fail": "Pen.Pts", "fee": "Fee SU/GB/d",
    "fee_ftu": "Est FTU/GB/d", "max_days": "Max Days", "max_piece": "Max Piece",
    "cap": "Capacity", "free": "Free",
    "served": "Served",
    "last_proof": "Last Proof", "heartbeat": "Heartbeat",
    "ip": "IP:Port", "location": "Location", "peer": "Peer ID", "address": "VK Address",
}

# ── Policy sort constants ──────────────────────────────────────────────────────
_POL_NUMERIC_COLS = {"gs", "files"}
_POL_COL_HEADINGS = {
    "name": "Policy Name", "fileid": "Policy ID",
    "gs": "Guardians", "files": "Files", "created": "Created",
}

# ── Guardian sort constants ────────────────────────────────────────────────────
_GUARDIAN_NUMERIC_COLS = {
    "rep", "stake", "done", "fail",
    "dkg_material", "dkg_share", "pre", "daily_custody", "max_days",
    "total_su", "total_proof_penalties",
}
_GUARDIAN_COL_HEADINGS = {
    "status": "Status", "rep": "Rep", "stake": "Stake FTU",
    "done": "Jobs", "fail": "Fail", "dkg_material": "DKG Mat SU",
    "dkg_share": "ShareKey SU", "pre": "PRE SU",
    "daily_custody": "Custody SU/day", "max_days": "Max Days",
    "suitable": "Suitable", "total_su": "Total SU",
    "cost": "Est. Cost", "source": "Price Src",
    "last_proof_at": "Last Proof", "total_proof_penalties": "Proof Penalties",
    "last_activity": "Last Activity",
    "address": "Guardian Address",
}

# Cached proof period (seconds) — refreshed on each load_guardians() call.
_proof_period_seconds = 86400
# Width the Guardian table's first column is widened to while an empty-state
# message is shown, and the original width saved so it can be put back.
_GUARDIAN_MESSAGE_COL_WIDTH = 260
_GUARDIAN_FIRST_COL_WIDTH = None
_VK_TX_GAS_VALUES_CACHE = None
_VK_ENDPOINT_CACHE: dict[str, dict] = {}
_DISCOVERY_RECORD_CACHE: dict[str, dict] = {}


def refresh_ida_info():
    """Update the IDA dispersal message from current n / t values."""
    if S.ida_info_var is None:
        return
    try:
        n = int(S.entry_n.get())
        t = int(S.entry_t.get())
        S.ida_info_var.set(
            f"File will be dispersed to {n} pieces, reconstructable by any {t}"
        )
    except (ValueError, AttributeError, tk.TclError):
        S.ida_info_var.set("Enter valid n and t values")


def _sync_n_from_selection():
    """Set IDA n to the number of selected VKs, then refresh the message."""
    if S.vault_keepers_listbox is None or S.entry_n is None:
        return
    count = len(S.vault_keepers_listbox.selection())
    if count > 0:
        S.entry_n.delete(0, tk.END)
        S.entry_n.insert(0, str(count))
    refresh_ida_info()


def toggle_vault_keeper_selection(event):
    if S.vault_keepers_listbox is None:
        return "break"
    if S.vault_keepers_listbox.identify_region(event.x, event.y) == "heading":
        return
    iid = S.vault_keepers_listbox.identify_row(event.y)
    if not iid:
        return "break"
    current = set(S.vault_keepers_listbox.selection())
    if iid in current:
        S.vault_keepers_listbox.selection_remove(iid)
    else:
        row = S.vault_keeper_rows.get(iid, {})
        if row and not row.get("eligible"):
            reason = row.get("eligibilityReason") or "VK is not eligible"
            L.log(f"[vk] selection blocked: {row.get('address', '')} — {reason}")
            return "break"
        S.vault_keepers_listbox.selection_add(iid)
    S.vault_keepers_listbox.after(0, _sync_n_from_selection)
    return "break"


def sort_vks_by_col(col: str):
    if S.vault_keepers_listbox is None:
        return
    reverse = (S._vk_sort_state["col"] == col and not S._vk_sort_state["reverse"])
    S._vk_sort_state["col"] = col
    S._vk_sort_state["reverse"] = reverse

    def _key(iid):
        val = S.vault_keepers_listbox.set(iid, col)
        if col in _VK_NUMERIC_COLS:
            try:
                return float(val.replace(",", "").strip() or 0)
            except ValueError:
                return 0.0
        return val.lower()

    items = [(iid, _key(iid)) for iid in S.vault_keepers_listbox.get_children("")]
    items.sort(key=lambda x: x[1], reverse=reverse)
    for idx, (iid, _) in enumerate(items):
        S.vault_keepers_listbox.move(iid, "", idx)

    arrow = " ↓" if reverse else " ↑"
    for c, base in _VK_COL_HEADINGS.items():
        S.vault_keepers_listbox.heading(c, text=base + (arrow if c == col else ""))


def sort_policies_by_col(col: str):
    if S.policies_tree is None:
        return
    reverse = (S._pol_sort_state["col"] == col and not S._pol_sort_state["reverse"])
    S._pol_sort_state["col"] = col
    S._pol_sort_state["reverse"] = reverse

    def _key(iid):
        val = S.policies_tree.set(iid, col)
        if col in _POL_NUMERIC_COLS:
            try:
                return int(val)
            except ValueError:
                return 0
        return val.lower()

    items = [(iid, _key(iid)) for iid in S.policies_tree.get_children("")]
    items.sort(key=lambda x: x[1], reverse=reverse)
    for idx, (iid, _) in enumerate(items):
        S.policies_tree.move(iid, "", idx)

    arrow = " ↓" if reverse else " ↑"
    for c, base in _POL_COL_HEADINGS.items():
        S.policies_tree.heading(c, text=base + (arrow if c == col else ""),
                                command=lambda cc=c: sort_policies_by_col(cc))


def sort_req_book_by_col(col: str):
    if S.req_book_tree is None:
        return
    reverse = (S._req_book_sort_state["col"] == col and not S._req_book_sort_state["reverse"])
    S._req_book_sort_state["col"] = col
    S._req_book_sort_state["reverse"] = reverse

    items = [(iid, S.req_book_tree.set(iid, col).lower()) for iid in S.req_book_tree.get_children("")]
    items.sort(key=lambda x: x[1], reverse=reverse)
    for idx, (iid, _) in enumerate(items):
        S.req_book_tree.move(iid, "", idx)

    arrow = " ↓" if reverse else " ↑"
    S.req_book_tree.heading("name",    text="Name"           + (arrow if col == "name"    else ""))
    S.req_book_tree.heading("address", text="Wallet Address" + (arrow if col == "address" else ""))


def select_all_vault_keepers():
    if S.vault_keepers_listbox is None:
        return
    eligible = [
        iid for iid in S.vault_keepers_listbox.get_children()
        if S.vault_keeper_rows.get(iid, {}).get("eligible")
    ]
    S.vault_keepers_listbox.selection_set(*eligible)
    _sync_n_from_selection()


def clear_vault_keeper_selection():
    if S.vault_keepers_listbox is None:
        return
    S.vault_keepers_listbox.selection_remove(*S.vault_keepers_listbox.get_children())
    _sync_n_from_selection()


def add_vks_to_policy():
    if S.vault_keepers_listbox is None:
        return
    peers = []
    addresses = []
    selected_rows = []
    unresolved = 0
    ineligible = 0
    refused: list[str] = []
    for iid in S.vault_keepers_listbox.selection():
        row = S.vault_keeper_rows.get(iid, {})
        if row.get("eligible") and row.get("multiaddr"):
            # The table is the discovery directory: a hint. Confirm each keeper
            # the user picked on chain, and take its signed address record.
            ok, reason = _verify_vk_before_paying(row)
            if not ok:
                refused.append(f"{str(row.get('address', ''))[:14]} ({reason})")
                continue
            peers.append(str(row["multiaddr"]).strip())
            addresses.append(str(row.get("address", ""))[:14])
            selected_rows.append(row)
        elif row.get("eligible") and row.get("peerId"):
            unresolved += 1
        else:
            ineligible += 1
    if refused:
        L.log(f"VK selection: skipped {len(refused)} VK(s) the chain disagreed about: {', '.join(refused[:5])}")
    if not peers:
        detail = ""
        if unresolved:
            detail += "\n\nSelected eligible VKs have peerIDs, but discovery did not return a live multiaddr yet."
        if ineligible:
            detail += "\n\nUnstaked, inactive, suspended, or under-minimum VKs cannot be selected."
        if refused:
            detail += "\n\nThe chain disagreed with the directory about: " + ", ".join(refused[:5])
        L.show_error("VK selection", f"Select at least one eligible, discovered Vault Keeper from the table first.{detail}")
        return
    S.policy_vk_peers = peers
    estimate = _selected_vk_cost_estimate(selected_rows)
    if S.policy_vk_status_var is not None:
        short = ", ".join(addresses[:3]) + ("..." if len(addresses) > 3 else "")
        if estimate.get("ok"):
            S.policy_vk_status_var.set(
                f"Upload VKs: {len(peers)} | VK DO {_format_wei_as_eth(estimate['vk_do_outlay_wei'])}  [{short}]"
            )
        else:
            S.policy_vk_status_var.set(
                f"Upload VKs: {len(peers)} | {_vk_estimate_status_reason(estimate)}  [{short}]"
            )
    L.log(f"Upload VKs confirmed: {len(peers)} VK(s)")
    for p in peers:
        L.log(f"  {p}")
    _log_selected_vk_cost_estimate(estimate)
    try:
        from . import do_actions as A
        A.save_latest_upload_settings()
    except Exception as exc:
        L.log(f"Could not persist latest VK settings: {exc}")


def clear_policy_vks():
    S.policy_vk_peers = []
    if S.policy_vk_status_var is not None:
        S.policy_vk_status_var.set("Upload VKs: none confirmed")


def _selected_vk_cost_estimate(vk_rows: list[dict]):
    if not vk_rows:
        return {"ok": False, "reason": "No selected Vault Keepers"}

    service_days = get_service_duration_days()
    ida_n = _entry_int(S.entry_n, len(vk_rows))
    ida_t = _entry_int(S.entry_t, min(len(vk_rows), max(1, ida_n)))
    piece_count = max(1, ida_n)
    threshold = max(1, min(piece_count, ida_t))
    piece_sizes, piece_size_source = _estimated_vk_piece_sizes(piece_count, threshold)
    if not piece_sizes:
        return {
            "ok": False,
            "reason": piece_size_source,
            "vk_count": len(vk_rows),
        }
    piece_count = len(piece_sizes)

    su_to_wei = _current_su_to_wei()
    assignments = []
    escrow_wei = 0
    for idx, piece_size in enumerate(piece_sizes, start=1):
        row = vk_rows[(idx - 1) % len(vk_rows)]
        fee_su = int(row.get("storageFee", 0) or 0)
        storage_gb = max(0, int(piece_size)) / 1_000_000_000
        piece_wei = _vk_storage_price_wei(fee_su, piece_size, service_days, su_to_wei)
        escrow_wei += piece_wei
        assignments.append({
            "piece": idx,
            "address": str(row.get("address", "")),
            "fee_su": fee_su,
            "piece_size": int(piece_size),
            "storage_gb": storage_gb,
            "escrow_wei": piece_wei,
        })

    gas_price = _fixed_gas_price_wei()
    gas_rows = _vk_gas_rows(piece_count)
    total_gas = sum(row["total_gas"] for row in gas_rows)
    do_gas = sum(row["total_gas"] for row in gas_rows if row["payer"] == "DO")
    total_gas_wei = total_gas * gas_price
    do_gas_wei = do_gas * gas_price

    return {
        "ok": True,
        "vk_count": len(vk_rows),
        "piece_count": piece_count,
        "threshold": threshold,
        "service_days": service_days,
        "piece_size_source": piece_size_source,
        "su_to_wei": su_to_wei,
        "gas_price_wei": gas_price,
        "vk_escrow_wei": escrow_wei,
        "vk_gas_rows": gas_rows,
        "vk_gas": total_gas,
        "vk_gas_wei": total_gas_wei,
        "vk_do_gas_wei": do_gas_wei,
        "vk_do_outlay_wei": escrow_wei + do_gas_wei,
        "vk_workflow_footprint_wei": escrow_wei + total_gas_wei,
        "assignments": assignments,
    }


def _log_selected_vk_cost_estimate(estimate=None):
    estimate = estimate or {"ok": False, "reason": "No estimate"}
    if not estimate.get("ok"):
        L.log(f"Vault Keeper ETH estimate unavailable: {estimate.get('reason', 'unknown reason')}")
        return

    L.log("=== Selected Vault Keeper ETH estimate ===")
    L.log(f"selected VKs: {estimate['vk_count']}")
    L.log(f"IDA pieces: {estimate['piece_count']}  threshold: {estimate['threshold']}")
    L.log(f"service days: {estimate['service_days']}")
    L.log(f"piece size source: {estimate['piece_size_source']}")
    L.log(f"SU->wei rate: {estimate['su_to_wei']}")
    L.log(f"fixed gas price: {estimate['gas_price_wei']} wei")
    L.log(f"VK escrow/storage estimate: {_format_wei_as_eth(estimate['vk_escrow_wei'])}")
    L.log(
        f"VK tx gas estimate: {estimate['vk_gas']:,} gas = "
        f"{_format_wei_as_eth(estimate['vk_gas_wei'])}"
    )
    L.log(f"VK estimated DO outlay (escrow + DO tx gas): {_format_wei_as_eth(estimate['vk_do_outlay_wei'])}")
    L.log(
        f"VK workflow footprint (escrow + all DO/VK gas): "
        f"{_format_wei_as_eth(estimate['vk_workflow_footprint_wei'])}"
    )
    for row in estimate["vk_gas_rows"]:
        L.log(_format_vk_gas_row(row, estimate["gas_price_wei"]))
    for item in estimate["assignments"]:
        L.log(
            f"  escrow piece {item['piece']}: VK {item['address'][:14]} "
            f"fee={item['fee_su']} SU/GB/day size={_format_gb(item['storage_gb'])} GB "
            f"= {_format_wei_as_eth(item['escrow_wei'])}"
        )
    L.log("VK estimates use selected VK storage fees and recent transaction_dashboard logs.")


def _estimated_vk_piece_sizes(piece_count: int, threshold: int):
    source = str(S.selected_file_var.get()).strip() if S.selected_file_var is not None else ""
    if not source or source == "No file selected":
        return [], "Select a file before estimating VK storage cost"
    if source and source != "No file selected":
        try:
            source_path = Path(source).expanduser()
            if source_path.is_file():
                source_size = source_path.stat().st_size
                aes_overhead = 48 if _aes_enabled() else 0
                ida_input_size = source_size + aes_overhead
                share_payload_size = math.ceil(ida_input_size / max(1, int(threshold)))
                share_size = share_payload_size + 16
                aes_note = " with AES overhead" if aes_overhead else ""
                return [share_size] * int(piece_count), (
                    f"selected file {source_path.name}{aes_note}: estimated IDA piece size "
                    f"{share_size:,} bytes"
                )
        except Exception:
            pass

    return [], "Selected file is not available for VK storage cost estimate"


def _aes_enabled() -> bool:
    try:
        return bool(S.chk_var is not None and S.chk_var.get())
    except Exception:
        return False


def _vk_storage_price_wei(fee_su_per_gb_day: int, size_bytes: int, service_days: int, su_to_wei: int) -> int:
    numerator = (
        int(fee_su_per_gb_day)
        * max(0, int(size_bytes))
        * max(0, int(service_days))
        * int(su_to_wei)
    )
    denominator = 1_000_000_000
    if numerator <= 0:
        return 0
    return (numerator + denominator - 1) // denominator


def _format_gb(value: float) -> str:
    return f"{float(value):.6f}".rstrip("0").rstrip(".")


def _format_bytes_limit(size_bytes: int) -> str:
    size = int(size_bytes or 0)
    if size <= 0:
        return "∞"
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024.0
    if unit == "B":
        return f"{int(value)} {unit}"
    return f"{value:.1f} {unit}"


def _registry_has_function(function_name: str) -> bool:
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        return False
    try:
        return any(
            item.get("type") == "function" and item.get("name") == function_name
            for item in getattr(registry, "abi", [])
            if isinstance(item, dict)
        )
    except Exception:
        return False


def _get_vk_max_piece_size(vk_addr: str) -> int:
    if not _registry_has_function("getVaultKeeperCapacity"):
        return 0
    try:
        checksum = C.w3.to_checksum_address(vk_addr)
        return int(C.vault_keeper_registry.functions.getVaultKeeperCapacity(checksum).call())
    except Exception as exc:
        L.log(f"[vk] capacity lookup failed for {vk_addr}: {exc}")
        return 0


def _current_estimated_vk_piece_size() -> int:
    try:
        piece_count = max(1, _entry_int(S.entry_n, 1))
        threshold = max(1, min(piece_count, _entry_int(S.entry_t, piece_count)))
        piece_sizes, _source = _estimated_vk_piece_sizes(piece_count, threshold)
        return max(int(x) for x in piece_sizes) if piece_sizes else 0
    except Exception:
        return 0


def _vk_gas_rows(piece_count: int):
    count = max(1, int(piece_count))
    # The upload path always commits the signed transfer/registration deadline
    # through V2. Sampling the legacy entry points understates the real
    # transaction and can make production cost estimates misleading.
    escrow_fn = "depositEscrowBatchV2" if count >= 2 else "depositEscrowV2"
    escrow_label = "VK escrow batch deposit" if count >= 2 else "VK escrow deposit"
    escrow_fallback = 749_017 if count >= 2 else 200_000
    escrow_fallback_count = 6 if count >= 2 else 1
    return [
        _vk_gas_row(
            "DO", "data_owner", "DataVault", "createV2BatchWithCids",
            1, 2_423_078, "Upload batch / piece roots",
            record_count=count, fallback_record_count=6,
        ),
        _vk_gas_row(
            "DO", "data_owner", "VKEscrow", escrow_fn,
            1, escrow_fallback, escrow_label,
            record_count=count, fallback_record_count=escrow_fallback_count,
        ),
        _vk_gas_row(
            "Vault Keeper", "vault_keeper", "FileRegistrationSC", "registerFileStorage",
            count, 234_502, "File storage registration",
        ),
    ]


def _vk_gas_row(
    payer: str,
    facility: str,
    contract_name: str,
    function_name: str,
    multiplier: int,
    fallback_gas: int,
    label: str,
    record_count: int | None = None,
    fallback_record_count: int | None = None,
):
    gas, total_gas, source, exact_sample = _vk_transaction_gas_estimate(
        facility,
        contract_name,
        function_name,
        multiplier,
        fallback_gas,
        record_count=record_count,
        fallback_record_count=fallback_record_count,
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


def _vk_transaction_gas_estimate(
    facility: str,
    contract_name: str,
    function_name: str,
    multiplier: int,
    fallback_gas: int,
    record_count: int | None = None,
    fallback_record_count: int | None = None,
):
    values = _vk_transaction_gas_values()
    key = (facility.lower(), contract_name.lower(), function_name.lower())
    multiplier = max(1, int(multiplier))
    samples = values.get(key) or []
    if samples:
        if record_count is not None and multiplier == 1:
            count = max(1, int(record_count))
            exact = [item for item in samples if int(item.get("record_count", 0) or 0) == count]
            if exact:
                gas = int(exact[-1]["gas"])
                return gas, gas, "latest transaction_dashboard log", True
            counted = [item for item in samples if int(item.get("record_count", 0) or 0) > 0]
            if counted:
                latest = counted[-1]
                sample_count = max(1, int(latest.get("record_count", 0) or 0))
                gas = max(1, math.ceil(int(latest["gas"]) * count / sample_count))
                return gas, gas, f"latest transaction_dashboard log scaled from {sample_count} records", False

        if len(samples) >= multiplier:
            recent = samples[-multiplier:]
            total_gas = sum(int(item["gas"]) for item in recent)
            avg_gas = int(round(total_gas / multiplier))
            source = "latest transaction_dashboard log" if multiplier == 1 else f"latest {multiplier} transaction_dashboard logs"
            return avg_gas, total_gas, source, True

        latest_gas = int(samples[-1]["gas"])
        return latest_gas, latest_gas * multiplier, "latest transaction_dashboard log scaled", False

    fallback_gas = int(fallback_gas)
    if record_count is not None and fallback_record_count:
        count = max(1, int(record_count))
        sample_count = max(1, int(fallback_record_count))
        fallback_gas = max(1, math.ceil(fallback_gas * count / sample_count))
        return fallback_gas, fallback_gas * multiplier, f"fallback baseline scaled from {sample_count} records", False
    return fallback_gas, fallback_gas * multiplier, "fallback baseline", False


def _vk_transaction_gas_values():
    global _VK_TX_GAS_VALUES_CACHE
    if _VK_TX_GAS_VALUES_CACHE is not None:
        return _VK_TX_GAS_VALUES_CACHE

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
                        "order": row_order,
                        "gas": gas,
                        "record_count": _int_or_zero(row.get("record_count") or row.get("value_count")),
                    })
        except Exception:
            continue

    for values in grouped.values():
        values.sort(key=lambda item: item["order"])

    _VK_TX_GAS_VALUES_CACHE = grouped
    return _VK_TX_GAS_VALUES_CACHE


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


def _entry_int(entry, fallback: int) -> int:
    try:
        return int(entry.get())
    except Exception:
        return int(fallback)


def _fixed_gas_price_wei() -> int:
    try:
        return C.gas_price_wei()
    except Exception:
        return 1_000_000


def _int_or_zero(value) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _format_vk_gas_row(row, gas_price_wei: int) -> str:
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


def _vk_estimate_status_reason(estimate) -> str:
    reason = str((estimate or {}).get("reason") or "VK estimate unavailable")
    if "Select a file" in reason:
        return "select file for VK cost"
    if len(reason) > 42:
        return reason[:39] + "..."
    return reason


def _format_gas_average(value: float) -> str:
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,.1f}"


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


def _set_entry_value(entry, value: int | str) -> None:
    if entry is None:
        return
    entry.delete(0, tk.END)
    entry.insert(0, str(value))


def set_auto_defaults(
    service_days: int = 30,
    guardian_t: int = 3,
    ida_n: int = 6,
    ida_t: int = 4,
    guardian_n: int | None = None,
) -> None:
    """Apply the auto-upload defaults to the visible dashboard controls."""
    _set_entry_value(S.entry_service_days, service_days)
    if guardian_n is not None:
        _set_entry_value(S.entry_guardian_n, guardian_n)
    _set_entry_value(S.entry_guardian_t, guardian_t)
    _set_entry_value(S.entry_n, ida_n)
    _set_entry_value(S.entry_t, ida_t)
    refresh_guardian_suitability()
    refresh_ida_info()


def _min_guardian_stake_wei() -> int:
    meta = D.meta()
    if "guardianMinStake" in meta:
        return int(meta["guardianMinStake"] or 0)
    try:
        if C.guardian_registry is not None:
            return int(C.guardian_registry.functions.minStake().call())
    except Exception:
        pass
    try:
        return int(getattr(C.config, "MIN_GUARDIAN_STAKE_WEI", 0) or 0)
    except Exception:
        return 0


def _latest_sign_of_life(*timestamps: int) -> int:
    """Newest on-chain sign of life for a participant.

    The registry `lastHeartbeat` only moves when a registry-touching tx is sent
    -- for Guardians that is nothing but an explicit heartbeat() call -- so a
    node doing real work still reads as stale.  Until real periodic heartbeats
    exist, treat the newest of heartbeat / ReputationManager activity / last
    proof as the heartbeat.  The raw values stay on the row for display.
    """
    return max((int(ts or 0) for ts in timestamps), default=0)


def _freshness_score(ts: int, stale_after_seconds: int = 2 * 86400) -> float:
    if not ts:
        return 0.0
    age = max(0, int(time.time()) - int(ts))
    return max(0.0, 1.0 - min(age, stale_after_seconds) / stale_after_seconds)


def _cost_score(value: int, low: int, high: int) -> float:
    if high <= low:
        return 1.0
    return 1.0 - ((int(value) - low) / (high - low))


def _vk_location_parts(row: dict) -> tuple[str, str, bool]:
    """Return (country, city, is_localhost) from a VK location string."""
    loc = str(row.get("location") or "").strip()
    if not loc:
        return "", "", False
    if loc.lower() == "localhost":
        return "Localhost", "", True
    parts = [p.strip() for p in loc.split(",", 1)]
    country = parts[0] if parts else ""
    city = parts[1] if len(parts) > 1 else ""
    return country, city, False


def _vk_location_score(row: dict, chosen_rows: list[dict]) -> float:
    """Reward geographically useful VKs, with a strong preference for diversity."""
    country, city, is_localhost = _vk_location_parts(row)
    lat = float(row.get("latitude") or 0.0)
    lon = float(row.get("longitude") or 0.0)
    has_geo = bool(country and (is_localhost or lat != 0.0 or lon != 0.0))
    if not has_geo:
        return 0.25
    if not chosen_rows:
        return 0.65 if is_localhost else 1.0

    chosen_parts = [_vk_location_parts(r) for r in chosen_rows]
    chosen_countries = {c for c, _city, _local in chosen_parts if c}
    chosen_city_keys = {(c, ct) for c, ct, _local in chosen_parts if c or ct}

    if is_localhost:
        return 0.50 if "Localhost" not in chosen_countries else 0.35
    if country not in chosen_countries:
        return 1.0
    if (country, city) not in chosen_city_keys and city:
        return 0.75
    return 0.45


def select_best_guardians(count: int = 5, threshold: int = 3, service_days: int = 30) -> list[str]:
    """Select the best active Guardians for a new auto-created policy."""
    set_auto_defaults(service_days=service_days, guardian_t=threshold, guardian_n=count)
    # From the network directory: usually a 304 from discovery, never a chain
    # read per guardian.
    load_guardians()

    min_stake = _min_guardian_stake_wei()
    candidates = []
    for row in S.guardian_display_records:
        stake = int(row.get("stake", 0) or 0)
        max_days = int(row.get("max_service_days", 0) or 0)
        if not row.get("active"):
            continue
        if max_days > 0 and service_days > max_days:
            continue
        if min_stake and stake < min_stake:
            continue
        candidates.append(row)

    if len(candidates) < count:
        raise RuntimeError(
            f"Auto-select needs {count} Guardians eligible for {service_days} days; found {len(candidates)}."
        )

    min_cost = min(int(r.get("total_su", 0) or 0) for r in candidates)
    max_cost = max(int(r.get("total_su", 0) or 0) for r in candidates)

    def _score(row: dict) -> tuple:
        rep = int(row.get("reputation", 0) or 0) / 10000.0
        total_su = int(row.get("total_su", 0) or 0)
        cost = _cost_score(total_su, min_cost, max_cost)
        failures = int(row.get("failed", 0) or 0)
        complaints = int(row.get("dkg_complaints", 0) or 0)
        proof_penalties = int(row.get("total_proof_penalties", 0) or 0)
        pre_bad = int(row.get("pre_bad_partial", 0) or 0)
        penalty = min(1.0, (failures * 0.08) + (complaints * 0.20) + (proof_penalties * 0.08) + (pre_bad * 0.12))
        reliability = max(0.0, 1.0 - penalty)
        stake_ratio = 1.0
        if min_stake:
            stake_ratio = min(int(row.get("stake", 0) or 0) / min_stake, 3.0) / 3.0
        freshness = _freshness_score(
            _latest_sign_of_life(
                row.get("last_sign_of_life", 0),
                row.get("last_proof_at", 0),
                row.get("last_activity_at", 0),
                row.get("last_heartbeat", 0),
            )
        )
        score = (rep * 0.50) + (reliability * 0.20) + (cost * 0.20) + (stake_ratio * 0.05) + (freshness * 0.05)
        return (score, -total_su, int(row.get("reputation", 0) or 0), str(row.get("address", "")).lower())

    # Best first; the ones actually chosen are confirmed on chain, and a
    # guardian the chain disagrees about is replaced by the next best.
    #
    # The chain is asked about several guardians at once. One after another it
    # was two round trips each in series -- the single slowest thing the
    # window did at start-up -- and the checks are independent, so the order
    # of the answers cannot change which guardians are chosen: the ranked list
    # is still walked in order below.
    # A bond reservation can lower stake after the directory snapshot. A
    # refreshed row must be ranked again before it may influence selection.
    for selection_pass in range(2):
        ranked = sorted(candidates, key=_score, reverse=True)
        stakes = {id(row): int(row.get("stake", 0) or 0) for row in ranked}
        verdicts = _verify_guardians_in_parallel(ranked, count)
        refreshed = any(
            not verdicts.get(id(row), (True, ""))[0]
            and verdicts.get(id(row), (True, ""))[1].startswith("stake overstated")
            and stakes[id(row)] != int(row.get("stake", 0) or 0)
            for row in ranked
        )
        if not refreshed or selection_pass:
            break
    chosen_rows = []
    refused: list[str] = []
    for row in ranked:
        if len(chosen_rows) >= count:
            break
        ok, reason = verdicts.get(id(row)) or _verify_guardian_before_use(row)
        if not ok:
            refused.append(f"{str(row.get('address', ''))[:14]} ({reason})")
            continue
        chosen_rows.append(row)
    if refused:
        L.log(f"[auto] skipped {len(refused)} Guardian(s) the chain disagreed about: {', '.join(refused[:5])}")
    if len(chosen_rows) < count:
        raise RuntimeError(
            f"Only {len(chosen_rows)} of {count} Guardians passed an on-chain check at selection time"
            + (f"; skipped: {', '.join(refused[:5])}" if refused else "")
        )
    chosen = [C.w3.to_checksum_address(r["address"]) for r in chosen_rows]

    clear_guardian_selection()
    if _guardian_widget_is_table() and S.guardians_listbox is not None:
        for addr in chosen:
            iid = addr.lower()
            if S.guardians_listbox.exists(iid):
                S.guardians_listbox.selection_add(iid)
        first_iid = chosen[0].lower()
        if S.guardians_listbox.exists(first_iid):
            S.guardians_listbox.focus(first_iid)
            S.guardians_listbox.see(first_iid)
    elif S.guardians_listbox is not None:
        wanted = {a.lower() for a in chosen}
        for i, addr in enumerate(S.guardian_rows):
            if addr.lower() in wanted:
                S.guardians_listbox.selection_set(i)
        first_index = next((i for i, addr in enumerate(S.guardian_rows) if addr.lower() == chosen[0].lower()), None)
        if first_index is not None:
            S.guardians_listbox.see(first_index)

    S.staged_guardians = chosen
    if S.staged_g_status_var is not None:
        S.staged_g_status_var.set(f"Auto staged: {len(chosen)} Guardian(s), t={threshold}")
    L.log(f"[auto] selected {len(chosen)} Guardians for {service_days} days (t={threshold})")
    for row in chosen_rows:
        L.log(
            f"[auto] G {row['address']} rep={row['reputation']} totalSU={row['total_su']} "
            f"stake={row['stake']} proofPenalties={row.get('total_proof_penalties', 0)}"
        )
    return chosen


def select_existing_policy_guardians(policy_guardians: list[str], threshold: int) -> list[str]:
    chosen = normalize_guardian_list(policy_guardians)
    _set_entry_value(S.entry_guardian_n, len(chosen))
    _set_entry_value(S.entry_guardian_t, threshold)
    S.staged_guardians = chosen
    select_policy_guardians_in_listbox(chosen)
    if S.staged_g_status_var is not None:
        S.staged_g_status_var.set(f"Existing policy: {len(chosen)} Guardian(s), t={threshold}")
    return chosen


def _vk_row_from_directory(entry: dict, min_vk_stake: int, current_piece_size: int,
                           duration_days: int, margin_bytes: int, ledger: bool = True) -> dict:
    """One directory keeper as the row dict the VK table and selection use.

    Everything comes from discovery's directory: chain facts read by discovery
    through NetworkDirectoryReader, plus the keeper's multiaddr and location
    from its own announcement. Nothing here is read from the chain or from the
    keeper by this DO; the keepers finally chosen are checked by
    _verify_vk_before_paying.
    """
    now = int(time.time())
    address = str(entry.get("address", ""))
    try:
        address = C.w3.to_checksum_address(address)
    except Exception:
        pass
    peer_id = _normalize_registry_peer(str(entry.get("peerId", "")))
    multiaddr = str(entry.get("multiaddr", "") or "")
    storage_fee = int(entry.get("storageFee", 0) or 0)
    stake_wei = int(entry.get("stake", 0) or 0)
    active = bool(entry.get("active", 0))
    last_heartbeat = int(entry.get("lastHeartbeat", 0) or 0)
    suspended_until = int(entry.get("suspendedUntil", 0) or 0)
    max_service_days = int(entry.get("maxServiceDays", 0) or 0)
    max_piece_size_bytes = int(entry.get("maxPieceSizeBytes", 0) or 0)
    last_activity_at = int(entry.get("lastActivityAt", 0) or 0)
    last_proof_at = int(entry.get("lastProofAt", 0) or 0)

    capacity_suitable = (
        max_piece_size_bytes == 0
        or current_piece_size == 0
        or current_piece_size <= max_piece_size_bytes
    )
    suspended = bool(suspended_until and suspended_until > now)
    eligible = bool(active and stake_wei >= min_vk_stake and not suspended and capacity_suitable)
    reason = ""
    if not active:
        reason = "inactive"
    elif suspended:
        reason = "suspended"
    elif stake_wei < min_vk_stake:
        reason = f"stake below minimum ({stake_wei} < {min_vk_stake})"
    elif not capacity_suitable:
        reason = (
            f"estimated piece {_format_bytes_limit(current_piece_size)} exceeds "
            f"VK max {_format_bytes_limit(max_piece_size_bytes)}"
        )

    admission_closed_registry = bool(entry.get("admissionClosed", 0))
    # Same rule as VaultKeeperRegistry.isAdmissionOpen: eligible and not closed.
    admission_open = bool(active and not suspended and stake_wei >= min_vk_stake
                          and not admission_closed_registry)
    free_bytes = int(entry.get("conservativeFreeBytes", 0) or 0)
    admission_free_bytes = int(entry.get("reportedFreeBytes", 0) or 0) or free_bytes
    admission_allocatable_bytes = admission_free_bytes if admission_free_bytes > margin_bytes else 0

    row = {
        "address": address,
        "peerId": peer_id,
        "multiaddr": multiaddr,
        "discoverySource": "directory",
        "location": str(entry.get("location", "") or ""),
        "latitude": float(entry.get("lat", 0.0) or 0.0),
        "longitude": float(entry.get("lon", 0.0) or 0.0),
        "metadataURI": "",
        "storageFee": storage_fee,
        "stake": stake_wei,
        "reputation": int(entry.get("reputation", 0) or 0),
        "penaltyPoints": int(entry.get("penaltyPoints", 0) or 0),
        "disputeCount": int(entry.get("disputeCount", 0) or 0),
        "completedPieces": int(entry.get("completedPieces", 0) or 0),
        "lastProofAt": last_proof_at,
        "active": active,
        "eligible": eligible,
        "eligibilityReason": reason,
        "minStake": min_vk_stake,
        "suspendedUntil": suspended_until,
        "lastHeartbeat": last_heartbeat,
        "lastActivityAt": last_activity_at,
        "lastSignOfLife": _latest_sign_of_life(last_heartbeat, last_activity_at, last_proof_at),
        "maxServiceDays": max_service_days,
        "maxPieceSizeBytes": max_piece_size_bytes,
        "capacitySuitable": capacity_suitable,
        "durationSuitable": max_service_days == 0 or duration_days <= max_service_days,
        "totalCapacityBytes": int(entry.get("declaredBytes", 0) or 0),
        "usedBytes": int(entry.get("registeredDataBytes", 0) or 0),
        "freeBytes": free_bytes,
        "admissionClosedRegistry": admission_closed_registry,
        "admissionOpen": admission_open,
        "admissionClosureReasonCode": int(entry.get("admissionClosureReason", 0) or 0),
        "admissionClosedLocal": False,
        "admissionFreeBytes": admission_free_bytes,
        "admissionMarginBytes": margin_bytes,
        "admissionAllocatableBytes": admission_allocatable_bytes,
    }
    # The keeper's capacity ledger, so a caller can ask "has this keeper proved
    # everything it says it holds?". Absent when discovery has no
    # CapacityProofSC configured: zeros read from nowhere must never be
    # readable as "converged", so the keys stay out entirely.
    if ledger:
        row.update({
            "registeredFreeBytes": int(entry.get("registeredFreeBytes", 0) or 0),
            "registeredDataBytes": int(entry.get("registeredDataBytes", 0) or 0),
            "provedFreeBytes": int(entry.get("provedFreeBytes", 0) or 0),
            "provedDataBytes": int(entry.get("provedDataBytes", 0) or 0),
            "capacityProofFresh": bool(entry.get("capacityProofFresh", 0)),
        })
    return row


# Live capacity telemetry each keeper reports about itself. The chain's capacity
# ledger only moves when a capacity proof lands (once per proof period), so it
# says nothing useful about free space right now -- on a fresh chain it is zero
# for every keeper. Admission and free space are therefore taken from the
# keeper itself, exactly as the table did before the directory existed.
_VK_TELEMETRY_KEYS = (
    "totalCapacityBytes", "usedBytes", "freeBytes", "admissionClosedLocal",
    "admissionFreeBytes", "admissionMarginBytes", "admissionAllocatableBytes",
)


def _apply_live_vk_info(row: dict, vk_info: dict) -> None:
    """Fill a row's capacity and admission fields from the keeper's own report."""
    disk_free = int(vk_info.get("freeBytes", 0) or 0)
    total_capacity = int(vk_info.get("totalCapacityBytes", 0) or 0)
    used = int(vk_info.get("usedBytes", 0) or 0)
    # A keeper reports the free space of the disk it sits on, which is the same
    # number for every keeper sharing one machine -- and is not what it can
    # accept. Free room is what is left inside its declared capacity, and the
    # disk is only an upper bound on that.
    if total_capacity > 0:
        free_bytes = max(0, total_capacity - used)
        if disk_free > 0:
            free_bytes = min(free_bytes, disk_free)
    else:
        free_bytes = disk_free
    admission_free = int(vk_info.get("admissionFreeBytes") or free_bytes or 0)
    admission_margin = int(vk_info.get("admissionMarginBytes", 0) or 0)
    closed_local = bool(vk_info.get("admissionClosed", False))
    row.update({
        "totalCapacityBytes": total_capacity,
        "usedBytes": used,
        "freeBytes": free_bytes,
        "admissionClosedLocal": closed_local,
        "admissionFreeBytes": admission_free,
        "admissionMarginBytes": admission_margin,
        "admissionAllocatableBytes": int(vk_info.get(
            "admissionAllocatableBytes",
            admission_free if admission_free > admission_margin else 0,
        ) or 0),
        # Open only when the registry says open and the keeper agrees.
        "admissionOpen": bool(row.get("admissionOpen")) and not closed_local,
    })


def _fill_live_vk_info(rows: list[dict]) -> None:
    """Ask every listed keeper for its live capacity, in parallel."""
    from concurrent.futures import ThreadPoolExecutor
    from .do_vaultmesh import get_vk_info

    reachable = [row for row in rows if row.get("multiaddr")]
    if not reachable:
        return
    with ThreadPoolExecutor(max_workers=min(32, len(reachable))) as pool:
        infos = list(pool.map(lambda r: get_vk_info(r["multiaddr"]) or {}, reachable))
    for row, info in zip(reachable, infos):
        _apply_live_vk_info(row, info)


def _vk_rows_from_directory() -> list[dict]:
    """Every keeper in the network, as table rows. Raises if no directory at all.

    Chain facts come from discovery's directory; free space and admission come
    live from each keeper, as they always did.
    """
    if not D.refresh():
        # Only once the directory has actually failed: a local copy from an
        # earlier run is enough to work from, and refusing before trying would
        # take that away.
        from . import ft_discovery

        raise RuntimeError(ft_discovery.problem(C.config) or (
            "No discovery node answered and no local copy of the network "
            "directory exists. The servers listed in config.json did not "
            "reply; \"Update network settings\" in the tray fetches a current "
            "list."
        ))
    meta = D.meta()
    min_vk_stake = _minimum_vk_stake_wei()
    piece_size = _current_estimated_vk_piece_size()
    duration_days = get_service_duration_days()
    margin = int(meta.get("admissionMarginBytes", 0) or 0)
    ledger = bool((meta.get("sources") or {}).get("capacityProof"))
    rows = [
        _vk_row_from_directory(entry, min_vk_stake, piece_size, duration_days, margin, ledger)
        for entry in D.keepers()
    ]
    _fill_live_vk_info(rows)
    return rows


# Asking every keeper for its live capacity is the slowest thing the window
# does -- one network round trip per keeper, a few seconds in all. Start-up
# did it twice: once to fill the table, then again inside auto-selection.
_VK_ROWS_MAX_AGE_SECONDS = 20.0
_vk_rows_cache: tuple[float, list[dict]] | None = None
_vk_rows_lock = threading.Lock()


def fetch_vk_rows(max_age: float = 0.0) -> list[dict]:
    """The keeper rows, re-used when they were fetched *max_age* seconds ago.

    Reads nothing from the window, so it is safe to call from a worker thread
    -- which is how start-up keeps the window alive while the keepers load.
    """
    global _vk_rows_cache
    if max_age > 0:
        with _vk_rows_lock:
            cached = _vk_rows_cache
        if cached is not None and (time.time() - cached[0]) <= max_age:
            return cached[1]
    rows = _vk_rows_from_directory()
    with _vk_rows_lock:
        _vk_rows_cache = (time.time(), rows)
    return rows


# A directory value may be up to a few minutes old, so a chosen keeper's or
# guardian's reputation on chain may have moved a little. More than this, and
# the directory overstated it -- stale or dishonest -- and the entry is refused.
_REPUTATION_DRIFT_ALLOWED = 0.10


def _reputation_overstated(claimed: int, on_chain: int) -> bool:
    return claimed > 0 and on_chain < claimed * (1.0 - _REPUTATION_DRIFT_ALLOWED)


def _vk_entry_from_chain(checksum: str) -> dict:
    """Every VK-table field for one keeper, read from the chain itself.

    Same fields, same contracts and the same fallbacks as NetworkDirectoryReader,
    so the row built from it can be compared with the directory's row one to
    one. About a dozen direct lookups by address; used for the few keepers
    chosen. Multiaddr and location are not chain data and are not set here.
    """
    registry = C.vault_keeper_registry
    vk = registry.functions.getVaultKeeper(checksum).call()
    entry = {
        "address": checksum,
        "peerId": str(registry.functions.vaultKeeperPeerId(checksum).call()),
        "storageFee": int(vk[1]), "stake": int(vk[2]), "active": bool(vk[3]),
        "registeredAt": int(vk[4]), "lastHeartbeat": int(vk[5]),
        "suspendedUntil": int(vk[6]), "maxServiceDays": int(vk[7]),
        "maxPieceSizeBytes": int(registry.functions.maxPieceSizeBytes(checksum).call()),
        "admissionClosed": bool(registry.functions.admissionClosed(checksum).call()),
        "admissionClosureReason": int(registry.functions.admissionClosureReason(checksum).call()),
        "reportedFreeBytes": int(registry.functions.reportedAdmissionFreeBytes(checksum).call()),
        "reputation": 0, "penaltyPoints": 0, "disputeCount": 0, "missedProofs": 0,
        "lastActivityAt": 0, "completedPieces": 0, "lastProofAt": 0,
        "declaredBytes": 0, "registeredFreeBytes": 0, "registeredDataBytes": 0,
        "provedFreeBytes": 0, "provedDataBytes": 0, "conservativeFreeBytes": 0,
        "capacityProofFresh": False,
    }
    if getattr(C, "reputation_manager", None) is not None:
        stats = C.reputation_manager.functions.getVKStats(checksum).call()
        entry.update({
            "reputation": int(stats[0]), "penaltyPoints": int(stats[1]),
            "disputeCount": int(stats[2]), "missedProofs": int(stats[4]),
            "lastActivityAt": int(stats[6]),
        })
    if getattr(C, "vk_escrow", None) is not None:
        entry["completedPieces"] = int(C.vk_escrow.functions.completedPieces(checksum).call())
    if getattr(C, "storage_proof_sc", None) is not None:
        entry["lastProofAt"] = int(C.storage_proof_sc.functions.lastProofAt(checksum).call())
    if getattr(C, "capacity_proof_sc", None) is not None:
        acct = C.capacity_proof_sc.functions.capacityAccountingOf(checksum).call()
        entry.update({
            "declaredBytes": int(acct[0]), "registeredFreeBytes": int(acct[1]),
            "registeredDataBytes": int(acct[2]), "provedFreeBytes": int(acct[3]),
            "provedDataBytes": int(acct[4]), "conservativeFreeBytes": int(acct[7]),
            "capacityProofFresh": bool(acct[9]),
        })
    return entry


def _vk_listing_mismatch(listed: dict, chain: dict) -> str:
    """A listed figure better for the keeper than the chain's, or ""."""
    if _reputation_overstated(int(listed.get("reputation", 0) or 0), int(chain["reputation"])):
        return f"reputation overstated ({listed.get('reputation')} listed, {chain['reputation']} on chain)"
    if int(listed.get("storageFee", 0) or 0) < int(chain["storageFee"]):
        return f"fee understated ({listed.get('storageFee')} listed, {chain['storageFee']} on chain)"
    if int(listed.get("stake", 0) or 0) > int(chain["stake"]):
        return f"stake overstated ({listed.get('stake')} listed, {chain['stake']} on chain)"
    for key in ("penaltyPoints", "disputeCount"):
        if int(listed.get(key, 0) or 0) < int(chain[key]):
            return f"{key} understated ({listed.get(key)} listed, {chain[key]} on chain)"
    for key in ("completedPieces", "lastProofAt", "lastActivityAt", "lastHeartbeat"):
        if int(listed.get(key, 0) or 0) > int(chain[key]):
            return f"{key} overstated ({listed.get(key)} listed, {chain[key]} on chain)"
    return ""


def _verify_vk_before_paying(
    row: dict, required_piece_size: int | None = None, service_days: int | None = None
) -> tuple[bool, str]:
    """Confirm one keeper against the chain, right before storing and paying.

    Shortlisting runs on the discovery directory, which comes from a party
    that is not trusted: it can be stale, or lie -- overstate a reputation,
    understate a fee, or point a keeper's address at a machine it runs.

    So for the keepers actually chosen, every field is read again from the
    chain: the keeper must be registered, eligible (active, unsuspended,
    minimum stake), open for admission, available for the service days and
    able to take the piece size; no listed figure may be better than the
    chain's (reputation within the allowed drift); and the address used is
    the keeper's own signed record, matched to its on-chain endpoint hash.
    On success the row is overwritten with the chain's values. Direct lookups
    by address only, so the cost is the same on a ten-year-old chain as on a
    new one, and it scales with the keepers picked, not the network.
    """
    registry = C.vault_keeper_registry
    if registry is None:
        return False, "registry not configured"

    address = str(row.get("address", "")).strip()
    if not address:
        return False, "no address"

    try:
        checksum = C.w3.to_checksum_address(address)
    except Exception:
        return False, "invalid address"

    piece = _current_estimated_vk_piece_size() if required_piece_size is None else int(required_piece_size)
    days = get_service_duration_days() if service_days is None else int(service_days)
    try:
        if not bool(registry.functions.isRegisteredVaultKeeper(checksum).call()):
            return False, "not registered"
        if not bool(registry.functions.isAdmissionOpen(checksum).call()):
            # isAdmissionOpen is the registry's own rule: active, unsuspended,
            # minimum stake, admission not closed.
            vk = registry.functions.getVaultKeeper(checksum).call()
            if not bool(vk[3]):
                return False, "inactive"
            if int(vk[6]) > int(time.time()):
                return False, "suspended"
            return False, "admission closed"
        chain = _vk_row_from_directory(
            _vk_entry_from_chain(checksum),
            int(registry.functions.minimumVaultKeeperStake().call()),
            piece,
            days,
            int(registry.functions.defaultAdmissionMarginBytes().call()),
            ledger=getattr(C, "capacity_proof_sc", None) is not None,
        )
    except Exception as exc:
        # Unable to confirm is not confirmation. Refusing here costs one
        # candidate; paying an unverified keeper costs the escrow.
        return False, f"chain check failed: {exc}"

    if not chain["eligible"]:
        return False, chain["eligibilityReason"] or "not eligible on chain"
    if not chain["admissionOpen"]:
        return False, "admission closed"
    if not chain["durationSuitable"]:
        return False, f"not available for {days} days (max {chain['maxServiceDays']} on chain)"
    # Free space is not checked here: the chain only learns it at each capacity
    # proof. Selection already used the keeper's live report, and the keeper
    # itself refuses a piece it has no room for.
    listed_peer = _normalize_registry_peer(str(row.get("peerId", "")))
    if listed_peer != chain["peerId"]:
        return False, f"peer id differs from chain ({listed_peer or '-'} listed, {chain['peerId']} on chain)"
    mismatch = _vk_listing_mismatch(row, chain)
    if mismatch:
        return False, mismatch

    # The multiaddr in the directory is not signed, so a dishonest discovery
    # node could point a real keeper's address at a machine it runs. The
    # keeper's own signed record, matched against its on-chain endpoint hash,
    # is the address actually used.
    if not chain["peerId"]:
        return False, "no peer id on chain"
    multiaddr, _source, _loc, _lat, _lon = resolve_vk_multiaddr(chain["peerId"], checksum)
    if not multiaddr:
        return False, "no signed discovery record matching the on-chain endpoint"
    if multiaddr != row.get("multiaddr"):
        L.log(f"[auto] VK {checksum[:14]} directory multiaddr replaced by its signed record")

    # From here on every figure is the chain's. Location is not chain data;
    # it stays as discovery reported it and only ever affects the ranking.
    for key in ("location", "latitude", "longitude"):
        chain[key] = row.get(key, chain[key])
    # Live capacity telemetry is the keeper's own report, not chain data.
    for key in _VK_TELEMETRY_KEYS:
        if key in row:
            chain[key] = row[key]
    chain["admissionOpen"] = bool(chain["admissionOpen"]) and not bool(row.get("admissionClosedLocal"))
    chain["multiaddr"] = multiaddr
    chain["discoverySource"] = "chain-verified"
    row.update(chain)
    return True, "ok"


def select_best_vault_keepers(count: int = 6, threshold: int = 4, service_days: int = 30) -> list[str]:
    """Select and confirm the best eligible VK peers for auto upload."""
    _set_entry_value(S.entry_n, count)
    _set_entry_value(S.entry_t, threshold)
    refresh_ida_info()

    # Every keeper comes from discovery's network directory, with reputation,
    # proof history and capacity already in it -- no chain read per keeper.
    # With a window open the table is reloaded from it (so the selection shows
    # there); without one the rows are used directly. Nothing is paid on the
    # directory: every keeper finally chosen is checked against the chain.
    if S.vault_keepers_listbox is not None:
        # The table is still refilled, so the selection shows there, but the
        # keepers are asked again only if the last answer is stale.
        # Auto-selection runs right after start-up has just asked them, and
        # asking all over again cost seconds of a frozen window.
        load_vault_keepers(rows=fetch_vk_rows(max_age=_VK_ROWS_MAX_AGE_SECONDS))
        source_rows = list(S.vault_keeper_rows.items())
    else:
        source_rows = [
            (row["address"], row)
            for row in fetch_vk_rows(max_age=_VK_ROWS_MAX_AGE_SECONDS)
        ]

    required_piece_size = 0
    try:
        piece_sizes, _source = _estimated_vk_piece_sizes(max(1, int(count)), max(1, min(int(count), int(threshold))))
        required_piece_size = max(int(x) for x in piece_sizes) if piece_sizes else 0
    except Exception:
        required_piece_size = 0

    candidates = []
    for iid, row in source_rows:
        max_days = int(row.get("maxServiceDays", 0) or 0)
        max_piece_size = int(row.get("maxPieceSizeBytes", 0) or 0)
        if not row.get("eligible"):
            continue
        if not row.get("multiaddr"):
            continue
        if max_days > 0 and service_days > max_days:
            continue
        if required_piece_size > 0 and max_piece_size > 0 and required_piece_size > max_piece_size:
            continue
        free_bytes = int(row.get("freeBytes", 0) or 0)
        if required_piece_size > 0 and free_bytes > 0 and required_piece_size > free_bytes:
            continue
        if not row.get("admissionOpen", True):
            continue
        admission_free = int(row.get("admissionFreeBytes", 0) or free_bytes or 0)
        admission_margin = int(row.get("admissionMarginBytes", 0) or 0)
        admission_allocatable = admission_free if admission_free > admission_margin else 0
        if required_piece_size > 0 and required_piece_size > admission_allocatable:
            continue
        candidates.append((iid, row))

    if len(candidates) < count:
        capacity_note = ""
        if required_piece_size > 0:
            capacity_note = f" for estimated piece size {_format_bytes_limit(required_piece_size)}"
        raise RuntimeError(
            f"Auto-select needs {count} Vault Keepers eligible for {service_days} days{capacity_note}; found {len(candidates)}."
        )

    fees = [int(r.get("storageFee", 0) or 0) for _iid, r in candidates]
    min_fee = min(fees)
    max_fee = max(fees)
    min_stake = _minimum_vk_stake_wei()

    def _score(item: tuple[str, dict], chosen_rows: list[dict]) -> tuple:
        _iid, row = item
        rep = int(row.get("reputation", 0) or 0) / 10000.0
        fee = int(row.get("storageFee", 0) or 0)
        cost = _cost_score(fee, min_fee, max_fee)
        disputes = int(row.get("disputeCount", 0) or 0)
        penalties = int(row.get("penaltyPoints", 0) or 0)
        reliability = max(0.0, 1.0 - min(1.0, disputes * 0.15 + penalties * 0.05))
        stake_ratio = 1.0
        if min_stake:
            stake_ratio = min(int(row.get("stake", 0) or 0) / min_stake, 3.0) / 3.0
        freshness = _freshness_score(
            _latest_sign_of_life(
                row.get("lastSignOfLife", 0),
                row.get("lastProofAt", 0),
                row.get("lastActivityAt", 0),
                row.get("lastHeartbeat", 0),
            )
        )
        served = min(int(row.get("completedPieces", 0) or 0), 100) / 100.0
        location = _vk_location_score(row, chosen_rows)
        score = (
            rep * 0.35
            + reliability * 0.18
            + cost * 0.17
            + location * 0.15
            + stake_ratio * 0.05
            + freshness * 0.05
            + served * 0.05
        )
        return (score, location, -fee, int(row.get("reputation", 0) or 0), str(row.get("address", "")).lower())

    remaining = list(candidates)
    chosen_items = []
    refused: list[str] = []
    while remaining and len(chosen_items) < count:
        chosen_rows = [row for _iid, row in chosen_items]
        best = max(remaining, key=lambda item: _score(item, chosen_rows))
        remaining.remove(best)
        # Everything above this line is shortlisting on the discovery
        # directory: figures this DO did not read from the chain itself, up to
        # a few minutes old. This is the moment the DO commits to storing and
        # paying, so the few keepers it actually chose are checked against the
        # chain and their signed address records -- direct lookups by address,
        # so the cost is the same whether the chain is a day or a decade old.
        ok, reason = _verify_vk_before_paying(best[1], required_piece_size, service_days)
        if not ok:
            refused.append(f"{str(best[1].get('address', ''))[:14]} ({reason})")
            continue
        chosen_items.append(best)

    if refused:
        L.log(f"[auto] skipped {len(refused)} VK(s) the chain disagreed about: {', '.join(refused[:5])}")

    if len(chosen_items) < count:
        raise RuntimeError(
            f"Only {len(chosen_items)} of {count} Vault Keepers still passed an on-chain "
            f"check at selection time"
            + (f"; skipped: {', '.join(refused[:5])}" if refused else "")
        )

    chosen_iids = [iid for iid, _row in chosen_items]
    chosen_peers = [str(row["multiaddr"]).strip() for _iid, row in chosen_items]

    if S.vault_keepers_listbox is not None:
        S.vault_keepers_listbox.selection_remove(*S.vault_keepers_listbox.get_children())
        S.vault_keepers_listbox.selection_set(*chosen_iids)
        if chosen_iids:
            S.vault_keepers_listbox.focus(chosen_iids[0])
            S.vault_keepers_listbox.see(chosen_iids[0])
        _sync_n_from_selection()
    S.policy_vk_peers = chosen_peers
    chosen_rows_for_estimate = [row for _iid, row in chosen_items]
    estimate = _selected_vk_cost_estimate(chosen_rows_for_estimate)
    if S.policy_vk_status_var is not None:
        addrs = [str(row.get("address", ""))[:14] for _iid, row in chosen_items]
        short = ", ".join(addrs[:3]) + ("..." if len(addrs) > 3 else "")
        if estimate.get("ok"):
            S.policy_vk_status_var.set(
                f"Auto VKs: {len(chosen_peers)} | VK DO {_format_wei_as_eth(estimate['vk_do_outlay_wei'])}  [{short}]"
            )
        else:
            S.policy_vk_status_var.set(
                f"Auto VKs: {len(chosen_peers)} | {_vk_estimate_status_reason(estimate)}  [{short}]"
            )

    L.log(f"[auto] selected {len(chosen_peers)} Vault Keepers for {service_days} days (IDA n={count}, t={threshold})")
    for _iid, row in chosen_items:
        loc = str(row.get("location") or "unknown")
        L.log(
            f"[auto] VK {row['address']} rep={row['reputation']} fee={row['storageFee']} "
            f"stake={row['stake']} maxPiece={_format_bytes_limit(row.get('maxPieceSizeBytes', 0))} "
            f"disputes={row.get('disputeCount', 0)} location={loc}"
        )
    _log_selected_vk_cost_estimate(estimate)
    return chosen_peers


def apply_auto_selection(
    service_days: int = 30,
    guardian_n: int = 5,
    guardian_t: int = 3,
    vk_n: int = 6,
    vk_t: int = 4,
    show_errors: bool = True,
) -> bool:
    """Apply auto defaults and show the ranked Guardian/VK choices in the tables."""
    set_auto_defaults(
        service_days=service_days,
        guardian_t=guardian_t,
        ida_n=vk_n,
        ida_t=vk_t,
        guardian_n=guardian_n,
    )
    # Says what the window is busy with. Every guardian is confirmed against
    # the chain before it is staged, which is work that cannot be skipped.
    L.set_status("Selecting Guardians and Vault Keepers...", "running")
    errors = []

    try:
        select_best_guardians(count=guardian_n, threshold=guardian_t, service_days=service_days)
    except Exception as exc:
        msg = f"Guardian auto-selection failed: {exc}"
        errors.append(msg)
        L.log(f"[auto] {msg}")

    try:
        select_best_vault_keepers(count=vk_n, threshold=vk_t, service_days=service_days)
    except Exception as exc:
        msg = f"Vault Keeper auto-selection failed: {exc}"
        errors.append(msg)
        L.log(f"[auto] {msg}")

    if errors:
        if show_errors:
            L.show_error("Auto-select", "\n\n".join(errors))
        L.set_status("Auto-select incomplete", "waiting")
        return False

    L.set_status("Auto-select ready", "done")
    try:
        from . import do_actions as A
        A.save_latest_upload_settings()
    except Exception as exc:
        L.log(f"Could not persist latest auto-select settings: {exc}")
    return True


def _fmt_vk_heartbeat(ts: int) -> str:
    if not ts:
        return "never"
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    diff = now - ts
    if diff < 0:
        return "just now"
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return datetime.datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M")


def _discovery_urls() -> list[str]:
    """The user's own directory servers first, then the network's."""
    from . import ft_discovery

    return ft_discovery.urls(C.config)


def _discovery_timeout() -> float:
    try:
        return float(getattr(C.config, "DISCOVERY_TIMEOUT_SECONDS", 2) or 2)
    except Exception:
        return 2.0


def _discovery_message(record: dict) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Record",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
            f"expiresAt={int(record.get('expiresAt', 0))}",
        ]
    )


def _endpoint_message(record: dict) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Endpoint",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
        ]
    )


def _endpoint_hash(record: dict) -> str:
    value = C.w3.keccak(text=_endpoint_message(record)).hex()
    return value if str(value).startswith("0x") else "0x" + str(value)


def _normalize_bytes32_hex(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    text = str(value or "").strip()
    if not text:
        return "0x" + ("0" * 64)
    if text.startswith("0x") and len(text) == 66:
        return text.lower()
    clean = text.removeprefix("0x")
    if len(clean) <= 64:
        return "0x" + clean.rjust(64, "0").lower()
    return text.lower()


def _is_endpoint_unsupported_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "function selector" in text
        or "not recognized" in text
        or "function does not exist" in text
        or "could not decode" in text
        or "return data: b''" in text
    )


def _discovery_verify_endpoint_hash_enabled() -> bool:
    return True


def _discovery_require_endpoint_hash() -> bool:
    return True


def _endpoint_cache_ttl() -> int:
    try:
        return max(1, int(getattr(C.config, "DISCOVERY_ENDPOINT_CACHE_SECONDS", 30) or 30))
    except Exception:
        return 30


def _registry_supports_endpoint_hash() -> bool:
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        return False
    try:
        return any(
            item.get("type") == "function" and item.get("name") == "getVaultKeeperEndpoint"
            for item in getattr(registry, "abi", [])
            if isinstance(item, dict)
        )
    except Exception:
        return False


def _get_registry_endpoint(vk_addr: str) -> tuple[str, int]:
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        raise RuntimeError("VaultKeeperRegistry is not configured")
    checksum = C.w3.to_checksum_address(vk_addr)
    now = int(time.time())
    cached = _VK_ENDPOINT_CACHE.get(checksum.lower())
    if cached and now - int(cached.get("loadedAt", 0)) < _endpoint_cache_ttl():
        return str(cached.get("endpointHash", "")), int(cached.get("seq", 0))
    endpoint = registry.functions.getVaultKeeperEndpoint(checksum).call()
    endpoint_hash = _normalize_bytes32_hex(endpoint[0] if len(endpoint) > 0 else "")
    seq = int(endpoint[1] if len(endpoint) > 1 else 0)
    _VK_ENDPOINT_CACHE[checksum.lower()] = {
        "endpointHash": endpoint_hash,
        "seq": seq,
        "loadedAt": now,
    }
    return endpoint_hash, seq


def _verify_discovery_endpoint(record: dict, vk_addr: str) -> tuple[bool, str]:
    if not _discovery_verify_endpoint_hash_enabled():
        return False, "endpoint hash verification is required"
    if not _registry_supports_endpoint_hash():
        return False, "registry does not support endpoint hashes"

    computed_hash = _endpoint_hash(record)
    announced_hash = str(record.get("endpointHash", "") or "").strip()
    if announced_hash and announced_hash.lower() != computed_hash.lower():
        return False, f"endpointHash mismatch: announced={announced_hash} computed={computed_hash}"

    try:
        chain_hash, chain_seq = _get_registry_endpoint(vk_addr)
        record_seq = int(record.get("seq", 0))
    except Exception as exc:
        return False, f"endpoint hash lookup failed: {exc}"

    zero_hash = "0x" + ("0" * 64)
    if chain_seq <= 0 or chain_hash.lower() == zero_hash:
        return False, "on-chain endpoint hash is not set"
    if chain_seq != record_seq:
        return False, f"endpoint seq mismatch: record={record_seq} chain={chain_seq}"
    if chain_hash.lower() != computed_hash.lower():
        return False, f"endpoint hash mismatch: record={computed_hash} chain={chain_hash}"
    return True, "ok"


def _verify_discovery_record(record: dict, peer_id: str, vk_addr: str) -> tuple[bool, str]:
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except Exception as exc:
        return False, f"eth_account unavailable: {exc}"

    if not isinstance(record, dict):
        return False, "record is not an object"
    rec_peer = str(record.get("peerId", "")).strip()
    rec_addr = str(record.get("vkAddress", "")).strip()
    multiaddr = str(record.get("multiaddr", "")).strip()
    sig = str(record.get("signature", "")).strip()

    if rec_peer != peer_id:
        return False, f"peerId mismatch: {rec_peer}"
    if rec_addr.lower() != str(vk_addr).lower():
        return False, f"vkAddress mismatch: {rec_addr}"
    if f"/p2p/{peer_id}" not in multiaddr:
        return False, "multiaddr does not contain peerId"
    if not sig:
        return False, "missing signature"
    try:
        if int(record.get("expiresAt", 0)) <= int(datetime.datetime.now(datetime.timezone.utc).timestamp()):
            return False, "record expired"
    except Exception:
        return False, "invalid expiresAt"

    try:
        recovered = Account.recover_message(encode_defunct(text=_discovery_message(record)), signature=sig)
    except Exception as exc:
        return False, f"signature recovery failed: {exc}"
    if recovered.lower() != str(vk_addr).lower():
        return False, f"signature recovered {recovered}"
    ok, reason = _verify_discovery_endpoint(record, vk_addr)
    if not ok:
        return False, reason
    return True, "ok"


def _discovery_request(url: str) -> urllib.request.Request:
    """A discovery call Cloudflare will answer.

    Every node is behind Cloudflare now, and Cloudflare refuses Python's
    default user agent with 403 Forbidden. A caller without a name of its own
    reads a healthy node as unreachable, moves on to the next, and ends up
    reporting that no keeper could be found.
    """
    return urllib.request.Request(url, headers={"User-Agent": "FileTrust-DO"})


def _query_discovery_node(url: str, peer_id: str) -> dict | None:
    peer_path = urllib.parse.quote(peer_id, safe="")
    endpoint = f"{url}/v1/peers/{peer_path}"
    # Named, because a discovery node behind Cloudflare answers 403 to
    # Python's default user agent and the lookup would simply find nothing.
    with urllib.request.urlopen(_discovery_request(endpoint), timeout=_discovery_timeout()) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ok"):
        return None
    return data.get("record")


def _fetch_geo_countries() -> tuple[list[dict], int]:
    """Return (countries, localhost_count) from the first reachable discovery node."""
    timeout = _discovery_timeout()
    for url in _discovery_urls():
        try:
            with urllib.request.urlopen(
                _discovery_request(f"{url}/v1/vk-geo/countries"), timeout=timeout
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("countries", []), int(data.get("localhostCount", 0))
        except Exception as exc:
            L.log(f"[map] geo/countries {url}: {exc}")
    return [], 0


def _fetch_geo_cities(country: str) -> list[dict]:
    """Return cities list for the given country from the first reachable discovery node."""
    timeout = _discovery_timeout()
    enc = urllib.parse.quote(country)
    for url in _discovery_urls():
        try:
            with urllib.request.urlopen(
                _discovery_request(f"{url}/v1/vk-geo/cities?country={enc}"), timeout=timeout
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("cities", [])
        except Exception as exc:
            L.log(f"[map] geo/cities {url}: {exc}")
    return []


def _fetch_geo_nodes(country: str, city: str) -> list[dict]:
    """Return full node records for a specific country+city from the first reachable discovery node."""
    timeout = _discovery_timeout()
    enc_co = urllib.parse.quote(country)
    enc_ci = urllib.parse.quote(city)
    for url in _discovery_urls():
        try:
            endpoint = f"{url}/v1/vk-geo/nodes?country={enc_co}&city={enc_ci}"
            with urllib.request.urlopen(_discovery_request(endpoint), timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("nodes", [])
        except Exception as exc:
            L.log(f"[map] geo/nodes {url}: {exc}")
    return []


def resolve_vk_multiaddr(peer_id: str, vk_addr: str) -> tuple[str, str, str, float, float]:
    """Return (multiaddr, source, location, lat, lon) for a registered VK peerId."""
    peer_id = str(peer_id or "").strip()
    if not peer_id:
        return "", "missing-peer", "", 0.0, 0.0
    urls = _discovery_urls()
    for attempt in range(2):
        for url in urls:
            try:
                record = _query_discovery_node(url, peer_id)
                if not record:
                    continue
                ok, reason = _verify_discovery_record(record, peer_id, vk_addr)
                if not ok:
                    L.log(f"[discovery] rejected record from {url} peerId={peer_id}: {reason}")
                    continue
                _DISCOVERY_RECORD_CACHE[peer_id] = dict(record)
                multiaddr = str(record.get("multiaddr", "")).strip()
                location = str(record.get("location", "")).strip()
                lat = float(record.get("latitude") or 0.0)
                lon = float(record.get("longitude") or 0.0)
                L.log(f"[discovery] resolved peerId={peer_id} via {url} -> {multiaddr} location={location or '?'}")
                return multiaddr, url, location, lat, lon
            except Exception as exc:
                if attempt == 1:
                    L.log(f"[discovery] query failed url={url} peerId={peer_id}: {exc}")
        if attempt == 0:
            time.sleep(0.25)

    cached = _DISCOVERY_RECORD_CACHE.get(peer_id)
    if cached:
        ok, reason = _verify_discovery_record(cached, peer_id, vk_addr)
        if ok:
            multiaddr = str(cached.get("multiaddr", "")).strip()
            return (
                multiaddr,
                "verified-cache",
                str(cached.get("location", "")).strip(),
                float(cached.get("latitude") or 0.0),
                float(cached.get("longitude") or 0.0),
            )
        _DISCOVERY_RECORD_CACHE.pop(peer_id, None)
        L.log(f"[discovery] cached record rejected peerId={peer_id}: {reason}")
    return "", "not-found", "", 0.0, 0.0


def _normalize_registry_peer(peer_value: str) -> str:
    """Return a bare peerId even if an older event stored a full multiaddr."""
    peer_value = str(peer_value or "").strip()
    if "/p2p/" in peer_value:
        return peer_value.rsplit("/p2p/", 1)[-1].strip()
    return peer_value


def _minimum_vk_stake_wei() -> int:
    """Return the current minimum VK stake, falling back to config if ABI is older."""
    meta = D.meta()
    if "vaultKeeperMinStake" in meta:
        return int(meta["vaultKeeperMinStake"] or 0)
    try:
        if C.vault_keeper_registry is not None:
            return int(C.vault_keeper_registry.functions.minimumVaultKeeperStake().call())
    except Exception:
        pass
    try:
        return int(getattr(C.config, "MIN_GUARDIAN_STAKE_WEI", 0) or 0)
    except Exception:
        return 0


_PEER_INDEX_CACHE: dict[str, str] = {}
_PEER_INDEX_LOADED_AT = 0.0
_PEER_INDEX_TTL_SECONDS = 30.0


def _discovery_peer_index(force: bool = False) -> dict[str, str]:
    """Map each VK address -> peerId, taken from discovery and checked by signature.

    One request per discovery node, not one chain search per keeper. Each record
    is signed by the keeper over its own peer id and address, so a discovery node
    cannot invent or swap a pairing; a record that fails that check is dropped.
    """
    global _PEER_INDEX_LOADED_AT
    now = time.time()
    if not force and _PEER_INDEX_CACHE and now - _PEER_INDEX_LOADED_AT < _PEER_INDEX_TTL_SECONDS:
        return _PEER_INDEX_CACHE

    index: dict[str, str] = {}
    for url in _discovery_urls():
        try:
            with urllib.request.urlopen(
                _discovery_request(f"{url}/v1/records"), timeout=_discovery_timeout()
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            L.log(f"[discovery] record list failed url={url}: {exc}")
            continue
        if not data.get("ok"):
            continue
        for record in data.get("records") or []:
            if not isinstance(record, dict):
                continue
            peer_id = str(record.get("peerId", "")).strip()
            vk_addr = str(record.get("vkAddress", "")).strip()
            if not peer_id or not vk_addr:
                continue
            ok, _reason = _verify_discovery_record(record, peer_id, vk_addr)
            if not ok:
                continue
            index.setdefault(vk_addr.lower(), peer_id)

    # An empty answer means discovery is unreachable or knows nothing yet. Keep
    # the previous index rather than forgetting every keeper at once.
    if index:
        _PEER_INDEX_CACHE.clear()
        _PEER_INDEX_CACHE.update(index)
        _PEER_INDEX_LOADED_AT = now
    return _PEER_INDEX_CACHE


def _get_vk_peer_from_events(addr: str) -> tuple[str, str]:
    """Return (peerId, metadataURI) for a VK.

    The peer id is not kept in registry state -- it exists only inside
    registration events -- so this used to search all chain history, from block
    zero, once per keeper. On any chain that caps log queries (Cosmos refuses
    more than 10,000 blocks) every one of those searches begins failing a few
    hours in, and the keeper's address becomes unresolvable, which stops every
    upload because an escrow quote cannot be bound without it.

    The keeper already tells discovery its peer id and address in one signed
    record, so ask there instead. History remains only as a bounded fallback.
    """
    try:
        checksum = C.w3.to_checksum_address(addr)
    except Exception:
        return "", ""

    peer_id = _discovery_peer_index().get(checksum.lower(), "")
    if not peer_id:
        peer_id = _discovery_peer_index(force=True).get(checksum.lower(), "")
    if peer_id:
        return peer_id, ""

    return _peer_from_recent_events(checksum)


def _peer_from_recent_events(checksum: str, window: int = 9_000, lookback: int = 5) -> tuple[str, str]:
    """Fallback: walk back from the head in windows the chain will actually serve.

    Bounded on purpose. This is for a keeper discovery has not heard from yet;
    it is not a way to rebuild the whole registry from history.
    """
    try:
        head = int(C.w3.eth.block_number)
    except Exception:
        return "", ""

    to_block = head
    for _ in range(max(1, lookback)):
        from_block = max(0, to_block - window)
        for event in (
            C.vault_keeper_registry.events.VaultKeeperUpdated,
            C.vault_keeper_registry.events.VaultKeeperRegistered,
        ):
            try:
                logs = event.get_logs(
                    from_block=from_block,
                    to_block=to_block,
                    argument_filters={"vkAddress": checksum},
                )
            except Exception:
                return "", ""
            if logs:
                latest = logs[-1]
                return str(latest.args.peerId), str(latest.args.metadataURI)
        if from_block == 0:
            break
        to_block = from_block - 1
    return "", ""


def load_vault_keepers(rows: list | None = None):
    """Fill the VK table from discovery's network directory.

    One request to discovery (usually a 304 or a small delta), no chain read
    and no request to any keeper. The rows are a hint for choosing; keepers
    actually chosen are checked by _verify_vk_before_paying.

    *rows* lets a caller that already has them -- start-up, which fetches them
    off the UI thread -- fill the table without fetching again.
    """
    if S.vault_keepers_listbox is None:
        return

    for iid in S.vault_keepers_listbox.get_children():
        S.vault_keepers_listbox.delete(iid)
    S.vault_keeper_rows.clear()
    S.vault_keeper_load_error = None

    try:
        if rows is None:
            rows = fetch_vk_rows()
        if not rows:
            L.log("No registered Vault Keepers in the network directory.")
            return

        from .do_vaultmesh import short_peer
        for row in rows:
            multiaddr = row["multiaddr"]
            max_service_days = row["maxServiceDays"]
            total_capacity_bytes = row["totalCapacityBytes"]
            stake_wei = row["stake"]
            display_peer = row["peerId"] or multiaddr
            max_days_str = "∞" if max_service_days == 0 else str(max_service_days)
            _ip_match = re.search(r'/ip4/([^/]+)(?:/tcp/([^/]+))?', multiaddr)
            if _ip_match:
                ip_str = f"{_ip_match.group(1)}:{_ip_match.group(2)}" if _ip_match.group(2) else _ip_match.group(1)
            else:
                ip_str = ""
            cap_str = _format_bytes_limit(total_capacity_bytes) if total_capacity_bytes else "-"
            free_str = _format_bytes_limit(row["freeBytes"]) if total_capacity_bytes else "-"
            iid = S.vault_keepers_listbox.insert(
                "", tk.END,
                values=(
                    "ACTIVE" if row["active"] else "OFF",
                    "YES" if row["eligible"] else "NO",
                    row["reputation"],
                    f"{stake_wei / 1e18:.4f}" if stake_wei else "0",
                    row["disputeCount"],
                    row["penaltyPoints"],
                    row["storageFee"],
                    _format_ftu_from_su(row["storageFee"]),
                    max_days_str,
                    _format_bytes_limit(row["maxPieceSizeBytes"]),
                    cap_str,
                    free_str,
                    row["completedPieces"],
                    _fmt_vk_heartbeat(row["lastProofAt"]),
                    _fmt_vk_heartbeat(row["lastSignOfLife"]),
                    ip_str,
                    row["location"],
                    short_peer(display_peer),
                    row["address"],
                ),
                tags=("active",) if row["eligible"] else ("off",),
            )
            S.vault_keeper_rows[iid] = row

        age = D.age_seconds()
        L.log(
            f"Loaded {len(rows)} Vault Keeper(s) from the network directory"
            + (f" (read from chain {age}s ago)" if age >= 0 else "")
            + ". Click rows to select/unselect."
        )

    except Exception as e:
        S.vault_keeper_load_error = str(e)
        L.show_error("Vault Keeper load error", str(e))
        L.log(f"Vault Keeper load error: {e}")


def get_selected_vk_peers() -> list[str]:
    """The keepers confirmed for this upload, or the ones selected in the table.

    Nothing else. There used to be a third source -- a keeper address typed
    into config.json, or read out of a vaultmesh_config.json beside the app --
    and it was the wrong shape for a network this size: a keeper reached that
    way has not been checked against the registry, is not known to discovery,
    and may not be holding anything. Every keeper the app uses now comes from
    the chain and from discovery, verified before a payment is made.
    """
    if S.policy_vk_peers:
        return list(S.policy_vk_peers)

    peers = []

    if S.vault_keepers_listbox is not None:
        for iid in S.vault_keepers_listbox.selection():
            row = S.vault_keeper_rows.get(iid, {})
            if row.get("eligible") and row.get("multiaddr"):
                ok, reason = _verify_vk_before_paying(row)
                if not ok:
                    L.log(f"VK {str(row.get('address', ''))[:14]} skipped: {reason}")
                    continue
                peers.append(str(row["multiaddr"]).strip())

    out = []
    seen = set()
    for p in peers:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def set_policy_status_text(text: str):
    if S.policy_status_var is not None:
        S.policy_status_var.set(text)


def _guardian_widget_is_table() -> bool:
    return S.guardians_listbox is not None and hasattr(S.guardians_listbox, "get_children")


def _clear_guardian_widget():
    if S.guardians_listbox is None:
        return
    if _guardian_widget_is_table():
        for iid in S.guardians_listbox.get_children():
            S.guardians_listbox.delete(iid)
    else:
        S.guardians_listbox.delete(0, tk.END)


def _guardian_table_columns():
    """Column ids of the Guardian treeview, normalised to a tuple."""
    columns = S.guardians_listbox["columns"]
    if isinstance(columns, str):
        columns = S.guardians_listbox.tk.splitlist(columns)
    return tuple(columns)


def _restore_guardian_first_col():
    """Undo the widening done by _insert_guardian_message()."""
    global _GUARDIAN_FIRST_COL_WIDTH
    if _GUARDIAN_FIRST_COL_WIDTH is None:
        return
    columns = _guardian_table_columns()
    if columns:
        S.guardians_listbox.column(
            columns[0],
            width=_GUARDIAN_FIRST_COL_WIDTH,
            minwidth=_GUARDIAN_FIRST_COL_WIDTH,
        )
    _GUARDIAN_FIRST_COL_WIDTH = None


def _insert_guardian_message(message: str):
    global _GUARDIAN_FIRST_COL_WIDTH
    _clear_guardian_widget()
    S.guardian_rows.clear()
    if S.guardians_listbox is None:
        return
    if _guardian_widget_is_table():
        # The message goes in the first column, padded to the table's real width
        # so the row cannot drift out of alignment when columns are added.  That
        # column is far too narrow for the text, so widen it while the message is
        # the only row; _render_guardian_records() puts it back.
        columns = _guardian_table_columns()
        values = [""] * len(columns)
        if not values:
            return
        values[0] = message
        if _GUARDIAN_FIRST_COL_WIDTH is None:
            _GUARDIAN_FIRST_COL_WIDTH = int(S.guardians_listbox.column(columns[0], "width"))
        S.guardians_listbox.column(columns[0], width=_GUARDIAN_MESSAGE_COL_WIDTH, minwidth=0)
        S.guardians_listbox.insert("", tk.END, values=tuple(values))
    else:
        S.guardians_listbox.insert(tk.END, message)


def _format_wei_as_ftu(wei_amount: int) -> str:
    try:
        return f"{int(wei_amount) / 10**18:.4f}"
    except Exception:
        return str(wei_amount)


def _guardian_addr_from_table_iid(iid: str) -> str:
    if not _guardian_widget_is_table() or S.guardians_listbox is None:
        return ""
    values = S.guardians_listbox.item(iid, "values") or []
    if values:
        candidate = str(values[-1]).strip()
        if candidate.startswith("0x"):
            return candidate
    if str(iid).startswith("0x"):
        return str(iid)
    return ""


def toggle_guardian_selection(event):
    """Kali/Linux-friendly selection: one normal click toggles selected/unselected."""
    if S.guardians_listbox is None:
        return "break"

    if _guardian_widget_is_table():
        if S.guardians_listbox.identify_region(event.x, event.y) == "heading":
            return
        iid = S.guardians_listbox.identify_row(event.y)
        if not iid:
            return "break"

        current = set(S.guardians_listbox.selection())
        if iid in current:
            S.guardians_listbox.selection_remove(iid)
        else:
            S.guardians_listbox.selection_add(iid)

        return "break"

    index = S.guardians_listbox.nearest(event.y)
    if index < 0 or index >= S.guardians_listbox.size():
        return "break"

    current = set(S.guardians_listbox.curselection())
    if index in current:
        S.guardians_listbox.selection_clear(index)
    else:
        S.guardians_listbox.selection_set(index)

    return "break"


def select_all_guardians():
    if S.guardians_listbox is None:
        return
    if _guardian_widget_is_table():
        S.guardians_listbox.selection_set(*S.guardians_listbox.get_children())
        return
    S.guardians_listbox.selection_set(0, tk.END)


def clear_guardian_selection():
    if S.guardians_listbox is None:
        return
    if _guardian_widget_is_table():
        S.guardians_listbox.selection_remove(*S.guardians_listbox.selection())
        return
    S.guardians_listbox.selection_clear(0, tk.END)


def _reward_default_su(action_name: str) -> int:
    if C.reward_manager is None:
        return {"dkg_material": 12000, "dkg_share_key": 6325, "pre_batch_partial": 30542, "daily_share_custody": 0}[action_name]
    try:
        if action_name == "dkg_material":
            return int(C.reward_manager.functions.dkgMaterialSu().call())
        if action_name == "dkg_share_key":
            return int(C.reward_manager.functions.dkgShareKeySu().call())
        if action_name == "pre_batch_partial":
            return int(C.reward_manager.functions.preBatchPartialSu().call())
    except Exception:
        pass
    return {"dkg_material": 12000, "dkg_share_key": 6325, "pre_batch_partial": 30542, "daily_share_custody": 0}[action_name]


def get_service_duration_days(default: int = 30) -> int:
    if S.entry_service_days is None:
        return default
    raw = S.entry_service_days.get().strip()
    try:
        days = int(raw)
        return days if days > 0 else default
    except Exception:
        return default


def _guardian_service_prices(addr: str):
    defaults = (
        _reward_default_su("dkg_material"),
        _reward_default_su("dkg_share_key"),
        _reward_default_su("pre_batch_partial"),
        _reward_default_su("daily_share_custody"),
        0,
    )
    if C.guardian_registry is None:
        return (*defaults, "default")
    try:
        p = C.guardian_registry.functions.getGuardianServiceInfo(addr).call()
        if bool(p[5]):
            return (int(p[0]), int(p[1]), int(p[2]), int(p[3]), int(p[4]), "guardian")
    except Exception:
        pass
    try:
        p = C.guardian_registry.functions.getGuardianServicePricingWithCustody(addr).call()
        if bool(p[4]):
            max_days = 0
            try:
                a = C.guardian_registry.functions.getGuardianAvailability(addr).call()
                max_days = int(a[0])
            except Exception:
                pass
            return (int(p[0]), int(p[1]), int(p[2]), int(p[3]), max_days, "guardian")
    except Exception:
        try:
            p = C.guardian_registry.functions.getGuardianServicePricingWithStatus(addr).call()
            if bool(p[3]):
                return (int(p[0]), int(p[1]), int(p[2]), defaults[3], defaults[4], "guardian")
        except Exception:
            pass
        try:
            p = C.guardian_registry.functions.getGuardianServicePricing(addr).call()
            if any(int(x) for x in p):
                return (int(p[0]), int(p[1]), int(p[2]), defaults[3], defaults[4], "guardian")
        except Exception:
            pass
    return (*defaults, "default")


_SU_TO_WEI_CACHE: tuple[float, int] | None = None
_SU_TO_WEI_CACHE_SECONDS = 30.0


def _current_su_to_wei() -> int:
    """The SU-to-wei rate, asked of the chain at most twice a minute.

    This is called once per number the window formats -- every guardian row,
    every keeper row, every estimate -- and each call was a round trip to the
    node. Filling one keeper table cost dozens of them, and on a busy node that
    was measured at roughly five seconds of the window's start-up, all of it on
    the thread that draws.

    The rate is a network-wide constant that changes on governance timescales,
    so a few seconds of staleness cannot mislead anyone; showing a price a
    moment late is not the same kind of error as paying one.
    """
    global _SU_TO_WEI_CACHE
    fallback = int(getattr(C.config, "SU_TO_WEI_RATE", "1000000000000") or 1000000000000)
    if C.reward_manager is None:
        return fallback

    now = time.time()
    if _SU_TO_WEI_CACHE is not None and now - _SU_TO_WEI_CACHE[0] < _SU_TO_WEI_CACHE_SECONDS:
        return _SU_TO_WEI_CACHE[1]
    try:
        rate = int(C.reward_manager.functions.suToWeiRate().call())
    except Exception:
        return fallback
    _SU_TO_WEI_CACHE = (now, rate)
    return rate


def _format_ftu_from_su(su: int) -> str:
    wei_amount = int(su) * _current_su_to_wei()
    ftu = wei_amount / 10**18
    return f"{ftu:.6f} FTU"


def _render_guardian_records(records):
    if S.guardians_listbox is None:
        return
    _clear_guardian_widget()
    if _guardian_widget_is_table():
        _restore_guardian_first_col()
    S.guardian_rows.clear()
    for row in records:
        addr = row["address"]
        S.guardian_rows.append(addr)
        status = "ACTIVE" if row["active"] else "OFF"
        source = "Own" if row["price_source"] == "guardian" else "Default"
        if _guardian_widget_is_table():
            _tags = []
            if not row["duration_suitable"]:
                _tags.append("unsuitable")
            last_proof = row.get("last_proof_at", 0)
            # Mark stale if never proved OR proof is older than 2 proof periods
            if C.guardian_share_proof is not None:
                stale = (last_proof == 0) or (time.time() - last_proof > 2 * _proof_period_seconds)
                if stale:
                    _tags.append("stale_proof")
            if row.get("dkg_complaints", 0) > 0:
                _tags.append("dkg_complaint")
            if row.get("pre_bad_partial", 0) > 0:
                _tags.append("pre_bad_partial")
            S.guardians_listbox.insert(
                "",
                tk.END,
                iid=addr.lower(),
                values=(
                    status,
                    row["reputation"],
                    _format_wei_as_ftu(row["stake"]),
                    row["completed"],
                    row["failed"],
                    row.get("total_proof_penalties", 0),
                    row["dkg_material_su"],
                    row["dkg_share_key_su"],
                    row["pre_batch_partial_su"],
                    row["daily_share_custody_su"],
                    "unlimited" if int(row["max_service_days"]) == 0 else row["max_service_days"],
                    "yes" if row["duration_suitable"] else "no",
                    row["total_su"],
                    _format_ftu_from_su(row["total_su"]),
                    source,
                    _fmt_vk_heartbeat(last_proof) if last_proof else "-",
                    _fmt_vk_heartbeat(row.get("last_sign_of_life", 0)),
                    addr,
                ),
                tags=tuple(_tags),
            )
        else:
            S.guardians_listbox.insert(
                tk.END,
                f"{status} | rep={row['reputation']} | stake={row['stake']} | "
                f"DKG={row['dkg_material_su']}+{row['dkg_share_key_su']} SU | "
                f"PRE={row['pre_batch_partial_su']} SU | custody/day={row['daily_share_custody_su']} SU | "
                f"maxDays={'unlimited' if int(row['max_service_days']) == 0 else row['max_service_days']} | "
                f"suitable={'yes' if row['duration_suitable'] else 'no'} | "
                f"total={row['total_su']} SU "
                f"({_format_ftu_from_su(row['total_su'])}) | price={source} | {addr}",
            )


def sort_guardians_by_price():
    S.guardian_display_records.sort(key=lambda r: (r["total_su"], -r["reputation"], r["address"].lower()))
    _render_guardian_records(S.guardian_display_records)


def sort_guardians_by_reputation():
    S.guardian_display_records.sort(key=lambda r: (-r["reputation"], r["total_su"], r["address"].lower()))
    _render_guardian_records(S.guardian_display_records)


def sort_guardians_by_cost():
    sort_guardians_by_price()


def sort_guardians_by_col(col: str):
    if S.guardians_listbox is None:
        return
    reverse = (S._guardian_sort_state["col"] == col and not S._guardian_sort_state["reverse"])
    S._guardian_sort_state["col"] = col
    S._guardian_sort_state["reverse"] = reverse

    def _key(iid):
        val = S.guardians_listbox.set(iid, col)
        if col in _GUARDIAN_NUMERIC_COLS:
            try:
                return float(val.replace(",", "").strip() or 0)
            except ValueError:
                return 0.0
        return val.lower()

    items = [(iid, _key(iid)) for iid in S.guardians_listbox.get_children("")]
    items.sort(key=lambda x: x[1], reverse=reverse)
    for idx, (iid, _) in enumerate(items):
        S.guardians_listbox.move(iid, "", idx)

    arrow = " ↓" if reverse else " ↑"
    for c, base in _GUARDIAN_COL_HEADINGS.items():
        S.guardians_listbox.heading(c, text=base + (arrow if c == col else ""))


def refresh_guardian_suitability():
    """Recompute suitability and total SU for all loaded Guardians based on current service days."""
    if not S.guardian_display_records:
        return
    duration_days = get_service_duration_days()
    for row in S.guardian_display_records:
        max_days = int(row.get("max_service_days", 0))
        row["duration_suitable"] = (max_days == 0 or duration_days <= max_days)
        row["total_su"] = (
            int(row["dkg_material_su"]) + int(row["dkg_share_key_su"]) +
            int(row["pre_batch_partial_su"]) + (duration_days * int(row["daily_share_custody_su"]))
        )
    _render_guardian_records(S.guardian_display_records)


def summarize_selected_guardian_prices(selected_guardians, threshold: int):
    by_addr = {row["address"].lower(): row for row in S.guardian_display_records}
    rows = []
    for addr in selected_guardians:
        row = by_addr.get(addr.lower())
        if row is None:
            dkg_material_su, dkg_share_key_su, pre_batch_partial_su, daily_share_custody_su, max_service_days, price_source = _guardian_service_prices(addr)
            duration_days = get_service_duration_days()
            row = {
                "address": addr,
                "dkg_material_su": dkg_material_su,
                "dkg_share_key_su": dkg_share_key_su,
                "pre_batch_partial_su": pre_batch_partial_su,
                "daily_share_custody_su": daily_share_custody_su,
                "max_service_days": max_service_days,
                "duration_suitable": (max_service_days == 0 or duration_days <= max_service_days),
                "price_source": price_source,
            }
        rows.append(row)

    dkg_su = sum(int(r["dkg_material_su"]) + int(r["dkg_share_key_su"]) for r in rows)
    custody_su = sum(int(r["daily_share_custody_su"]) for r in rows)
    cheapest_pre = sorted(int(r["pre_batch_partial_su"]) for r in rows)[:threshold]
    pre_su = sum(cheapest_pre)
    return rows, dkg_su, custody_su, pre_su


def _guardian_record_from_directory(entry: dict, duration_days: int) -> dict:
    """One directory guardian as the record the Guardian table and selection use."""
    address = str(entry.get("address", ""))
    try:
        address = C.w3.to_checksum_address(address)
    except Exception:
        pass
    if entry.get("pricingSet"):
        prices = (
            int(entry.get("dkgMaterialSu", 0) or 0),
            int(entry.get("dkgShareKeySu", 0) or 0),
            int(entry.get("preBatchPartialSu", 0) or 0),
            int(entry.get("dailyShareCustodySu", 0) or 0),
        )
        max_service_days = int(entry.get("maxServiceDays", 0) or 0)
        price_source = "guardian"
    else:
        prices = (
            _reward_default_su("dkg_material"),
            _reward_default_su("dkg_share_key"),
            _reward_default_su("pre_batch_partial"),
            _reward_default_su("daily_share_custody"),
        )
        max_service_days = 0
        price_source = "default"
    dkg_material_su, dkg_share_key_su, pre_batch_partial_su, daily_share_custody_su = prices
    last_heartbeat = int(entry.get("lastHeartbeat", 0) or 0)
    last_activity_at = int(entry.get("lastActivityAt", 0) or 0)
    last_proof_at = int(entry.get("lastProofAt", 0) or 0)
    return {
        "address": address,
        "active": bool(entry.get("active", 0)),
        "stake": int(entry.get("stake", 0) or 0),
        "reputation": int(entry.get("reputation", 0) or 0),
        "completed": int(entry.get("completedJobs", 0) or 0),
        "failed": int(entry.get("failedJobs", 0) or 0),
        "dkg_fee": int(entry.get("dkgFee", 0) or 0),
        "telg_fee": int(entry.get("telgFee", 0) or 0),
        "refresh_fee": int(entry.get("refreshFee", 0) or 0),
        "dkg_material_su": dkg_material_su,
        "dkg_share_key_su": dkg_share_key_su,
        "pre_batch_partial_su": pre_batch_partial_su,
        "daily_share_custody_su": daily_share_custody_su,
        "max_service_days": max_service_days,
        "duration_suitable": max_service_days == 0 or duration_days <= max_service_days,
        "total_su": dkg_material_su + dkg_share_key_su + pre_batch_partial_su
        + (duration_days * daily_share_custody_su),
        "price_source": price_source,
        "last_proof_at": last_proof_at,
        "last_heartbeat": last_heartbeat,
        "last_activity_at": last_activity_at,
        "last_sign_of_life": _latest_sign_of_life(last_heartbeat, last_activity_at, last_proof_at),
        "total_proof_penalties": int(entry.get("totalProofPenalties", 0) or 0),
        "dkg_complaints": int(entry.get("dkgComplaints", 0) or 0),
        "pre_bad_partial": int(entry.get("preBadPartial", 0) or 0),
    }


def load_guardians():
    """Fill the Guardian records (and the table, when there is one) from the
    network directory: one request to discovery, no chain read per guardian.

    Runs without a window too, so automatic selection has the same records.
    """
    global _proof_period_seconds
    _clear_guardian_widget()
    S.guardian_rows.clear()
    S.guardian_display_records.clear()
    S.guardian_load_error = None

    try:
        if not D.refresh():
            raise RuntimeError(
                "No discovery node answered and no local copy of the network directory exists. "
                "Check DISCOVERY_URLS and that discovery is running."
            )
        period = int(D.meta().get("guardianProofPeriodSeconds", 0) or 0)
        if period > 0:
            _proof_period_seconds = period
        duration_days = get_service_duration_days()
        records = [_guardian_record_from_directory(e, duration_days) for e in D.guardians()]

        if not records:
            _insert_guardian_message("No registered guardians found")
            L.log("No registered guardians in the network directory.")
            return

        S.guardian_display_records.extend(records)
        _render_guardian_records(S.guardian_display_records)

        L.log(
            f"Loaded {len(records)} guardian(s) from the network directory. Click rows to toggle selection. "
            "Rows show Guardian SU price, reputation, stake, and estimated DKG+custody+PRE contribution."
        )
        L.log("Guardian prices are dynamic; estimates use current on-chain prices and future rewards use the latest price at reward time.")

    except Exception as e:
        S.guardian_load_error = str(e)
        L.show_error("Guardian load error", str(e))
        L.log(f"Guardian load error: {e}")


def _guardian_entry_from_chain(checksum: str) -> dict:
    """Every Guardian-table field for one guardian, read from the chain itself.

    Same fields, same contracts and the same fallbacks as NetworkDirectoryReader,
    so a row built from this can be compared with the directory's row one to
    one. Seven direct lookups by address; used for the few guardians chosen.
    """
    g = C.guardian_registry.functions.getGuardian(checksum).call()
    entry = {
        "address": checksum,
        "dkgFee": int(g[5]), "telgFee": int(g[6]), "refreshFee": int(g[7]),
        "stake": int(g[8]), "reputation": int(g[9]),
        "completedJobs": int(g[10]), "failedJobs": int(g[11]), "disputes": int(g[12]),
        "active": bool(g[13]), "registeredAt": int(g[14]), "lastHeartbeat": int(g[15]),
        "pricingSet": False, "dkgMaterialSu": 0, "dkgShareKeySu": 0,
        "preBatchPartialSu": 0, "dailyShareCustodySu": 0, "maxServiceDays": 0,
        "lastProofAt": 0, "totalProofPenalties": 0, "dkgComplaints": 0,
        "lastActivityAt": 0, "preBadPartial": 0,
    }
    info = C.guardian_registry.functions.getGuardianServiceInfo(checksum).call()
    entry.update({
        "dkgMaterialSu": int(info[0]), "dkgShareKeySu": int(info[1]),
        "preBatchPartialSu": int(info[2]), "dailyShareCustodySu": int(info[3]),
        "maxServiceDays": int(info[4]), "pricingSet": bool(info[5]),
    })
    if getattr(C, "reputation_manager", None) is not None:
        stats = C.reputation_manager.functions.getGuardianStats(checksum).call()
        entry["dkgComplaints"] = int(stats[5])
        entry["lastActivityAt"] = int(stats[8])
        entry["totalProofPenalties"] = int(
            C.reputation_manager.functions.getTotalShareProofPenalties(checksum).call()
        )
    if getattr(C, "guardian_share_proof", None) is not None:
        entry["lastProofAt"] = int(C.guardian_share_proof.functions.lastProofAt(checksum).call())
    if getattr(C, "telg_v2", None) is not None:
        entry["preBadPartial"] = int(C.telg_v2.functions.preBadPartialCount(checksum).call())
    return entry


# Fields the directory row is compared on. A listed value better for the
# guardian than the chain's beyond the reputation drift means the directory was
# stale or dishonest, and the guardian is refused rather than corrected: it was
# chosen on figures that were not true.
def _guardian_listing_mismatch(listed: dict, chain: dict) -> str:
    if _reputation_overstated(int(listed.get("reputation", 0) or 0), int(chain["reputation"])):
        return f"reputation overstated ({listed.get('reputation')} listed, {chain['reputation']} on chain)"
    # Unit prices, not total_su: the total depends on the service days, which
    # may differ between when the list was loaded and now.
    for key in ("dkg_material_su", "dkg_share_key_su", "pre_batch_partial_su", "daily_share_custody_su"):
        if int(listed.get(key, 0) or 0) < int(chain[key]):
            return f"price understated ({key} {listed.get(key)} listed, {chain[key]} on chain)"
    if int(listed.get("stake", 0) or 0) > int(chain["stake"]):
        return f"stake overstated ({listed.get('stake')} listed, {chain['stake']} on chain)"
    for key in ("failed", "dkg_complaints", "total_proof_penalties", "pre_bad_partial"):
        if int(listed.get(key, 0) or 0) < int(chain[key]):
            return f"{key} understated ({listed.get(key)} listed, {chain[key]} on chain)"
    return ""


def _verify_guardians_in_parallel(ranked: list[dict], count: int) -> dict:
    """Check the guardians likely to be needed, several at a time.

    Only as far down the ranked list as could plausibly be reached: enough for
    the ones wanted plus room for refusals, never the whole directory. Keyed
    by row identity because the verification writes the chain's values back
    into the row it was given.
    """
    wanted = ranked[: max(0, int(count)) + 4]
    if len(wanted) < 2:
        return {}
    from concurrent.futures import ThreadPoolExecutor

    # Read from the window here and pass the value down. The service days live
    # in an entry box, and Tk may only be touched from the thread running the
    # window -- reading it inside the pool hung the app outright.
    service_days = get_service_duration_days()

    def check(row: dict) -> tuple[int, tuple[bool, str]]:
        try:
            return id(row), _verify_guardian_before_use(row, service_days=service_days)
        except Exception as exc:  # unable to confirm is not confirmation
            return id(row), (False, f"chain check failed: {exc}")

    # Sized so the wall time stays about the same as the network grows: these
    # are short chain reads, and the limit that matters is how long the window
    # is held, not how many calls are in flight.
    with ThreadPoolExecutor(max_workers=min(32, len(wanted))) as pool:
        return dict(pool.map(check, wanted))


def _verify_guardian_before_use(
    row: dict, service_days: int | None = None
) -> tuple[bool, str]:
    """Confirm one chosen guardian against the chain before it is staged.

    The directory is a hint from a party that is not trusted. So every field
    the guardian was chosen on is read again from the chain: it must be
    active with the minimum stake, available for the service days, and no
    listed figure may be better than the chain's (reputation within the
    allowed drift). On success the row is overwritten with the chain's values,
    so cost estimates and logs from here on use the chain, never the list.
    """
    address = str(row.get("address", "")).strip()
    try:
        checksum = C.w3.to_checksum_address(address)
    except Exception:
        return False, "invalid address"
    if C.guardian_registry is None:
        return False, "GuardianRegistry not configured"
    try:
        if not bool(C.guardian_registry.functions.isActiveGuardian(checksum).call()):
            return False, "not active on chain"
        chain = _guardian_record_from_directory(
            _guardian_entry_from_chain(checksum),
            get_service_duration_days() if service_days is None else int(service_days),
        )
    except Exception as exc:
        # Unable to confirm is not confirmation.
        return False, f"chain check failed: {exc}"
    if not chain["duration_suitable"]:
        return False, f"not available for the service days (max {chain['max_service_days']} on chain)"
    mismatch = _guardian_listing_mismatch(row, chain)
    if mismatch.startswith("stake overstated"):
        # A stale stake is repairable only when ALL other directory checks
        # pass. The caller must repeat selection using this authoritative row.
        other = _guardian_listing_mismatch({**row, "stake": chain["stake"]}, chain)
        if other:
            return False, other
        try:
            minimum = int(C.guardian_registry.functions.minStake().call())
        except Exception as exc:
            return False, f"chain check failed: {exc}"
        if minimum <= 0 or int(chain["stake"]) < minimum:
            return False, "insufficient on-chain stake"
        row.update(chain)
        return False, mismatch + "; current chain row refreshed; repeat selection"
    if mismatch:
        return False, mismatch
    row.update(chain)
    return True, "ok"


def get_selected_guardians():
    if S.guardians_listbox is None:
        return []

    if _guardian_widget_is_table():
        selected = S.guardians_listbox.selection()
        guardians = []
        for iid in selected:
            addr = _guardian_addr_from_table_iid(iid)
            if addr:
                guardians.append(addr)
        return guardians

    selected = S.guardians_listbox.curselection()
    return [S.guardian_rows[i] for i in selected if i < len(S.guardian_rows)]


def get_guardian_threshold(default=None):
    if S.entry_guardian_t is None:
        return default

    raw = S.entry_guardian_t.get().strip()
    try:
        return int(raw)
    except Exception:
        return default


def normalize_guardian_list(items):
    seen = set()
    out = []

    for item in items:
        addr = C.w3.to_checksum_address(item)
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            out.append(addr)

    return out


def select_policy_guardians_in_listbox(policy_guardians):
    if S.guardians_listbox is None:
        return

    wanted = {g.lower() for g in policy_guardians}
    clear_guardian_selection()

    if _guardian_widget_is_table():
        for iid in S.guardians_listbox.get_children():
            addr = _guardian_addr_from_table_iid(iid)
            if addr and addr.lower() in wanted:
                S.guardians_listbox.selection_add(iid)
        return

    for i, addr in enumerate(S.guardian_rows):
        if addr.lower() in wanted:
            S.guardians_listbox.selection_set(i)


def load_policy_requesters_ui():
    """Populate the requester list from the currently selected policy's record."""
    if S.req_book_tree is None:
        return
    for iid in S.req_book_tree.get_children():
        S.req_book_tree.delete(iid)
    policy_name = S.entry_policy_name.get().strip() if S.entry_policy_name else ""
    if not policy_name:
        return
    for req in R.get_policy_requesters(policy_name):
        addr = req.get("address", "")
        name = req.get("name", "")
        if addr:
            S.req_book_tree.insert("", tk.END, iid=addr.lower(), values=(name or "—", addr))


def req_book_row_selected(event=None):
    if S.req_book_tree is None:
        return
    sel = S.req_book_tree.selection()
    if not sel:
        return
    vals = S.req_book_tree.item(sel[0], "values")
    if not vals:
        return
    name = vals[0] if vals[0] != "—" else ""
    addr = vals[1] if len(vals) > 1 else ""
    if S.entry_req_address is not None:
        S.entry_req_address.delete(0, tk.END)
        S.entry_req_address.insert(0, addr)
    if S.entry_req_name is not None:
        S.entry_req_name.delete(0, tk.END)
        S.entry_req_name.insert(0, name)


def remove_from_policy_list():
    if S.req_book_tree is None:
        return
    sel = S.req_book_tree.selection()
    if not sel:
        L.show_error("Requester", "Select a requester from the list first.")
        return
    iid = sel[0]
    vals = S.req_book_tree.item(iid, "values")
    addr = vals[1] if vals and len(vals) > 1 else iid
    policy_name = S.entry_policy_name.get().strip() if S.entry_policy_name else ""
    if not policy_name:
        return
    R._update_policy_requesters(policy_name, addr, add=False)
    try:
        from . import do_actions as A
        A.save_latest_upload_settings(prefer_policy_requesters=True)
    except Exception as exc:
        L.log(f"Could not persist latest requester settings: {exc}")
    load_policy_requesters_ui()
    L.log(f"Removed from policy '{policy_name}': {addr}")


# ═══════════════════════════════════════════════════════════════════════════════
# VK Map
# ═══════════════════════════════════════════════════════════════════════════════

def _on_vk_tab_change() -> None:
    try:
        if S.vk_tab_view is not None and S.vk_tab_view.get() == "Map":
            # Only do the initial load; after that the map preserves its own
            # position/zoom. The user can hit ⟳ Refresh to return to world view.
            if not S.vk_map_markers:
                refresh_vk_map()
    except Exception as exc:
        L.log(f"[map] tab change error: {exc}")


def refresh_vk_map() -> None:
    if S.vk_map_widget is None:
        return
    _vk_map_clear_markers()
    S.vk_map_level = "world"
    S.vk_map_current_country = ""
    _vk_map_show_countries()


def _vk_map_clear_markers() -> None:
    global _vk_node_marker_pairs
    for m in S.vk_map_markers:
        try:
            m.delete()
        except Exception:
            pass
    S.vk_map_markers.clear()
    _vk_node_marker_pairs = []
    # Remove canvas right-click binding when not at node level
    try:
        if S.vk_map_widget is not None:
            S.vk_map_widget.canvas.unbind("<Button-3>")
    except Exception:
        pass


# Geographic centroids for country-level map markers.
# Used instead of averaging VK coordinates so the pin lands at the country
# centre regardless of which city or cities the VKs are in.
_COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "United Kingdom":   (55.3781,   -3.4360),
    "Germany":          (51.1657,   10.4515),
    "United States":    (37.0902,  -95.7129),
    "Japan":            (36.2048,  138.2529),
    "Australia":        (-25.2744, 133.7751),
    "Brazil":           (-14.2350,  -51.9253),
    "Canada":           (56.1304, -106.3468),
    "France":           (46.2276,    2.2137),
    "Singapore":        ( 1.3521,  103.8198),
    "South Africa":     (-30.5595,  22.9375),
    "India":            (20.5937,   78.9629),
    "Netherlands":      (52.1326,    5.2913),
}


def _country_centroid(country: str, fallback_lat: float = 0.0, fallback_lon: float = 0.0) -> tuple[float, float]:
    """Return geographic centre for the country, falling back to the supplied average."""
    if country in _COUNTRY_CENTROIDS:
        return _COUNTRY_CENTROIDS[country]
    return fallback_lat, fallback_lon


def _vk_map_show_countries() -> None:
    """Fetch country summary from discovery in background, then draw markers."""
    if S.vk_map_widget is None:
        return
    if S.vk_map_info_var is not None:
        S.vk_map_info_var.set("Loading countries…")

    def _worker():
        try:
            countries, localhost_count = _fetch_geo_countries()
        except Exception:
            countries, localhost_count = [], 0
        if S.vk_map_widget is None:
            return
        S.vk_map_widget.after(0, lambda: _draw_countries(countries, localhost_count))

    threading.Thread(target=_worker, daemon=True).start()


def _draw_countries(countries: list, localhost_count: int) -> None:
    if S.vk_map_widget is None:
        return
    for c in countries:
        country = c["country"]
        clat, clon = _country_centroid(country, c["lat"], c["lon"])
        marker = S.vk_map_widget.set_marker(
            clat, clon,
            text=f"{country}  ({c['count']})",
            marker_color_outside="#0D7377",
            marker_color_circle="#E0F7FA",
            command=lambda m, co=country: _vk_map_on_country_click(co),
        )
        S.vk_map_markers.append(marker)

    if S.vk_map_local_var is not None:
        S.vk_map_local_var.set(f"Localhost: {localhost_count} node(s)" if localhost_count else "")
    if S.vk_map_back_btn is not None:
        S.vk_map_back_btn.configure(state="disabled", text="← Back")
    if countries:
        S.vk_map_widget.set_position(20, 10)
        S.vk_map_widget.set_zoom(2)
    else:
        if S.vk_map_info_var is not None:
            S.vk_map_info_var.set("No geo data — discovery nodes may have no location info yet")


def _vk_map_on_country_click(country: str) -> None:
    _vk_map_clear_markers()
    S.vk_map_level = "country"
    S.vk_map_current_country = country
    if S.vk_map_back_btn is not None:
        S.vk_map_back_btn.configure(state="normal", text="← World")
    _vk_map_show_cities(country)


def _vk_map_show_cities(country: str) -> None:
    """Fetch city summary for the given country from discovery, then draw markers."""
    if S.vk_map_widget is None:
        return
    if S.vk_map_info_var is not None:
        S.vk_map_info_var.set(f"Loading cities in {country}…")

    def _worker():
        try:
            cities = _fetch_geo_cities(country)
        except Exception:
            cities = []
        if S.vk_map_widget is None:
            return
        S.vk_map_widget.after(0, lambda: _draw_cities(country, cities))

    threading.Thread(target=_worker, daemon=True).start()


def _draw_cities(country: str, cities: list) -> None:
    if S.vk_map_widget is None:
        return
    for c in cities:
        marker = S.vk_map_widget.set_marker(
            c["lat"], c["lon"],
            text=f"{c['city']}  ({c['count']})",
            marker_color_outside="#14919B",
            marker_color_circle="#E0F7FA",
            command=lambda m, ci=c["city"], co=country: _vk_map_on_city_click(co, ci),
        )
        S.vk_map_markers.append(marker)

    if cities:
        avg_lat = sum(c["lat"] for c in cities) / len(cities)
        avg_lon = sum(c["lon"] for c in cities) / len(cities)
        # Zoom first so set_position uses the target zoom level when computing tile
        # bounds — prevents check_map_border_crossing from shifting high-longitude
        # cities (e.g. Sydney 151°E) off-screen at the wider zoom-2 tile grid.
        S.vk_map_widget.set_zoom(5)
        S.vk_map_widget.set_position(avg_lat, avg_lon)


def _vk_map_on_city_click(country: str, city: str) -> None:
    _vk_map_clear_markers()
    S.vk_map_level = "city"
    S.vk_map_current_country = country
    if S.vk_map_back_btn is not None:
        S.vk_map_back_btn.configure(state="normal", text=f"← {country}")
    _vk_map_show_nodes(country, city)


# Per-session state for node-level marker interaction.
_vk_node_marker_pairs: list = []   # [(marker, row), …] at node zoom — for right-click lookup
_vk_last_click_time: dict = {}     # address → timestamp, for double-click detection
_node_icon_cache: object = None    # ImageTk.PhotoImage — kept alive to prevent GC


def _get_node_icon():
    """Return a cached PIL ImageTk.PhotoImage of a storage-server icon for VK node markers."""
    global _node_icon_cache
    if _node_icon_cache is not None:
        return _node_icon_cache
    try:
        from PIL import Image, ImageDraw, ImageTk
        W, H = 36, 36
        img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)

        # Outer chassis — dark navy, rounded
        d.rounded_rectangle([1, 1, W - 2, H - 2], radius=6,
                             fill=(20, 58, 95, 248), outline=(8, 24, 48, 255), width=1)

        # Header stripe (top bar)
        d.rounded_rectangle([2, 2, W - 3, 11], radius=5, fill=(45, 106, 159, 248))
        d.rectangle([2, 7, W - 3, 11], fill=(45, 106, 159, 248))   # flatten bottom of header

        # Three disk-slot rows
        for y in (16, 21, 26):
            d.rectangle([4, y - 2, W - 6, y + 2], fill=(14, 40, 68, 200))   # slot recess
            d.line([(5, y), (W - 8, y)], fill=(74, 144, 217, 220), width=1)  # slot line

        # Green activity LED in top-right corner of header
        lx, ly = W - 7, 6
        d.ellipse([lx - 3, ly - 3, lx + 3, ly + 3],
                  fill=(0, 230, 118, 255), outline=(0, 160, 80, 255))

        # Bottom status bar
        d.rectangle([2, H - 7, W - 3, H - 2], fill=(14, 40, 68, 220))

        _node_icon_cache = ImageTk.PhotoImage(img)
        return _node_icon_cache
    except Exception:
        return None


def _spread_node_positions(rows: list, spread: float = 0.006) -> list:
    """Return [(lat, lon, row), …] with offsets so co-located markers don't overlap.

    Nodes at the exact same coordinate are arranged in a small circle of radius
    `spread` degrees (~650 m at city zoom).  Single nodes are placed exactly.
    """
    import math
    from collections import defaultdict
    buckets: dict = defaultdict(list)
    for row in rows:
        key = (round(float(row.get("latitude") or 0.0), 3),
               round(float(row.get("longitude") or 0.0), 3))
        buckets[key].append(row)

    result = []
    for (lat, lon), group in buckets.items():
        n = len(group)
        for i, row in enumerate(group):
            if n == 1:
                result.append((lat, lon, row))
            else:
                angle = 2 * math.pi * i / n - math.pi / 2
                result.append((lat + spread * math.cos(angle),
                               lon + spread * math.sin(angle),
                               row))
    return result


def _vk_map_show_nodes(country: str, city: str) -> None:
    """Fetch individual node records for country+city from discovery, then draw markers."""
    if S.vk_map_widget is None:
        return
    if S.vk_map_info_var is not None:
        S.vk_map_info_var.set(f"Loading nodes in {city}…")

    def _worker():
        try:
            nodes = _fetch_geo_nodes(country, city)
        except Exception:
            nodes = []
        if S.vk_map_widget is None:
            return
        S.vk_map_widget.after(0, lambda: _draw_nodes(nodes))

    threading.Thread(target=_worker, daemon=True).start()


def _draw_nodes(rows: list) -> None:
    from .do_vaultmesh import short_peer

    global _vk_node_marker_pairs
    _vk_node_marker_pairs = []

    if S.vk_map_widget is None:
        return

    node_icon = _get_node_icon()
    for lat, lon, row in _spread_node_positions(rows):
        label = short_peer(row.get("peerId") or row.get("address", "?"))
        extra = {"icon": node_icon, "icon_anchor": "center"} if node_icon else {}
        marker = S.vk_map_widget.set_marker(
            lat, lon,
            text=label,
            command=lambda m, r=row: _vk_map_node_single_click(m, r),
            **extra,
        )
        S.vk_map_markers.append(marker)
        _vk_node_marker_pairs.append((marker, row))

    if rows:
        lats = [float(r.get("latitude") or 0.0) for r in rows]
        lons = [float(r.get("longitude") or 0.0) for r in rows]
        S.vk_map_widget.set_zoom(11)
        S.vk_map_widget.set_position(sum(lats) / len(lats), sum(lons) / len(lons))

    try:
        S.vk_map_widget.canvas.bind("<Button-3>", _vk_map_canvas_right_click)
    except Exception:
        pass

    _update_map_info_bar()


def _vk_map_node_single_click(marker, row: dict) -> None:
    """TkinterMapView fires this on every left-click; we detect double-click via timing."""
    import time as _t
    addr = str(row.get("address", ""))
    now = _t.time()
    last = _vk_last_click_time.get(addr, 0.0)
    _vk_last_click_time[addr] = now

    if now - last < 0.40:          # two clicks within 400 ms → double-click
        _vk_map_toggle_node(row, select=True)
    else:
        # Single click: show info hint only
        loc = str(row.get("location", ""))
        short = f"{addr[:8]}…{addr[-6:]}" if len(addr) > 14 else addr
        if S.vk_map_info_var is not None:
            S.vk_map_info_var.set(
                f"{short}  ·  {loc}  —  double-click to select  ·  right-click to deselect"
            )


def _vk_map_canvas_right_click(event) -> None:
    """Right-click deselects the node marker nearest to the cursor (within 40 px)."""
    if not _vk_node_marker_pairs or S.vk_map_widget is None:
        return
    x, y = event.x, event.y
    best_pair = None
    best_d2 = 40 * 40          # accept only within 40-pixel radius
    for marker, row in _vk_node_marker_pairs:
        try:
            mx, my = marker.get_canvas_pos(marker.position)
            d2 = (x - mx) ** 2 + (y - my) ** 2
            if d2 < best_d2:
                best_d2 = d2
                best_pair = (marker, row)
        except Exception:
            pass
    if best_pair:
        _vk_map_toggle_node(best_pair[1], select=False)


def _vk_map_toggle_node(row: dict, select: bool) -> None:
    """Add (select=True) or remove (select=False) a VK from the table selection."""
    # Support both field names: geo nodes use vkAddress, table rows use address.
    addr = str(row.get("address") or row.get("vkAddress") or "").lower()
    lb = S.vault_keepers_listbox
    if lb is None:
        return
    found = False
    for iid, r in S.vault_keeper_rows.items():
        if str(r.get("address") or "").lower() != addr:
            continue
        found = True
        if select:
            if not r.get("eligible"):
                reason = r.get("eligibilityReason") or "not eligible"
                if S.vk_map_info_var is not None:
                    S.vk_map_info_var.set(f"VK {addr[:10]}… not selectable: {reason}")
                L.log(f"[map] VK not eligible: {addr} — {reason}")
            else:
                lb.selection_add(iid)
                lb.see(iid)
                L.log(f"[map] VK added to selection: {addr}")
        else:
            lb.selection_remove(iid)
            L.log(f"[map] VK removed from selection: {addr}")
        _sync_n_from_selection()
        break
    if not found and select:
        short = f"{addr[:8]}…{addr[-6:]}" if len(addr) > 14 else addr
        msg = f"VK {short} not in your table — may not be registered on-chain yet"
        if S.vk_map_info_var is not None:
            S.vk_map_info_var.set(msg)
        L.log(f"[map] {msg}")
    _update_map_info_bar()


def _update_map_info_bar() -> None:
    if S.vault_keepers_listbox is None or S.vk_map_info_var is None:
        return
    count = len(S.vault_keepers_listbox.selection())
    if count:
        S.vk_map_info_var.set(
            f"Selected: {count} VK(s)  —  double-click to add  ·  right-click to remove"
        )
    else:
        S.vk_map_info_var.set("Double-click a node to select  ·  Right-click to deselect")


def vk_map_go_back() -> None:
    if S.vk_map_level == "city":
        country = S.vk_map_current_country
        _vk_map_clear_markers()
        S.vk_map_level = "country"
        if S.vk_map_back_btn is not None:
            S.vk_map_back_btn.configure(state="normal", text="← World")
        _vk_map_show_cities(country)   # re-fetches from discovery
    else:
        _vk_map_clear_markers()
        S.vk_map_level = "world"
        S.vk_map_current_country = ""
        _vk_map_show_countries()       # re-fetches from discovery
