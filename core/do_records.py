# do_records.py — local JSON record management.
# All path helpers and JSON persistence for policies, PK cache, and requester book.

import os
import json
import datetime
import tempfile
from pathlib import Path

from . import do_config as C
from . import do_state as S
from . import do_log as L
from . import do_hex as HX


def _write_private_json(path_text: str, value: object) -> None:
    """Atomically persist local DO metadata with owner-only permissions."""
    path = Path(path_text)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def normalize_pk_file_id(file_id_hex: str) -> str:
    return HX.normalize_file_id(file_id_hex)


def pk_latest_path(file_id_hex: str) -> str:
    clean = normalize_pk_file_id(file_id_hex)
    name=clean if getattr(C,'DKG_ATTEMPT_PROTOCOL',0)==1 else clean[:16]
    return os.path.join(C.PK_CACHE_DIR, f"dkg_public_key_{name}_latest.json")


def pk_epoch_path(file_id_hex: str, key_epoch: int) -> str:
    clean = normalize_pk_file_id(file_id_hex)
    name=clean if getattr(C,'DKG_ATTEMPT_PROTOCOL',0)==1 else clean[:16]
    return os.path.join(C.PK_CACHE_DIR, f"dkg_public_key_{name}_k{int(key_epoch)}.json")


def pk_any_latest_path() -> str | None:
    candidates = sorted(
        Path(C.PK_CACHE_DIR).glob("dkg_public_key_*_latest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(candidates[0]) if candidates else None


def share_cids_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "share_cids.json")


def enc_cids_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "enc_cids.json")


def vaultmesh_piece_receipts_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "vaultmesh_piece_receipts.json")


def piece_lifecycle_journal_path() -> str:
    """Private authoritative state; unlike pid_records this survives uploads."""
    return os.path.join(getattr(C,'NETWORK_STATE_DIR',C.BASE_DIR), "transfer_jobs", "piece_lifecycle.sqlite3")


def drop_uploads_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "drop_uploads.json")


def drop_folder_baselines_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "drop_folder_baselines.json")


def vk_receipts_dir() -> str:
    path = os.path.join(C.CID_RECORDS_DIR, "vk_receipts")
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def policies_record_path() -> str:
    return os.path.join(getattr(C,'NETWORK_STATE_DIR',C.BASE_DIR), "policies.json")


def load_policies_record() -> dict:
    p = policies_record_path()
    if not os.path.isfile(p):
        return {}
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_drop_upload_records() -> dict:
    p = drop_uploads_path()
    if not os.path.isfile(p):
        return {}
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_drop_folder_baselines() -> dict:
    p = drop_folder_baselines_path()
    if not os.path.isfile(p):
        return {}
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_drop_folder_baseline(folder_key: str, record: dict) -> None:
    records = load_drop_folder_baselines()
    records[str(folder_key)] = record
    _write_private_json(drop_folder_baselines_path(), records)


def save_drop_upload_record(path_key: str, record: dict) -> None:
    records = load_drop_upload_records()
    records[str(path_key)] = record
    _write_private_json(drop_uploads_path(), records)


def update_drop_upload_record(path_key: str, updates: dict) -> None:
    records = load_drop_upload_records()
    key = str(path_key)
    record = records.get(key, {})
    if not isinstance(record, dict):
        record = {}
    record.update(updates)
    records[key] = record
    _write_private_json(drop_uploads_path(), records)


def save_policy_record(policy_name: str, file_id_hex: str, guardians: list, threshold: int):
    recs = load_policies_record()
    key = policy_name.lower()
    existing = recs.get(key, {})
    existing.update({
        "policyName": policy_name,
        "policyId": file_id_hex,
        "guardians": [str(g) for g in guardians],
        "threshold": int(threshold),
        "updated": datetime.date.today().isoformat(),
    })
    if "created" not in existing:
        existing["created"] = datetime.date.today().isoformat()
    if "files" not in existing:
        existing["files"] = []
    recs[key] = existing
    _write_private_json(policies_record_path(), recs)


def _policy_record_key(recs: dict, policy_name: str, file_id: str = "") -> str | None:
    """Which record this upload belongs to, by id first and name second."""
    wanted_id = str(file_id or "").strip().lower().removeprefix("0x")
    if wanted_id:
        for key, record in recs.items():
            stored = str(record.get("policyId", "")).strip().lower().removeprefix("0x")
            if stored and stored == wanted_id:
                return key

    name_key = str(policy_name or "").strip().lower()
    if name_key and name_key in recs:
        return name_key

    if not name_key and not wanted_id:
        return None

    # Nothing matched: make the record rather than lose the upload.
    key = name_key or f"onchain_{wanted_id[:16]}"
    recs[key] = {
        "policyName": policy_name or f"0x{wanted_id[:14]}...",
        "policyId": f"0x{wanted_id}" if wanted_id else "",
        "guardians": [],
        "threshold": 0,
        "created": datetime.datetime.now().astimezone().isoformat(),
        "updated": "",
        "files": [],
        "requesters": [],
    }
    return key


def save_file_upload_record(policy_name: str, data_tag: str, date_str: str,
                            ts: int, pieces: list, file_id: str = ""):
    """Record a finished upload under its policy.

    Matched by policy id first, then by name. A policy recovered from the
    chain is stored under a generated key like "onchain_a1b2..." with the
    user's name unknown, so keying on the name alone meant an upload made
    right after a reinstall was dropped on the floor: the upload succeeded,
    the Policies tab showed the policy, and the file was simply not there,
    with nothing logged.

    A policy nobody has a record of is created rather than discarded. The
    pieces are stored and paid for either way; losing the only local note of
    them because of a missing dictionary key is not a trade worth making.
    """
    recs = load_policies_record()
    key = _policy_record_key(recs, policy_name, file_id)
    if key is None:
        return
    files = recs[key].get("files", [])
    files = [f for f in files if not (f.get("dataTag") == data_tag and f.get("date") == date_str)]
    piece_records = []
    upload_instance_id = ""
    for item in pieces:
        r = item.get("privateReceipt") or {}
        item_upload_id = str(item.get("uploadInstanceId", "") or "")
        if upload_instance_id and item_upload_id and item_upload_id != upload_instance_id:
            raise ValueError("one file upload record contains multiple uploadInstanceIds")
        if item_upload_id:
            upload_instance_id = item_upload_id
        piece_records.append({
            "pieceIndex": item.get("pieceIndex", 0),
            "pieceRoot": r.get("pieceRoot", item.get("pieceRoot", "")),
            "vkAddress": r.get("vkAddress", item.get("vkAddress", "")),
            "sectorRoot": r.get("sectorRoot", item.get("sectorRoot", "")),
            "sectorId": r.get("sectorId", item.get("sectorId", "")),
            "serviceEnd": r.get("serviceEnd", item.get("serviceEnd", 0)),
        })
    files.append({
        "uploadInstanceId": upload_instance_id,
        "dataTag": data_tag,
        "date": date_str,
        "ts": ts,
        "uploaded": datetime.datetime.now().astimezone().isoformat(),
        "pieces": piece_records,
    })
    recs[key]["files"] = files
    _write_private_json(policies_record_path(), recs)


def save_pk_cache(pk_data: dict, write_legacy: bool = True):
    os.makedirs(C.PK_CACHE_DIR, exist_ok=True)

    clean_file_id = normalize_pk_file_id(pk_data["fileId"])
    key_epoch = int(pk_data.get("keyEpoch", 0))

    data = dict(pk_data)
    data["fileId"] = clean_file_id
    if getattr(C,'DKG_ATTEMPT_PROTOCOL',0)==1:
        coordinator=C.config.ZKDKG_COORDINATOR_V2_ADDRESS.lower()
        chain_id=C.config.DKG_RECOVERY.get('chain_id',C.config.CHAIN_ID)
        if (data.get('coordinator',coordinator).lower()!=coordinator or data.get('chainId',chain_id)!=chain_id):
            raise ValueError('Public-key cache belongs to a different deployment')
        data.update(protocol=1,chainId=chain_id,coordinator=coordinator)

    with open(pk_latest_path(clean_file_id), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    if key_epoch > 0:
        with open(pk_epoch_path(clean_file_id, key_epoch), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def requester_book_path() -> str:
    return os.path.join(C.CID_RECORDS_DIR, "requester_book.json")


def load_requester_book() -> dict:
    p = requester_book_path()
    if not os.path.isfile(p):
        return {}
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_requester_to_book(addr: str, name: str):
    book = load_requester_book()
    key = addr.lower()
    existing_name = book.get(key, {}).get("name", "") if isinstance(book.get(key), dict) else book.get(key, "")
    book[key] = {"address": addr, "name": name.strip() if name.strip() else existing_name}
    Path(requester_book_path()).write_text(json.dumps(book, indent=2), encoding="utf-8")


def remove_from_requester_book(addr: str):
    book = load_requester_book()
    key = addr.lower()
    if key in book:
        del book[key]
        Path(requester_book_path()).write_text(json.dumps(book, indent=2), encoding="utf-8")


def get_policy_requesters(policy_name: str) -> list:
    """Return list of {address, name} dicts for the given policy."""
    recs = load_policies_record()
    key = policy_name.lower()
    if key not in recs:
        return []
    reqs = recs[key].get("requesters", {})
    if isinstance(reqs, list):
        # migrate old list-of-addresses format on read
        return [{"address": r, "name": ""} for r in reqs]
    return list(reqs.values())


def _update_policy_requesters(policy_name: str, req_addr: str, add: bool, name: str = ""):
    recs = load_policies_record()
    key = policy_name.lower()
    if key not in recs:
        return
    reqs = recs[key].get("requesters", {})
    # migrate old list-of-addresses format
    if isinstance(reqs, list):
        reqs = {r.lower(): {"address": r, "name": ""} for r in reqs}
    addr_lower = req_addr.lower()
    if add:
        reqs[addr_lower] = {"address": req_addr, "name": name.strip()}
    else:
        reqs.pop(addr_lower, None)
    recs[key]["requesters"] = reqs
    Path(policies_record_path()).write_text(json.dumps(recs, indent=2), encoding="utf-8")
