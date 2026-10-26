"""Authoritative, crash-safe lifecycle journal for VaultMesh pieces.

The JSON receipt manifests under ``pid_records`` are working/output files and
may be replaced between uploads.  This journal is the durable source of truth
for every local storage obligation, including incomplete uploads and deletion
jobs.  SQLite gives us transactional cross-process updates without exposing
piece secrets through the load-test registry or dashboard.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Iterable

from . import do_hex as HX


SCHEMA_VERSION = 2
_VALID_DELETION_STATES = {
    "active",
    "requested",
    "pending",
    "failed",
    "blocked",
    "disputed",
    "confirmed",
}
_TERMINAL_DELETION_STATE = "confirmed"
_DELETION_STATE_RANK = {
    "active": 0,
    "requested": 1,
    "pending": 2,
    "failed": 3,
    "blocked": 4,
    "disputed": 5,
    "confirmed": 6,
}
_VALID_UPLOAD_STATES = {
    "incomplete",
    "storage_complete",
    "completed",
    "cleanup_pending",
}
_UPLOAD_STATE_TRANSITIONS = {
    "incomplete": {"incomplete", "storage_complete", "cleanup_pending"},
    "storage_complete": {"storage_complete", "completed", "cleanup_pending"},
    "cleanup_pending": {"cleanup_pending", "completed"},
    "completed": {"completed"},
}
_recovery_lock = threading.RLock()
_recovered_bases: set[str] = set()


class PieceJournalError(RuntimeError):
    """The durable lifecycle state is missing, corrupt, or contradictory."""


class AmbiguousPieceReference(PieceJournalError):
    """A non-unique piece root was supplied where a commitment was required."""


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def journal_path(base_dir: str | os.PathLike) -> Path:
    # transfer_jobs is intentionally durable across individual uploads and is
    # already excluded from role release archives because it contains secrets.
    return Path(base_dir) / "transfer_jobs" / "piece_lifecycle.sqlite3"


def _prepare_path(base_dir: str | os.PathLike) -> Path:
    path = journal_path(base_dir)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    # sqlite3.connect() otherwise creates the database using the process
    # umask.  Pre-create it with owner-only permissions so there is never a
    # window in which private receipts or deletion secrets are world-readable.
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file():
            raise PieceJournalError(
                "piece lifecycle journal path is not a regular file"
            )
    except OSError as exc:
        raise PieceJournalError(
            f"piece lifecycle journal cannot be created safely: {exc}"
        ) from exc
    else:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        raise PieceJournalError(
            f"piece lifecycle journal permissions cannot be secured: {exc}"
        ) from exc
    return path


def _secure_sqlite_files(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if candidate.exists():
            try:
                os.chmod(candidate, 0o600)
            except OSError:
                pass


def _enable_wal(connection: sqlite3.Connection) -> None:
    """Put the journal in WAL mode, without failing when someone else has it.

    Changing the journal mode takes a brief exclusive lock, and that one
    statement does not honour `busy_timeout`: SQLite refuses immediately with
    "database is locked" if any other connection has the file open. Every other
    statement here waits up to thirty seconds; this one never did, so running
    it on every open turned ordinary overlap into a failed save -- eight
    threads registering pieces at once lost one about a fifth of the time.

    The mode is a property of the file and survives, so it only has to be set
    once, by whoever gets there first. Reading it costs no lock. A refusal
    after that is not a problem worth reporting: the mode is either already
    WAL, or the connection that is holding the lock is in the middle of setting
    it.
    """
    try:
        current = connection.execute("PRAGMA journal_mode").fetchone()
        mode = str(current[0]).lower() if current else ""
        if mode == "wal":
            return
    except sqlite3.Error:
        pass  # fall through and try to set it

    try:
        connection.execute("PRAGMA journal_mode = WAL")
    except sqlite3.OperationalError:
        # Another connection is setting it, or has it open. Either way this
        # connection is usable; a genuinely unusable database fails on the
        # statements below, which do wait their turn.
        pass


def _connect(base_dir: str | os.PathLike) -> sqlite3.Connection:
    path = _prepare_path(base_dir)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        _enable_wal(connection)
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not {"journal_meta", "piece_lifecycle"} <= tables:
            connection.executescript(
                """
            CREATE TABLE IF NOT EXISTS journal_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS piece_lifecycle (
                record_key TEXT PRIMARY KEY,
                commitment_hash TEXT,
                logical_job_id TEXT NOT NULL DEFAULT '',
                transfer_id TEXT NOT NULL DEFAULT '',
                upload_instance_id TEXT NOT NULL DEFAULT '',
                chain_id TEXT NOT NULL DEFAULT '',
                file_registration_contract TEXT NOT NULL DEFAULT '',
                file_id TEXT NOT NULL,
                piece_index INTEGER NOT NULL,
                piece_root TEXT NOT NULL,
                deletion_status TEXT NOT NULL,
                deleted INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            """
            )
        required_columns = {
            "transfer_id",
            "upload_instance_id",
            "chain_id",
            "file_registration_contract",
        }
        required_indexes = {
            "piece_lifecycle_commitment_ns_uq",
            "piece_lifecycle_active_logical_uq",
            "piece_lifecycle_active_transfer_uq",
            "piece_lifecycle_file_idx",
            "piece_lifecycle_upload_idx",
            "piece_lifecycle_namespace_idx",
            "piece_lifecycle_root_idx",
            "piece_lifecycle_deletion_idx",
        }
        initial_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(piece_lifecycle)")
        }
        initial_version_row = connection.execute(
            "SELECT value FROM journal_meta WHERE key = 'schema_version'"
        ).fetchone()
        initial_indexes = {
            str(row["name"])
            for row in connection.execute("PRAGMA index_list(piece_lifecycle)")
        }
        if (
            initial_version_row is not None
            and int(initial_version_row["value"]) == SCHEMA_VERSION
            and required_columns <= initial_columns
            and required_indexes <= initial_indexes
            and "piece_lifecycle_commitment_uq" not in initial_indexes
        ):
            _secure_sqlite_files(path)
            return connection

        connection.execute("BEGIN IMMEDIATE")
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(piece_lifecycle)")
        }
        added_columns = False
        for name in required_columns:
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE piece_lifecycle ADD COLUMN {name} "
                    "TEXT NOT NULL DEFAULT ''"
                )
                added_columns = True

        version_row = connection.execute(
            "SELECT value FROM journal_meta WHERE key = 'schema_version'"
        ).fetchone()
        existing_version = (
            int(version_row["value"]) if version_row is not None else SCHEMA_VERSION
        )
        if added_columns or existing_version == 1:
            _migrate_index_columns(connection)
        if version_row is None:
            connection.execute(
                """
                INSERT INTO journal_meta(key, value)
                VALUES('schema_version', ?)
                ON CONFLICT(key) DO NOTHING
                """,
                (str(SCHEMA_VERSION),),
            )
        else:
            if existing_version not in {1, SCHEMA_VERSION}:
                raise PieceJournalError(
                    "unsupported piece lifecycle journal schema "
                    f"{existing_version} (expected 1 or {SCHEMA_VERSION})"
                )
            if existing_version == 1:
                connection.execute(
                    "UPDATE journal_meta SET value = ? WHERE key = 'schema_version'",
                    (str(SCHEMA_VERSION),),
                )

        # Version 1 treated a commitment as globally unique.  Commitments are
        # scoped to a particular chain and FileRegistration deployment.
        connection.execute("DROP INDEX IF EXISTS piece_lifecycle_commitment_uq")
        index_statements = (
            """CREATE UNIQUE INDEX IF NOT EXISTS piece_lifecycle_commitment_ns_uq
                ON piece_lifecycle(
                    chain_id, file_registration_contract, commitment_hash
                )
                WHERE commitment_hash IS NOT NULL AND commitment_hash != ''""",
            """CREATE UNIQUE INDEX IF NOT EXISTS piece_lifecycle_active_logical_uq
                ON piece_lifecycle(
                    chain_id, file_registration_contract,
                    upload_instance_id, logical_job_id
                )
                WHERE logical_job_id != '' AND deletion_status != 'confirmed'""",
            """CREATE UNIQUE INDEX IF NOT EXISTS piece_lifecycle_active_transfer_uq
                ON piece_lifecycle(
                    chain_id, file_registration_contract,
                    upload_instance_id, transfer_id
                )
                WHERE transfer_id != '' AND deletion_status != 'confirmed'""",
            """CREATE INDEX IF NOT EXISTS piece_lifecycle_file_idx
                ON piece_lifecycle(file_id, piece_index)""",
            """CREATE INDEX IF NOT EXISTS piece_lifecycle_upload_idx
                ON piece_lifecycle(upload_instance_id, file_id, piece_index)""",
            """CREATE INDEX IF NOT EXISTS piece_lifecycle_namespace_idx
                ON piece_lifecycle(chain_id, file_registration_contract)""",
            """CREATE INDEX IF NOT EXISTS piece_lifecycle_root_idx
                ON piece_lifecycle(piece_root)""",
            """CREATE INDEX IF NOT EXISTS piece_lifecycle_deletion_idx
                ON piece_lifecycle(deletion_status, deleted)""",
        )
        for statement in index_statements:
            connection.execute(statement)
        connection.commit()
    except (sqlite3.Error, ValueError, PieceJournalError) as exc:
        try:
            if connection is not None:
                connection.rollback()
                connection.close()
        except Exception:
            pass
        if isinstance(exc, PieceJournalError):
            raise
        raise PieceJournalError(f"piece lifecycle journal cannot be opened safely: {exc}") from exc
    _secure_sqlite_files(path)
    return connection


def _canonical_optional_bytes32(value: object, field: str) -> str:
    if not HX.strip_hex_prefix(value):
        return ""
    return "0x" + HX.normalize_hex(value, expected_bytes=32, field=field)


def _normalize_upload_instance_id(value: object) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if len(normalized) > 256 or any(ord(char) < 0x20 for char in normalized):
        raise PieceJournalError("uploadInstanceId is invalid")
    return normalized


def _normalize_chain_id(value: object) -> str:
    if value in (None, ""):
        return ""
    try:
        if isinstance(value, bool):
            raise ValueError("boolean chain id")
        if isinstance(value, int):
            chain_id = value
        elif isinstance(value, str) and value.strip().lower().startswith("0x"):
            chain_id = int(value.strip(), 16)
        elif isinstance(value, str):
            text = value.strip()
            if not text or not text.isdecimal():
                raise ValueError("non-decimal chain id")
            chain_id = int(text, 10)
        else:
            raise ValueError("unsupported chain id type")
    except (TypeError, ValueError) as exc:
        raise PieceJournalError("chainId is invalid") from exc
    if chain_id < 0 or chain_id >= 2**256:
        raise PieceJournalError("chainId is outside the uint256 range")
    return str(chain_id)


def _normalize_contract(value: object) -> str:
    if not HX.strip_hex_prefix(value):
        return ""
    try:
        return "0x" + HX.normalize_hex(
            value,
            expected_bytes=20,
            field="fileRegistrationContract",
        )
    except ValueError as exc:
        raise PieceJournalError(str(exc)) from exc


def _namespace_values(
    *,
    chain_id: object = "",
    file_registration_contract: object = "",
) -> tuple[str, str]:
    return (
        _normalize_chain_id(chain_id),
        _normalize_contract(file_registration_contract),
    )


def _receipt(item: dict) -> dict:
    value = item.get("privateReceipt")
    return value if isinstance(value, dict) else {}


def _piece_value(item: dict, *keys: str) -> object:
    receipt = _receipt(item)
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
        value = receipt.get(key)
        if value not in (None, ""):
            return value
    return ""


def _live_generation_pieces(pieces: list) -> list:
    """Drop pieces whose deletion is already settled, when live ones remain.

    One upload generation may hold several rows for the same piece index: a
    partial delete settles the first, and the re-upload of that piece is a new
    row under the same uploadInstanceId. The settled row owns no bytes and no
    escrow, and its lifecycle can no longer move -- ``cleanup_pending`` and
    ``completed`` are its only states -- so including it in a generation-wide
    transition permanently blocks the live pieces beside it.

    A generation whose every piece is settled keeps them all, because the
    cleanup path still has to move that generation to its final state.
    """
    live = [piece for piece in pieces if not _normalize_deletion_state(piece)[1]]
    return live or list(pieces)


def _normalize_deletion_state(item: dict) -> tuple[str, bool]:
    raw = str(
        item.get("deletionStatus", "")
        or item.get("deleteStatus", "")
        or ""
    ).strip().lower()
    aliases = {
        "deleted": "confirmed",
        "deletion_confirmed": "confirmed",
        "deleting": "pending",
    }
    state = aliases.get(raw, raw)
    if bool(item.get("deleted")):
        state = "confirmed"
    if not state:
        state = "active"
    if state not in _VALID_DELETION_STATES:
        raise PieceJournalError(f"unknown deletion lifecycle state: {state}")
    return state, state == _TERMINAL_DELETION_STATE


def _normalize_piece(item: dict) -> dict:
    if not isinstance(item, dict):
        raise PieceJournalError("piece lifecycle record must be an object")
    normalized = dict(item)
    if "privateReceipt" in normalized and normalized["privateReceipt"] not in (None, {}):
        if not isinstance(normalized["privateReceipt"], dict):
            raise PieceJournalError("privateReceipt must be an object")
    file_id = HX.normalize_file_id(_piece_value(normalized, "fileId"))
    piece_root = _canonical_optional_bytes32(
        _piece_value(normalized, "pieceRoot"), "pieceRoot"
    )
    commitment_hash = _canonical_optional_bytes32(
        _piece_value(normalized, "commitmentHash"), "commitmentHash"
    )
    logical_job_id = str(normalized.get("logicalJobId", "") or "").strip()
    transfer_id = str(normalized.get("transferId", "") or "").strip()
    if len(transfer_id) > 256 or any(ord(char) < 0x20 for char in transfer_id):
        raise PieceJournalError("transferId is invalid")
    upload_instance_id = _normalize_upload_instance_id(
        normalized.get("uploadInstanceId", "")
    )
    chain_id = _normalize_chain_id(_piece_value(normalized, "chainId"))
    file_registration_contract = _normalize_contract(
        _piece_value(normalized, "fileRegistrationContract")
    )
    try:
        piece_index = int(normalized.get("pieceIndex", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise PieceJournalError("pieceIndex is invalid") from exc
    if piece_index <= 0:
        raise PieceJournalError("pieceIndex must be positive")
    if not piece_root and not commitment_hash:
        raise PieceJournalError(
            "piece lifecycle record needs a pieceRoot or commitmentHash"
        )
    if not commitment_hash and not logical_job_id and not transfer_id:
        raise PieceJournalError(
            "unregistered piece lifecycle record needs a logicalJobId or transferId"
        )

    normalized["fileId"] = file_id
    normalized["pieceIndex"] = piece_index
    if piece_root:
        normalized["pieceRoot"] = piece_root
    if commitment_hash:
        normalized["commitmentHash"] = commitment_hash
    if logical_job_id:
        normalized["logicalJobId"] = logical_job_id
    else:
        normalized["logicalJobId"] = ""
    normalized["transferId"] = transfer_id
    normalized["uploadInstanceId"] = upload_instance_id
    normalized["chainId"] = chain_id
    normalized["fileRegistrationContract"] = file_registration_contract
    if "uploadLifecycleStatus" in normalized:
        upload_state = str(
            normalized.get("uploadLifecycleStatus", "") or ""
        ).strip().lower()
        if upload_state not in _VALID_UPLOAD_STATES:
            raise PieceJournalError(
                f"invalid upload lifecycle state: {upload_state}"
            )
        normalized["uploadLifecycleStatus"] = upload_state

    receipt = dict(_receipt(normalized))
    if receipt:
        # Keep the signed receipt byte-for-byte equivalent.  Canonical fields
        # live on the journal item; adding/changing receipt fields could affect
        # later signature or dispute verification.
        normalized["privateReceipt"] = receipt

    deletion_status, deleted = _normalize_deletion_state(normalized)
    normalized["deletionStatus"] = deletion_status
    normalized["deleted"] = deleted
    return normalized


def _record_key(item: dict) -> str:
    commitment = str(item.get("commitmentHash", "") or "")
    namespace = (
        str(item.get("chainId", "") or ""),
        str(item.get("fileRegistrationContract", "") or ""),
    )
    if commitment:
        material = "|".join(("commitment", *namespace, commitment))
    else:
        transfer_id = str(item.get("transferId", "") or "")
        if not transfer_id:
            raise PieceJournalError(
                "new pre-registration records require a durable transferId"
            )
        material = "|".join(
            (
                "precommit-transfer",
                *namespace,
                str(item.get("uploadInstanceId", "") or ""),
                transfer_id,
            )
        )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _immutable_value(item: dict, key: str) -> str:
    value = _piece_value(item, key)
    if key in {"fileId"} and value not in (None, ""):
        return HX.normalize_file_id(value)
    if key in {"pieceRoot", "commitmentHash", "deletionAuthHash"} and value not in (None, ""):
        return _canonical_optional_bytes32(value, key)
    if key == "uploadInstanceId":
        return _normalize_upload_instance_id(value)
    if key == "chainId":
        return _normalize_chain_id(value)
    if key == "fileRegistrationContract":
        return _normalize_contract(value)
    return str(value or "").strip().lower()


def _receipt_fingerprint(value: dict) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise PieceJournalError("privateReceipt is not valid JSON") from exc


def _indexed_values(item: dict) -> dict[str, object]:
    return {
        "commitment_hash": str(item.get("commitmentHash", "") or ""),
        "logical_job_id": str(item.get("logicalJobId", "") or ""),
        "transfer_id": str(item.get("transferId", "") or ""),
        "upload_instance_id": str(item.get("uploadInstanceId", "") or ""),
        "chain_id": str(item.get("chainId", "") or ""),
        "file_registration_contract": str(
            item.get("fileRegistrationContract", "") or ""
        ),
        "file_id": str(item["fileId"]),
        "piece_index": int(item["pieceIndex"]),
        "piece_root": str(item.get("pieceRoot", "") or ""),
        "deletion_status": str(item["deletionStatus"]),
        "deleted": 1 if item.get("deleted") else 0,
    }


def _assert_row_matches_payload(row: sqlite3.Row, item: dict) -> None:
    journal_key = str(item.get("journalKey", "") or "")
    if journal_key and journal_key != str(row["record_key"]):
        raise PieceJournalError(
            f"piece lifecycle record {row['record_key']} has a conflicting journalKey"
        )
    for column, expected in _indexed_values(item).items():
        actual = row[column]
        if column == "commitment_hash":
            actual = str(actual or "")
        elif column in {"piece_index", "deleted"}:
            actual = int(actual)
        else:
            actual = str(actual or "")
        if actual != expected:
            raise PieceJournalError(
                f"piece lifecycle record {row['record_key']} has inconsistent "
                f"indexed {column}"
            )


def _migrate_index_columns(connection: sqlite3.Connection) -> None:
    """Backfill v1 payload fields while rejecting pre-existing contradictions."""
    rows = connection.execute("SELECT * FROM piece_lifecycle").fetchall()
    for row in rows:
        try:
            raw = json.loads(row["payload_json"])
        except Exception as exc:
            raise PieceJournalError(
                f"piece lifecycle record {row['record_key']} contains invalid JSON"
            ) from exc
        if not isinstance(raw, dict):
            raise PieceJournalError(
                f"piece lifecycle record {row['record_key']} is not an object"
            )
        raw_journal_key = str(raw.get("journalKey", "") or "")
        if raw_journal_key and raw_journal_key != str(row["record_key"]):
            raise PieceJournalError(
                f"piece lifecycle record {row['record_key']} has a conflicting journalKey"
            )
        item = _normalize_piece(raw)
        # Columns present in v1 were already integrity indexes and must agree
        # with the payload.  Only newly introduced v2 columns are backfilled.
        for column in (
            "commitment_hash",
            "logical_job_id",
            "file_id",
            "piece_index",
            "piece_root",
            "deletion_status",
            "deleted",
        ):
            expected = _indexed_values(item)[column]
            actual = row[column]
            if column == "commitment_hash":
                actual = str(actual or "")
            elif column in {"piece_index", "deleted"}:
                actual = int(actual)
            else:
                actual = str(actual or "")
            if actual != expected:
                raise PieceJournalError(
                    f"piece lifecycle record {row['record_key']} has inconsistent "
                    f"indexed {column}"
                )
        item["journalKey"] = str(row["record_key"])
        indexed = _indexed_values(item)
        connection.execute(
            """
            UPDATE piece_lifecycle
               SET transfer_id = ?, upload_instance_id = ?, chain_id = ?,
                   file_registration_contract = ?, payload_json = ?
             WHERE record_key = ?
            """,
            (
                indexed["transfer_id"],
                indexed["upload_instance_id"],
                indexed["chain_id"],
                indexed["file_registration_contract"],
                json.dumps(item, sort_keys=True, separators=(",", ":")),
                str(row["record_key"]),
            ),
        )


def _merge_piece(
    existing: dict | None,
    incoming: dict,
    *,
    incoming_has_lifecycle: bool,
) -> dict:
    incoming = _normalize_piece(incoming)
    if existing is None:
        merged = incoming
        merged.setdefault("uploadLifecycleStatus", "incomplete")
        merged.setdefault("journalCreatedAt", _utc_now())
        merged["journalUpdatedAt"] = _utc_now()
        return merged

    existing = _normalize_piece(existing)
    immutable_fields = (
        "uploadInstanceId",
        "chainId",
        "fileRegistrationContract",
        "fileId",
        "pieceIndex",
        "pieceRoot",
        "commitmentHash",
        "logicalJobId",
        "transferId",
        "vkAddress",
        "commitmentNonce",
        "deletionAuthSecret",
        "deletionAuthHash",
        "serviceEnd",
        "registrationTxHash",
    )
    for field in immutable_fields:
        old = _immutable_value(existing, field)
        new = _immutable_value(incoming, field)
        if old and new and old != new:
            raise PieceJournalError(
                f"conflicting immutable {field} for one storage obligation"
            )

    old_receipt = _receipt(existing)
    new_receipt = _receipt(incoming)
    if (
        old_receipt
        and new_receipt
        and _receipt_fingerprint(old_receipt) != _receipt_fingerprint(new_receipt)
    ):
        raise PieceJournalError(
            "conflicting signed privateReceipt for one storage obligation"
        )

    old_upload_state = str(
        existing.get("uploadLifecycleStatus", "incomplete") or "incomplete"
    ).strip().lower()
    if "uploadLifecycleStatus" in incoming:
        new_upload_state = str(incoming["uploadLifecycleStatus"]).strip().lower()
        if new_upload_state not in _UPLOAD_STATE_TRANSITIONS[old_upload_state]:
            raise PieceJournalError(
                f"invalid upload lifecycle transition: "
                f"{old_upload_state} -> {new_upload_state}"
            )

    merged = dict(existing)
    merged.update(incoming)
    # Missing data from an older recovery source may enrich nothing, but it
    # must never erase identity learned from a signed receipt/current runtime.
    for field in immutable_fields:
        old = _immutable_value(existing, field)
        new = _immutable_value(incoming, field)
        if old and not new and field in existing:
            merged[field] = existing[field]
    old_state, old_deleted = _normalize_deletion_state(existing)
    incoming_state, _ = _normalize_deletion_state(incoming)
    stale_lifecycle = (
        not incoming_has_lifecycle
        or _DELETION_STATE_RANK[incoming_state] < _DELETION_STATE_RANK[old_state]
    )
    if old_deleted or stale_lifecycle:
        # A stale transfer/lifecycle result can never move deletion backwards.
        merged["deletionStatus"] = old_state
        merged["deleted"] = old_deleted
        for key, value in existing.items():
            if key.startswith("deletion"):
                merged[key] = value

    # Positive chain evidence is monotonic even when a later RPC observation
    # is incomplete or a stale worker reports an older lifecycle state.
    for field in (
        "deletionDeclared",
        "deletionConfirmed",
        "deletionEvidenceOk",
        "deletionDisputeFiled",
        "deletionDisputeSubmitted",
        "deletionAuthHashRegistered",
    ):
        merged[field] = bool(existing.get(field)) or bool(incoming.get(field))
    for field in ("deletionAttempts",):
        try:
            merged[field] = max(
                int(existing.get(field, 0) or 0),
                int(incoming.get(field, 0) or 0),
            )
        except (TypeError, ValueError) as exc:
            raise PieceJournalError(f"{field} is invalid") from exc
    for field in ("deletionDeclaredAt", "deletionGraceSeconds"):
        try:
            old_value = int(existing.get(field, 0) or 0)
            new_value = int(incoming.get(field, 0) or 0)
        except (TypeError, ValueError) as exc:
            raise PieceJournalError(f"{field} is invalid") from exc
        if old_value and new_value and old_value != new_value:
            raise PieceJournalError(f"conflicting {field} chain evidence")
        if old_value or new_value:
            merged[field] = old_value or new_value
    old_confirmed_at = int(existing.get("deletionConfirmedAt", 0) or 0)
    new_confirmed_at = int(incoming.get("deletionConfirmedAt", 0) or 0)
    if old_confirmed_at and new_confirmed_at and old_confirmed_at != new_confirmed_at:
        raise PieceJournalError(
            "conflicting deletionConfirmedAt chain evidence"
        )
    if old_confirmed_at or new_confirmed_at:
        merged["deletionConfirmedAt"] = old_confirmed_at or new_confirmed_at

    merged.setdefault("journalCreatedAt", existing.get("journalCreatedAt") or _utc_now())
    merged["journalUpdatedAt"] = _utc_now()
    return _normalize_piece(merged)


def _row_payload(row: sqlite3.Row) -> dict:
    try:
        value = json.loads(row["payload_json"])
    except Exception as exc:
        raise PieceJournalError(
            f"piece lifecycle record {row['record_key']} contains invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise PieceJournalError(
            f"piece lifecycle record {row['record_key']} is not an object"
        )
    normalized = _normalize_piece(value)
    _assert_row_matches_payload(row, normalized)
    normalized["journalKey"] = str(row["record_key"])
    return normalized


def _find_existing_row(connection: sqlite3.Connection, item: dict) -> sqlite3.Row | None:
    commitment = str(item.get("commitmentHash", "") or "")
    chain_id = str(item.get("chainId", "") or "")
    contract = str(item.get("fileRegistrationContract", "") or "")
    upload_instance_id = str(item.get("uploadInstanceId", "") or "")
    if commitment:
        # A v1 record or stale recovery source may not know its deployment
        # namespace. Adopt one compatible record; never guess between candidates.
        compatible = connection.execute(
            """
            SELECT * FROM piece_lifecycle
             WHERE commitment_hash = ?
               AND (? = '' OR chain_id = ? OR chain_id = '')
               AND (? = '' OR file_registration_contract = ?
                    OR file_registration_contract = '')
             ORDER BY created_at, record_key
            """,
            (commitment, chain_id, chain_id, contract, contract),
        ).fetchall()
        if len(compatible) > 1:
            raise PieceJournalError(
                "commitmentHash is ambiguous across chain namespaces"
            )
        if compatible:
            return compatible[0]

    logical_job_id = str(item.get("logicalJobId", "") or "")
    if logical_job_id:
        compatible = connection.execute(
            """
            SELECT * FROM piece_lifecycle
             WHERE logical_job_id = ? AND deletion_status != 'confirmed'
               AND (? = '' OR chain_id = ? OR chain_id = '')
               AND (? = '' OR file_registration_contract = ?
                    OR file_registration_contract = '')
               AND (? = '' OR upload_instance_id = ? OR upload_instance_id = '')
             ORDER BY created_at, record_key
            """,
            (
                logical_job_id,
                chain_id,
                chain_id,
                contract,
                contract,
                upload_instance_id,
                upload_instance_id,
            ),
        ).fetchall()
        if len(compatible) > 1:
            raise PieceJournalError("multiple active records share one logical generation")
        if compatible:
            return compatible[0]

    transfer_id = str(item.get("transferId", "") or "")
    if transfer_id:
        rows = connection.execute(
            """
            SELECT * FROM piece_lifecycle
             WHERE transfer_id = ?
               AND deletion_status != 'confirmed'
               AND (? = '' OR chain_id = ? OR chain_id = '')
               AND (? = '' OR file_registration_contract = ?
                    OR file_registration_contract = '')
               AND (? = '' OR upload_instance_id = ? OR upload_instance_id = '')
             ORDER BY created_at, record_key
            """,
            (
                transfer_id,
                chain_id,
                chain_id,
                contract,
                contract,
                upload_instance_id,
                upload_instance_id,
            ),
        ).fetchall()
        if len(rows) > 1:
            raise PieceJournalError(
                "multiple active records share one transferId"
            )
        if rows:
            return rows[0]
    return None


def record_registration(
    base_dir: str | os.PathLike,
    item: dict,
    *,
    source: str = "runtime",
) -> dict:
    """Insert or merge one piece without ever removing another piece."""
    incoming_has_lifecycle = (
        "deletionStatus" in item
        or "deleteStatus" in item
        or bool(item.get("deleted"))
    )
    normalized = _normalize_piece(item)
    sources = set(str(value) for value in normalized.get("journalSources", []) if value)
    sources.add(str(source))
    normalized["journalSources"] = sorted(sources)
    connection = _connect(base_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = _find_existing_row(connection, normalized)
        existing = _row_payload(row) if row is not None else None
        if existing is not None:
            sources.update(
                str(value) for value in existing.get("journalSources", []) if value
            )
            normalized["journalSources"] = sorted(sources)
        merged = _merge_piece(
            existing,
            normalized,
            incoming_has_lifecycle=incoming_has_lifecycle,
        )
        record_key = row["record_key"] if row is not None else _record_key(merged)
        if row is None:
            key_collision = connection.execute(
                "SELECT record_key FROM piece_lifecycle WHERE record_key = ?",
                (record_key,),
            ).fetchone()
            if key_collision is not None:
                raise PieceJournalError(
                    "durable transfer identity was already used by another "
                    "storage obligation"
                )
        merged["journalKey"] = record_key
        commitment = str(merged.get("commitmentHash", "") or "") or None
        created_at = (
            str(row["created_at"])
            if row is not None
            else str(merged.get("journalCreatedAt") or _utc_now())
        )
        updated_at = str(merged.get("journalUpdatedAt") or _utc_now())
        payload_json = json.dumps(merged, sort_keys=True, separators=(",", ":"))
        connection.execute(
            """
            INSERT INTO piece_lifecycle(
                record_key, commitment_hash, logical_job_id, transfer_id,
                upload_instance_id, chain_id, file_registration_contract, file_id,
                piece_index, piece_root, deletion_status, deleted,
                payload_json, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_key) DO UPDATE SET
                commitment_hash=excluded.commitment_hash,
                logical_job_id=excluded.logical_job_id,
                transfer_id=excluded.transfer_id,
                upload_instance_id=excluded.upload_instance_id,
                chain_id=excluded.chain_id,
                file_registration_contract=excluded.file_registration_contract,
                file_id=excluded.file_id,
                piece_index=excluded.piece_index,
                piece_root=excluded.piece_root,
                deletion_status=excluded.deletion_status,
                deleted=excluded.deleted,
                payload_json=excluded.payload_json,
                updated_at=excluded.updated_at
            """,
            (
                record_key,
                commitment,
                str(merged.get("logicalJobId", "") or ""),
                str(merged.get("transferId", "") or ""),
                str(merged.get("uploadInstanceId", "") or ""),
                str(merged.get("chainId", "") or ""),
                str(merged.get("fileRegistrationContract", "") or ""),
                merged["fileId"],
                int(merged["pieceIndex"]),
                str(merged.get("pieceRoot", "") or ""),
                str(merged["deletionStatus"]),
                1 if merged.get("deleted") else 0,
                payload_json,
                created_at,
                updated_at,
            ),
        )
        written = connection.execute(
            "SELECT * FROM piece_lifecycle WHERE record_key = ?",
            (record_key,),
        ).fetchone()
        if written is None:
            raise PieceJournalError("piece lifecycle write was not durable")
        _row_payload(written)
        connection.commit()
        return dict(merged)
    except (sqlite3.Error, ValueError, PieceJournalError) as exc:
        connection.rollback()
        if isinstance(exc, PieceJournalError):
            raise
        raise PieceJournalError(f"piece lifecycle update failed: {exc}") from exc
    finally:
        connection.close()
        _secure_sqlite_files(journal_path(base_dir))


def record_many(
    base_dir: str | os.PathLike,
    pieces: Iterable[dict],
    *,
    source: str,
) -> list[dict]:
    # Each record is its own fully durable transaction.  A crash can leave a
    # prefix imported, and the idempotent recovery pass safely completes it.
    return [record_registration(base_dir, piece, source=source) for piece in pieces]


def _legacy_pieces(base_dir: str | os.PathLike) -> list[tuple[str, dict]]:
    recovered: list[tuple[str, dict]] = []
    receipt_path = Path(base_dir) / "pid_records" / "vaultmesh_piece_receipts.json"
    if receipt_path.is_file():
        try:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PieceJournalError(
                f"legacy piece receipt manifest is corrupt: {exc}"
            ) from exc
        pieces = payload.get("pieces", []) if isinstance(payload, dict) else payload
        if not isinstance(pieces, list):
            raise PieceJournalError("legacy piece receipt manifest has invalid pieces")
        recovered.extend(("legacy-receipt-manifest", piece) for piece in pieces)

    uploads_dir = Path(base_dir) / "transfer_jobs" / "uploads"
    if uploads_dir.is_dir():
        for path in sorted(uploads_dir.glob("*.json")):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise PieceJournalError(f"durable transfer job is corrupt: {path}: {exc}") from exc
            if str(job.get("status", "")) != "completed" or not isinstance(job.get("result"), dict):
                continue
            item = dict(job["result"])
            for target, source_key in (
                ("fileId", "fileId"),
                ("pieceIndex", "pieceIndex"),
                ("logicalJobId", "logicalJobId"),
                ("transferId", "transferId"),
                ("commitmentNonce", "commitmentNonce"),
                ("deletionAuthSecret", "deletionAuthSecret"),
                ("sourceDigest", "fileDigest"),
            ):
                if not item.get(target) and job.get(source_key) not in (None, ""):
                    item[target] = job[source_key]
            recovered.append(("completed-transfer-job", item))

    queue_dir = Path(base_dir) / "storage_verification_queue"
    if queue_dir.is_dir():
        for path in sorted(queue_dir.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise PieceJournalError(
                    f"storage verification recovery record is corrupt: {path}: {exc}"
                ) from exc
            item = record.get("item")
            if isinstance(item, dict):
                recovered.append(("storage-verification-queue", dict(item)))
    return recovered


def ensure_recovered(
    base_dir: str | os.PathLike,
    *,
    force: bool = False,
) -> int:
    """Idempotently migrate all legacy sources before lifecycle operations."""
    base_key = str(Path(base_dir).resolve())
    with _recovery_lock:
        if not force and base_key in _recovered_bases:
            return 0
        connection = _connect(base_dir)
        try:
            row = connection.execute(
                "SELECT value FROM journal_meta WHERE key = 'legacy_recovery_complete'"
            ).fetchone()
        finally:
            connection.close()
        if row is not None and not force:
            _recovered_bases.add(base_key)
            return 0

        imported = 0
        for source, item in _legacy_pieces(base_dir):
            record_registration(base_dir, item, source=source)
            imported += 1

        connection = _connect(base_dir)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO journal_meta(key, value)
                VALUES('legacy_recovery_complete', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (_utc_now(),),
            )
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise PieceJournalError(f"journal recovery checkpoint failed: {exc}") from exc
        finally:
            connection.close()
        _recovered_bases.add(base_key)
        return imported


def list_pieces(
    base_dir: str | os.PathLike,
    *,
    file_id: object | None = None,
    upload_instance_id: object | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
    include_deleted: bool = True,
    recover: bool = True,
) -> list[dict]:
    if recover:
        ensure_recovered(base_dir)
    params: list[object] = []
    where: list[str] = []
    if file_id not in (None, ""):
        where.append("file_id = ?")
        params.append(HX.normalize_file_id(file_id))
    if upload_instance_id not in (None, ""):
        where.append("upload_instance_id = ?")
        params.append(_normalize_upload_instance_id(upload_instance_id))
    namespace_chain, namespace_contract = _namespace_values(
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    if chain_id not in (None, ""):
        where.append("chain_id = ?")
        params.append(namespace_chain)
    if file_registration_contract not in (None, ""):
        where.append("file_registration_contract = ?")
        params.append(namespace_contract)
    if not include_deleted:
        where.append("deleted = 0")
    sql = "SELECT * FROM piece_lifecycle"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at, file_id, piece_index, record_key"
    connection = _connect(base_dir)
    try:
        return [_row_payload(row) for row in connection.execute(sql, params).fetchall()]
    except sqlite3.Error as exc:
        raise PieceJournalError(f"piece lifecycle read failed: {exc}") from exc
    finally:
        connection.close()


def load_manifest(
    base_dir: str | os.PathLike,
    *,
    file_id: object | None = None,
    upload_instance_id: object | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
    include_deleted: bool = True,
    recover: bool = True,
) -> dict:
    pieces = list_pieces(
        base_dir,
        file_id=file_id,
        upload_instance_id=upload_instance_id,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        include_deleted=include_deleted,
        recover=recover,
    )
    return {
        "schema": "filetrust-do-piece-lifecycle",
        "schemaVersion": SCHEMA_VERSION,
        "storage": "vaultmesh",
        "pieces": pieces,
    }


def get_by_commitment(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict | None:
    commitment = _canonical_optional_bytes32(commitment_hash, "commitmentHash")
    if not commitment:
        raise PieceJournalError("commitmentHash is required")
    ensure_recovered(base_dir)
    connection = _connect(base_dir)
    try:
        params: list[object] = [commitment]
        where = ["commitment_hash = ?"]
        namespace_chain, namespace_contract = _namespace_values(
            chain_id=chain_id,
            file_registration_contract=file_registration_contract,
        )
        if chain_id not in (None, ""):
            where.append("chain_id = ?")
            params.append(namespace_chain)
        if file_registration_contract not in (None, ""):
            where.append("file_registration_contract = ?")
            params.append(namespace_contract)
        rows = connection.execute(
            "SELECT * FROM piece_lifecycle WHERE " + " AND ".join(where),
            params,
        ).fetchall()
        if len(rows) > 1:
            raise PieceJournalError(
                "commitmentHash exists in multiple chain namespaces; "
                "chainId and fileRegistrationContract are required"
            )
        return _row_payload(rows[0]) if rows else None
    finally:
        connection.close()


def find_by_piece_root(
    base_dir: str | os.PathLike,
    piece_root: object,
    *,
    include_deleted: bool = True,
    upload_instance_id: object | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> list[dict]:
    root = _canonical_optional_bytes32(piece_root, "pieceRoot")
    if not root:
        raise PieceJournalError("pieceRoot is required")
    ensure_recovered(base_dir)
    params: list[object] = [root]
    where = ["piece_root = ?"]
    if not include_deleted:
        where.append("deleted = 0")
    if upload_instance_id not in (None, ""):
        where.append("upload_instance_id = ?")
        params.append(_normalize_upload_instance_id(upload_instance_id))
    namespace_chain, namespace_contract = _namespace_values(
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    if chain_id not in (None, ""):
        where.append("chain_id = ?")
        params.append(namespace_chain)
    if file_registration_contract not in (None, ""):
        where.append("file_registration_contract = ?")
        params.append(namespace_contract)
    sql = "SELECT * FROM piece_lifecycle WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at, record_key"
    connection = _connect(base_dir)
    try:
        return [_row_payload(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        connection.close()


def resolve_piece_reference(
    base_dir: str | os.PathLike,
    *,
    commitment_hash: object = "",
    piece_root: object = "",
    include_deleted: bool = True,
    upload_instance_id: object | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict | None:
    if HX.strip_hex_prefix(commitment_hash):
        return get_by_commitment(
            base_dir,
            commitment_hash,
            chain_id=chain_id,
            file_registration_contract=file_registration_contract,
        )
    matches = find_by_piece_root(
        base_dir,
        piece_root,
        include_deleted=include_deleted,
        upload_instance_id=upload_instance_id,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    if len(matches) > 1:
        raise AmbiguousPieceReference(
            "pieceRoot matches multiple registrations; commitmentHash is required"
        )
    return matches[0] if matches else None


def update_by_commitment(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
    **updates: object,
) -> dict:
    current = get_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    if current is None:
        raise PieceJournalError("piece commitment is not present in the lifecycle journal")
    merged = dict(current)
    merged.update(updates)
    return record_registration(base_dir, merged, source="lifecycle-update")


def begin_deletion(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    summary: str = "",
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict:
    now = _utc_now()
    current = get_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    if current is None:
        raise PieceJournalError("piece commitment is not present in the lifecycle journal")
    first_requested_at = str(current.get("deletionRequestedAt", "") or now)
    return update_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        deletionStatus="requested",
        deleted=False,
        deletionRequestedAt=first_requested_at,
        deletionLastRequestedAt=now,
        deletionAttempts=int(current.get("deletionAttempts", 0) or 0) + 1,
        deletionUpdatedAt=now,
        deletionSummary=str(summary or "deletion requested"),
    )


def mark_deletion_pending(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    summary: str,
    chain_status: dict | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict:
    updates: dict[str, object] = {
        "deletionStatus": "pending",
        "deleted": False,
        "deletionUpdatedAt": _utc_now(),
        "deletionSummary": str(summary),
    }
    if chain_status is not None:
        updates.update({
            "deletionDeclared": bool(chain_status.get("declared")),
            "deletionConfirmed": bool(chain_status.get("confirmed")),
            "deletionEvidenceOk": bool(chain_status.get("ok")),
            "deletionDeclaredAt": int(chain_status.get("declared_at", 0) or 0),
            "deletionGraceSeconds": int(chain_status.get("grace_seconds", 0) or 0),
            "deletionLastChainError": str(chain_status.get("error", "") or ""),
        })
    return update_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        **updates,
    )


def mark_deletion_failed(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    summary: str,
    blocked: bool = False,
    extra: dict | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict:
    updates: dict[str, object] = {
        "deletionStatus": "blocked" if blocked else "failed",
        "deleted": False,
        "deletionUpdatedAt": _utc_now(),
        "deletionSummary": str(summary),
    }
    if extra:
        updates.update(extra)
    return update_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        **updates,
    )


def mark_deletion_disputed(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    summary: str,
    dispute_summary: str,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict:
    """Persist the terminal, on-chain-deduplicated dispute decision."""
    return update_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        deletionStatus="disputed",
        deleted=False,
        deletionUpdatedAt=_utc_now(),
        deletionSummary=str(summary),
        deletionDisputeSubmitted=True,
        deletionDisputeSummary=str(dispute_summary),
    )


def mark_deletion_confirmed(
    base_dir: str | os.PathLike,
    commitment_hash: object,
    *,
    summary: str,
    chain_status: dict,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> dict:
    if not isinstance(chain_status, dict) or not all(
        chain_status.get(field) is True
        for field in ("declared", "confirmed", "ok")
    ):
        raise PieceJournalError(
            "confirmed deletion requires declared, confirmed, and ok chain evidence"
        )
    confirmed_at = int(chain_status.get("confirmed_at", 0) or 0)
    updates: dict[str, object] = {
        "deletionStatus": "confirmed",
        "deleted": True,
        "deletionDeclared": bool(chain_status.get("declared")),
        "deletionConfirmed": bool(chain_status.get("confirmed")),
        "deletionEvidenceOk": bool(chain_status.get("ok")),
        "deletionUpdatedAt": _utc_now(),
        "deletionSummary": str(summary),
    }
    if confirmed_at:
        updates["deletionConfirmedAt"] = confirmed_at
        updates["deletionConfirmedAtIso"] = datetime.datetime.fromtimestamp(
            confirmed_at, tz=datetime.timezone.utc
        ).isoformat()
    return update_by_commitment(
        base_dir,
        commitment_hash,
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
        **updates,
    )


def adopt_partial_namespace(
    base_dir: str | os.PathLike,
    *,
    chain_id: object,
    file_registration_contract: object,
    source: str,
) -> int:
    """Give rows that hold half a chain namespace the whole of this one.

    A row is namespaced by chain AND contract, and every lookup asks for both.
    A writer that filled in only the chain -- the owner-recovery path did,
    because the keeper's receipt carries a chain id and no contract -- left
    rows that are listed but can never be found again: the piece was on
    screen and the delete said "Piece not found".

    Only rows written by *source* are touched, and only those missing the
    contract. The row's identity changes with its namespace, so a row whose
    corrected identity already exists is dropped rather than duplicated.
    """
    namespace_chain, namespace_contract = _namespace_values(
        chain_id=chain_id, file_registration_contract=file_registration_contract,
    )
    if not namespace_chain or not namespace_contract:
        return 0

    fixed = 0
    connection = _connect(base_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT * FROM piece_lifecycle "
            "WHERE chain_id != '' AND file_registration_contract = ''"
        ).fetchall()
        for row in rows:
            payload = _row_payload(row)
            if source not in (payload.get("journalSources") or []):
                continue
            payload["chainId"] = namespace_chain
            payload["fileRegistrationContract"] = namespace_contract
            record_key = _record_key(payload)
            payload["journalKey"] = record_key
            if record_key != row["record_key"]:
                taken = connection.execute(
                    "SELECT 1 FROM piece_lifecycle WHERE record_key = ?",
                    (record_key,),
                ).fetchone()
                if taken is not None:
                    connection.execute(
                        "DELETE FROM piece_lifecycle WHERE record_key = ?",
                        (row["record_key"],),
                    )
                    fixed += 1
                    continue
            connection.execute(
                """
                UPDATE piece_lifecycle
                SET record_key = ?, chain_id = ?, file_registration_contract = ?,
                    payload_json = ?, updated_at = ?
                WHERE record_key = ?
                """,
                (
                    record_key,
                    namespace_chain,
                    namespace_contract,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    _utc_now(),
                    row["record_key"],
                ),
            )
            fixed += 1
        connection.commit()
        return fixed
    except sqlite3.Error as exc:
        connection.rollback()
        raise PieceJournalError(f"namespace repair failed: {exc}") from exc
    finally:
        connection.close()


def unresolved_deletions(
    base_dir: str | os.PathLike,
    *,
    upload_instance_id: object | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> list[dict]:
    return [
        piece
        for piece in list_pieces(
            base_dir,
            upload_instance_id=upload_instance_id,
            chain_id=chain_id,
            file_registration_contract=file_registration_contract,
            include_deleted=False,
        )
        if str(piece.get("deletionStatus", "active"))
        in {"requested", "pending", "failed", "blocked"}
    ]


def transition_upload_instance_state(
    base_dir: str | os.PathLike,
    upload_instance_id: object,
    *,
    from_states: str | Iterable[str],
    to_state: str,
    commitment_hashes: Iterable[object] | None = None,
    chain_id: object | None = None,
    file_registration_contract: object | None = None,
) -> int:
    """Atomically compare-and-set an exact upload generation's pieces.

    ``commitment_hashes`` optionally supplies the complete target set.  A
    missing or extra target fails the transaction instead of partially marking
    an upload complete.
    """
    upload_id = _normalize_upload_instance_id(upload_instance_id)
    if not upload_id:
        raise PieceJournalError("uploadInstanceId is required")
    new_state = str(to_state or "").strip().lower()
    if new_state not in _VALID_UPLOAD_STATES:
        raise PieceJournalError(f"invalid upload lifecycle state: {to_state}")
    if isinstance(from_states, str):
        expected_states = {from_states.strip().lower()}
    else:
        expected_states = {
            str(value or "").strip().lower() for value in from_states
        }
    if not expected_states or not expected_states <= _VALID_UPLOAD_STATES:
        raise PieceJournalError("from_states contains an invalid upload lifecycle state")
    namespace_chain, namespace_contract = _namespace_values(
        chain_id=chain_id,
        file_registration_contract=file_registration_contract,
    )
    expected_commitments: set[str] | None = None
    if commitment_hashes is not None:
        normalized_commitments = [
            _canonical_optional_bytes32(value, "commitmentHash")
            for value in commitment_hashes
        ]
        expected_commitments = set(normalized_commitments)
        if "" in expected_commitments:
            raise PieceJournalError("commitment_hashes contains an empty value")
        if len(expected_commitments) != len(normalized_commitments):
            raise PieceJournalError("commitment_hashes contains a duplicate value")

    ensure_recovered(base_dir)
    connection = _connect(base_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        params: list[object] = [upload_id]
        where = ["upload_instance_id = ?"]
        if chain_id not in (None, ""):
            where.append("chain_id = ?")
            params.append(namespace_chain)
        if file_registration_contract not in (None, ""):
            where.append("file_registration_contract = ?")
            params.append(namespace_contract)
        rows = connection.execute(
            "SELECT * FROM piece_lifecycle WHERE " + " AND ".join(where)
            + " ORDER BY created_at, record_key",
            params,
        ).fetchall()
        pieces = [(row, _row_payload(row)) for row in rows]
        # Same rule as mark_file_upload_state: a settled-deleted row is not part
        # of the live generation, so it must not join the completeness check or
        # the transition below. Applied here too because this function reads the
        # generation itself, and a caller that named only the live commitments
        # would otherwise fail the "commitments do not match the journal" check.
        live_pieces = [
            item for item in pieces if not _normalize_deletion_state(item[1])[1]
        ]
        if live_pieces:
            pieces = live_pieces
        namespaces = {
            (
                str(piece.get("chainId", "") or ""),
                str(piece.get("fileRegistrationContract", "") or ""),
            )
            for _, piece in pieces
        }
        if len(namespaces) > 1:
            raise PieceJournalError(
                "uploadInstanceId exists in multiple chain namespaces; "
                "chainId and fileRegistrationContract are required"
            )
        if expected_commitments is not None:
            if any(
                not str(piece.get("commitmentHash", "") or "")
                for _, piece in pieces
            ):
                raise PieceJournalError(
                    "upload lifecycle target still contains a pre-registration record"
                )
            actual_commitments = {
                str(piece.get("commitmentHash", "") or "")
                for _, piece in pieces
                if str(piece.get("commitmentHash", "") or "")
            }
            if len(actual_commitments) != len(pieces):
                raise PieceJournalError(
                    "upload lifecycle target has duplicate commitment namespaces"
                )
            if actual_commitments != expected_commitments:
                raise PieceJournalError(
                    "upload lifecycle target commitments do not match the journal"
                )
            pieces = [
                (row, piece)
                for row, piece in pieces
                if str(piece.get("commitmentHash", "") or "")
                in expected_commitments
            ]
        if not pieces:
            raise PieceJournalError(
                "uploadInstanceId is not present in the lifecycle journal"
            )

        now = _utc_now()
        for row, piece in pieces:
            current_state = str(
                piece.get("uploadLifecycleStatus", "incomplete") or "incomplete"
            ).strip().lower()
            if current_state not in expected_states:
                raise PieceJournalError(
                    f"upload lifecycle compare-and-set failed: {current_state} "
                    f"is not one of {sorted(expected_states)}"
                )
            if new_state not in _UPLOAD_STATE_TRANSITIONS[current_state]:
                raise PieceJournalError(
                    f"invalid upload lifecycle transition: {current_state} -> {new_state}"
                )
            piece["uploadLifecycleStatus"] = new_state
            piece["uploadLifecycleUpdatedAt"] = now
            piece["journalUpdatedAt"] = now
            payload_json = json.dumps(piece, sort_keys=True, separators=(",", ":"))
            connection.execute(
                """
                UPDATE piece_lifecycle
                   SET payload_json = ?, updated_at = ?
                 WHERE record_key = ?
                """,
                (payload_json, now, str(row["record_key"])),
            )
        for row, _ in pieces:
            written = connection.execute(
                "SELECT * FROM piece_lifecycle WHERE record_key = ?",
                (str(row["record_key"]),),
            ).fetchone()
            if written is None:
                raise PieceJournalError("upload lifecycle transition was not durable")
            _row_payload(written)
        connection.commit()
        return len(pieces)
    except (sqlite3.Error, ValueError, PieceJournalError) as exc:
        connection.rollback()
        if isinstance(exc, PieceJournalError):
            raise
        raise PieceJournalError(f"upload lifecycle transition failed: {exc}") from exc
    finally:
        connection.close()
        _secure_sqlite_files(journal_path(base_dir))


def mark_file_upload_state(
    base_dir: str | os.PathLike,
    file_id: object,
    state: str,
    *,
    upload_instance_id: object | None = None,
) -> int:
    normalized_state = str(state or "").strip().lower()
    if normalized_state not in _VALID_UPLOAD_STATES:
        raise PieceJournalError(f"invalid upload lifecycle state: {state}")
    pieces = list_pieces(base_dir, file_id=file_id, include_deleted=True)
    if upload_instance_id not in (None, ""):
        upload_id = _normalize_upload_instance_id(upload_instance_id)
        pieces = [
            piece for piece in pieces
            if piece.get("uploadInstanceId", "") == upload_id
        ]
        if not pieces:
            raise PieceJournalError(
                "fileId and uploadInstanceId do not identify a journal generation"
            )
    else:
        generations = {
            str(piece.get("uploadInstanceId", "") or "")
            for piece in pieces
            if str(piece.get("uploadInstanceId", "") or "")
        }
        if len(generations) > 1:
            raise PieceJournalError(
                "fileId contains multiple upload generations; uploadInstanceId is required"
            )
        upload_id = next(iter(generations), "")
    pieces = _live_generation_pieces(pieces)
    if upload_id:
        current_states = {
            str(piece.get("uploadLifecycleStatus", "incomplete") or "incomplete")
            .strip()
            .lower()
            for piece in pieces
        }
        return transition_upload_instance_state(
            base_dir,
            upload_id,
            from_states=current_states,
            to_state=normalized_state,
            commitment_hashes=[
                piece["commitmentHash"] for piece in pieces
                if piece.get("commitmentHash")
            ],
        )
    for piece in pieces:
        current_state = str(
            piece.get("uploadLifecycleStatus", "incomplete") or "incomplete"
        ).strip().lower()
        if normalized_state not in _UPLOAD_STATE_TRANSITIONS[current_state]:
            raise PieceJournalError(
                f"invalid upload lifecycle transition: {current_state} -> {normalized_state}"
            )
        updated = dict(piece)
        updated["uploadLifecycleStatus"] = normalized_state
        updated["uploadLifecycleUpdatedAt"] = _utc_now()
        record_registration(base_dir, updated, source="upload-lifecycle-update")
    return len(pieces)


def safe_summary(base_dir: str | os.PathLike) -> dict:
    """Return counters only; never expose private receipts or deletion secrets."""
    pieces = list_pieces(base_dir, include_deleted=True)
    active = [piece for piece in pieces if not piece.get("deleted")]
    pending = [
        piece
        for piece in active
        if str(piece.get("deletionStatus", "active"))
        in {"requested", "pending", "failed", "blocked"}
    ]
    return {
        "total": len(pieces),
        "active": len(active),
        "confirmed_deleted": sum(1 for piece in pieces if piece.get("deleted")),
        "pending_deletion": len(pending),
    }
