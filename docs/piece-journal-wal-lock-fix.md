# Piece journal: "database is locked" on concurrent open

`_connect()` ran `PRAGMA journal_mode = WAL` on every open. That rewrites the
database header, so it needs a brief exclusive lock and can be refused with
`database is locked`, which `_connect` wrapped into `PieceJournalError`.

## Measured locking behaviour

Probed directly with `sqlite3` (Python 3.13.12, SQLite 3.46.1), one holder
connection open while a second asks for WAL:

| database state | holder holds | `PRAGMA journal_mode = WAL` |
| --- | --- | --- |
| not yet WAL | write lock (`BEGIN IMMEDIATE`) | refused after 0.4 ms |
| not yet WAL | read lock (`BEGIN`) | refused after **30043 ms** |
| already WAL | write lock | OK, 0.4 ms |
| already WAL | read lock | OK, 0.4 ms |

Two things differ from the original description of the bug:

- The statement **does** honour `busy_timeout` when the holder has a read
  lock. It waits the full 30 s and then fails, so the old code could also
  stall an open for 30 seconds, not just fail fast.
- Once the database is in WAL, re-requesting WAL takes no lock and cannot
  fail. The vulnerable window is therefore **only while the journal is being
  created** — which is exactly what the test does, a fresh temp dir per run,
  and why long-lived production journals stop being affected after the first
  open.

## Fix

`_enable_wal()`:

1. Read `PRAGMA journal_mode` first and return if it is already `wal`. No lock
   is taken, so the common case can no longer fail or stall.
2. Only while creating the journal, attempt the write under a short
   250 ms busy timeout, then restore 30 s. Losing that race is harmless: the
   winner has already made the mode durable, and a connection that lost is
   still correct, because every statement reads the mode from the file when it
   begins a transaction.
3. Tolerate only `SQLITE_BUSY` / `SQLITE_LOCKED`. Anything else — for example
   `SQLITE_READONLY` — still raises and still becomes `PieceJournalError`.

`synchronous = FULL` and `foreign_keys = ON` are unchanged.

## Verification

A/B on the real `record_registration` path, fresh journal per trial, all
threads released from a barrier. `old` restores exactly the replaced line, so
both arms are otherwise identical code:

```
trials=150 threads=24
old    attempts=3600 failures=7 (0.2%)  trials_with_lost_records=6
       7x PieceJournalError: piece lifecycle journal cannot be opened safely: database is locked
fixed  attempts=3600 failures=0 (0.0%)  trials_with_lost_records=0
```

The failure really did lose records: in 6 trials the final piece count was
short. Note the plain pytest test is a weak detector — on an idle machine it
passed 60/60 even unfixed — so the two new tests assert the mechanism
directly instead:

- `test_opening_a_new_journal_survives_a_contended_journal_mode` — fails
  against the old line.
- `test_real_open_failures_are_still_reported` — fails against a fix that
  swallows every `OperationalError` instead of just busy ones.

Suite: 256 passed (254 pre-existing + 2 new). Target test: 0 failures in 50
iterations. `core/test_deletion_redrive.py` has a pre-existing collection
error, unrelated and untouched.

Running the suite in a worktree needs the gitignored contract artifacts:
`ln -sfn /mnt/E/FileTrust/Blockchain/artifacts Blockchain/artifacts`.

## Callers and the no-lost-jobs invariant

No production caller retries on `PieceJournalError`; nothing in `core/`
catches it at all. The invariant still holds, through the transfer-job layer
rather than the journal:

- The two most critical calls (`do_vaultmesh.py` ~1760 and ~1939, after the
  VK store response, when bytes already exist remotely) are bare calls inside
  `vaultmesh_store_piece`.
- Their only production caller, `_upload_one` (`do_vaultmesh.py` ~3517),
  catches `Exception` and immediately calls `XFER.get_or_create_upload_job`,
  durably recording the piece. If even that fails it raises `TransferPending`
  with "durable state is ambiguous".
- When the job represents a real obligation, `requires_same_peer_resume`
  turns the failure into `TransferPending` for same-peer resume. The job is
  cancelled only via `cancel_upload_job_before_obligation`, after the
  transfer manager proves no bytes or escrow can exist.
- `ensure_recovered` can rebuild journal rows from those upload-job files.
- `do_actions.py` ~2415 (legacy drop-folder deletion) converts the error to
  `ok=False` without retrying, but fails *before* deleting, so it cannot
  delete without a durable record.

So a transient lock error degraded an upload to pending/failed and relied on
recovery, rather than losing the job. The gap worth knowing about is that
there is no retry anywhere: before this fix the degradation was reachable
from ordinary concurrency, and it is what the user saw. Adding a retry around
`record_registration` was left out of scope.
