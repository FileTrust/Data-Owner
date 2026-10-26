"""Persistent account-wide recovery state shared by DO application copies."""
import os
from pathlib import Path
import sqlite3


def wallet_journal_path(address):
    normalized = str(address).lower().removeprefix('0x')
    if not normalized or any(c not in '0123456789abcdef' for c in normalized):
        raise ValueError('Invalid recovery wallet address')
    configured = os.environ.get('FILETRUST_DKG_STATE_DIR')
    if configured:
        root = Path(configured)
    elif os.name == 'nt':
        root = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData/Local') / 'FileTrust/DO/recovery'
    else:
        root = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state') / 'filetrust-do/recovery'
    return root / f'{normalized}.sqlite3'


def require_no_pending_recovery(address):
    path = wallet_journal_path(address)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        raise RuntimeError('Cannot verify the wallet recovery journal')
    try:
        db = sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=1)
        try:
            pending = db.execute("SELECT 1 FROM actions WHERE status IN ('reserved','signed') LIMIT 1").fetchone()
        finally:
            db.close()
    except sqlite3.Error:
        raise RuntimeError('Cannot verify pending recovery transactions; wallet sends are deferred') from None
    if pending:
        raise RuntimeError('A DKG recovery transaction reserves this wallet nonce; resume recovery before another send')
