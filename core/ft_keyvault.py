# ft_keyvault.py — the account key in an encrypted file, unlocked by a password.
#
# Until now the private key sat in config.json in clear text. Anything that
# could read that file owned the account: a backup, a synced folder, a support
# session where someone pastes their settings. This module puts the key in
# keyvault.json instead, encrypted with a key derived from a password that is
# never stored anywhere, and hands the plain key to the rest of the app in
# memory only, for the life of the process.
#
# Shape of the file:
#
#   {"filetrust_keyvault": 1,
#    "address": "0x...",            # derived from the key; public anyway
#    "two_factor": true,            # a hint for the prompt, not a gate
#    "password_source": "keyring",  # absent when the user types it
#    "keyring_id": "vault-...",     # which keyring entry holds the password
#    "kdf":    {"name": "scrypt", "n": ..., "r": 8, "p": 1, "salt": b64},
#    "cipher": {"name": "AES-256-GCM", "nonce": b64, "ciphertext": b64}}
#
# By default the password is a long random one kept in the operating system's
# keyring, so there is nothing for the user to remember and nothing to type;
# see the keyring section below for what that does and does not defend against.
# A password the user chooses is the other option, and then nothing but their
# memory holds it.
#
# Everything except the ciphertext is authenticated as AES-GCM associated data,
# so editing the address or the KDF cost in the file makes it fail to open
# rather than open differently.
#
# The second factor is a standard TOTP secret (RFC 6238), kept *inside* the
# encrypted payload. Be clear about what that buys: it is a second thing to
# present when this app starts, and it stops someone who watched the password
# being typed. It is not a second encryption factor — whoever has both the file
# and the password can decrypt it with ten lines of Python and never meet the
# code prompt. Said plainly here so nobody designs on a stronger assumption.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import tempfile
import time
from pathlib import Path

VAULT_FILENAME = "keyvault.json"
FORMAT_VERSION = 1

# scrypt at n=2**17, r=8 needs 128 MB and roughly a second on a desktop. That
# is the point: it is the whole defence for a short password, and it is paid
# once per app start.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32

MIN_PASSWORD_LENGTH = 8

TOTP_DIGITS = 6
TOTP_STEP = 30
# One step either side: phone clocks drift, and a user typing a code as it
# turns over should not be told their code is wrong.
TOTP_DRIFT = 1


class VaultError(Exception):
    """The vault file is unusable: missing, malformed, or from a newer app."""


class BadPassword(VaultError):
    """The password (or the file's integrity) did not check out."""


# ── Where it lives ───────────────────────────────────────────────────────────

def vault_path(base_dir) -> Path:
    return Path(base_dir) / VAULT_FILENAME


def exists(path) -> bool:
    try:
        return Path(path).is_file()
    except OSError:
        return False


def read_header(path) -> dict:
    """The public part of the vault, without needing the password."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VaultError(f"{path} cannot be read: {exc}") from exc
    if not isinstance(data, dict) or "cipher" not in data:
        raise VaultError(f"{path} is not a FileTrust key vault")
    version = int(data.get("filetrust_keyvault") or 0)
    if version > FORMAT_VERSION:
        raise VaultError(
            f"{path} was written by a newer version of the app (format {version})"
        )
    return data


def address_in(path) -> str:
    try:
        return str(read_header(path).get("address") or "")
    except VaultError:
        return ""


def has_two_factor(path) -> bool:
    """Whether the prompt should expect a code. A hint only — see the note above."""
    try:
        return bool(read_header(path).get("two_factor"))
    except VaultError:
        return False


# ── Encrypt and decrypt ──────────────────────────────────────────────────────

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text, what: str) -> bytes:
    try:
        return base64.b64decode(str(text), validate=True)
    except Exception as exc:
        raise VaultError(f"the vault's {what} is not valid base64") from exc


def _derive(password: str, salt: bytes, kdf: dict) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    name = str(kdf.get("name") or "scrypt").lower()
    if name != "scrypt":
        raise VaultError(f"the vault uses an unknown key derivation ({name})")
    return Scrypt(
        salt=salt,
        length=int(kdf.get("dklen") or DKLEN),
        n=int(kdf.get("n") or SCRYPT_N),
        r=int(kdf.get("r") or SCRYPT_R),
        p=int(kdf.get("p") or SCRYPT_P),
    ).derive(password.encode("utf-8"))


def _associated_data(header: dict) -> bytes:
    """Everything in the file except the ciphertext, canonically encoded.

    Passed to AES-GCM as associated data so the fields a reader trusts -- the
    address it shows before unlocking, the cost of the KDF -- cannot be edited
    without the open failing.
    """
    public = {
        "filetrust_keyvault": header.get("filetrust_keyvault"),
        "address": header.get("address"),
        "two_factor": bool(header.get("two_factor")),
        "kdf": header.get("kdf"),
        "cipher_name": (header.get("cipher") or {}).get("name"),
        "nonce": (header.get("cipher") or {}).get("nonce"),
    }
    return json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _address_of(private_key: str) -> str:
    """The address for a key, without importing web3 if eth_account is enough."""
    try:
        from eth_account import Account
    except ImportError:  # pragma: no cover - web3 installs eth-account
        return ""
    try:
        return Account.from_key(private_key).address
    except Exception as exc:
        raise VaultError(f"that private key cannot be used: {exc}") from exc


def _payload(private_key: str, totp_secret: str | None) -> bytes:
    body = {
        "private_key": private_key,
        "totp_secret": totp_secret or None,
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def create(path, private_key: str, password: str, *, totp_secret: str | None = None,
           keyring_id: str = "") -> dict:
    """Write a new vault for this key. Returns the header that was written.

    `keyring_id` records that the password lives in the operating system's
    keyring under that name, so the app knows to look there before asking
    anybody anything. It is a hint and is deliberately *not* authenticated:
    editing it can only cost a prompt that was not needed, never access.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = str(private_key or "").strip()
    if not key:
        raise VaultError("there is no private key to protect")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise VaultError(
            f"the password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    header = {
        "filetrust_keyvault": FORMAT_VERSION,
        "address": _address_of(key),
        "two_factor": bool(totp_secret),
        "kdf": {
            "name": "scrypt",
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": DKLEN,
            "salt": _b64(salt),
        },
        "cipher": {"name": "AES-256-GCM", "nonce": _b64(nonce)},
    }
    secret = _derive(password, salt, header["kdf"])
    blob = AESGCM(secret).encrypt(nonce, _payload(key, totp_secret), _associated_data(header))
    header["cipher"]["ciphertext"] = _b64(blob)
    if keyring_id:
        header["password_source"] = "keyring"
        header["keyring_id"] = str(keyring_id)
    _write_private_json(path, header)
    return header


def unlock(path, password: str) -> dict:
    """Open the vault. Returns {"private_key": ..., "totp_secret": ... or None}."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    header = read_header(path)
    kdf = header.get("kdf") or {}
    cipher = header.get("cipher") or {}
    salt = _unb64(kdf.get("salt"), "salt")
    nonce = _unb64(cipher.get("nonce"), "nonce")
    blob = _unb64(cipher.get("ciphertext"), "ciphertext")

    secret = _derive(password or "", salt, kdf)
    try:
        plain = AESGCM(secret).decrypt(nonce, blob, _associated_data(header))
    except InvalidTag as exc:
        # One message for both causes on purpose: telling an attacker apart
        # "wrong password" from "edited file" tells them which to try next.
        raise BadPassword("wrong password, or the vault file has been altered") from exc
    try:
        body = json.loads(plain.decode("utf-8"))
        key = str(body["private_key"])
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise VaultError("the vault opened but its contents are not readable") from exc
    return {"private_key": key, "totp_secret": body.get("totp_secret") or None}


def rewrite(path, password: str, *, new_password: str | None = None,
            private_key: str | None = None, totp_secret: str | None = "",
            keyring_id: str | None = None) -> dict:
    """Change the password, the key, or the second factor, in place.

    `totp_secret=""` means "leave it as it is"; None removes it; a string sets
    it. `keyring_id=None` keeps whatever the vault already records, "" drops
    it. The vault is opened first, so every change needs the current password.
    """
    current = unlock(path, password)
    key = private_key if private_key is not None else current["private_key"]
    if totp_secret == "":
        totp = current["totp_secret"]
    else:
        totp = totp_secret or None
    stored_id = keyring_id_in(path) if keyring_id is None else keyring_id
    return create(path, key, new_password or password, totp_secret=totp,
                  keyring_id=stored_id)


def _write_private_json(path, data: dict) -> None:
    """Write 0600, atomically, so no readable copy exists even for a moment."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".keyvault-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def file_is_private(path) -> tuple[bool, str]:
    """Whether the vault is readable only by its owner, and the mode if not.

    On a Windows-formatted disk it never will be, which is worth saying once
    rather than pretending the permission took.
    """
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError as exc:
        return False, f"{path} cannot be checked: {exc}"
    if mode & 0o077:
        return False, (
            f"{path} is mode {mode:04o}; this filesystem cannot keep permissions, "
            "so other accounts on this machine can read the file (it is still "
            "encrypted)"
        )
    return True, ""


# ── The password in the operating system's keyring ───────────────────────────
#
# The default, because a password nobody has to remember is the one nobody
# writes on a note beside the computer. The app invents a long random password,
# keeps it in the keyring the desktop already unlocks at login -- Keyring or
# KWallet on Linux, Keychain on macOS, Credential Manager on Windows -- and
# reads it back at start-up. The key file stays encrypted exactly as before;
# only the place the password comes from changes.
#
# What this does not defend against, said plainly: anything already running as
# this user can ask the keyring for the password, the same way the app does. It
# protects a stolen file, a backup, a copied disk. A typed password protects
# more, and stays available as a choice.
#
# The random password is never shown: it is the app's own business, like a
# session token, and printing it only teaches the user to keep something they do
# not need. A keyring is still not a backup -- a reinstalled system or a reset
# keyring leaves a vault nobody can open -- so setup says to keep a backup of
# the account key, which is what every wallet asks for anyway and what actually
# gets the user back in. Someone who wants a password that survives the machine
# chooses their own instead; both are offered.

KEYRING_SERVICE = "FileTrust key vault"
RANDOM_PASSWORD_BYTES = 24


def new_random_password() -> str:
    """A password meant for the keyring: long enough that scrypt is not the
    thing standing between an attacker and the key."""
    return base64.urlsafe_b64encode(secrets.token_bytes(RANDOM_PASSWORD_BYTES)).decode("ascii")


def new_keyring_id() -> str:
    """A name for this install's entry, kept in the vault.

    Not the file's path: moving the app folder would then lose a password
    nobody can retype.
    """
    return "vault-" + secrets.token_hex(8)


def _keyring():
    """The keyring module, or None when it is absent or has no usable backend."""
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except Exception:
        return None
    try:
        if isinstance(keyring.get_keyring(), FailKeyring):
            return None
    except Exception:
        return None
    return keyring


def keyring_available() -> bool:
    return _keyring() is not None


def keyring_backend_name() -> str:
    module = _keyring()
    if module is None:
        return ""
    try:
        return type(module.get_keyring()).__module__.split(".")[-1]
    except Exception:
        return "unknown"


def keyring_store(keyring_id: str, password: str) -> bool:
    """Put the password in the keyring, and prove it can be read back.

    Written and then read, because a backend that accepts a write and returns
    nothing afterwards -- a locked wallet, a dbus session that is not really
    there -- would otherwise be discovered at the next start-up, when the
    password is already the only way in.
    """
    module = _keyring()
    if module is None:
        return False
    try:
        module.set_password(KEYRING_SERVICE, keyring_id, password)
        return module.get_password(KEYRING_SERVICE, keyring_id) == password
    except Exception:
        return False


def keyring_fetch(keyring_id: str) -> str:
    module = _keyring()
    if module is None or not keyring_id:
        return ""
    try:
        return module.get_password(KEYRING_SERVICE, keyring_id) or ""
    except Exception:
        return ""


def keyring_forget(keyring_id: str) -> bool:
    module = _keyring()
    if module is None or not keyring_id:
        return False
    try:
        module.delete_password(KEYRING_SERVICE, keyring_id)
        return True
    except Exception:
        return False


def keyring_id_in(path) -> str:
    try:
        header = read_header(path)
    except VaultError:
        return ""
    if str(header.get("password_source") or "") != "keyring":
        return ""
    return str(header.get("keyring_id") or "")


def password_from_keyring(path) -> str:
    """The stored password for this vault, or "" if there is not one to find."""
    return keyring_fetch(keyring_id_in(path))


# ── The unlocked key, for this process only ──────────────────────────────────
# The config modules read the key at import time. Rather than hand it round in
# an environment variable, where every child process inherits it, the entry
# script leaves it here and the config module picks it up.

_unlocked: dict[str, str] = {}


def remember_key(private_key: str) -> None:
    _unlocked["private_key"] = str(private_key or "").strip()


def unlocked_key() -> str:
    return _unlocked.get("private_key", "")


def forget_key() -> None:
    _unlocked.pop("private_key", None)


PASSWORD_ENV = "FILETRUST_KEY_PASSWORD"


def key_from_environment(path) -> str:
    """Unlock without a prompt, for scripts and headless runs.

    A user who protects their key still has command-line tools to run. They
    export FILETRUST_KEY_PASSWORD for the one command instead of being locked
    out of their own install.
    """
    password = os.environ.get(PASSWORD_ENV, "")
    if not password or not exists(path):
        return ""
    return unlock(path, password)["private_key"]


def key_without_prompt(path) -> str:
    """The key, if it can be had without asking anybody: environment, keyring.

    This is what a module imported by a script reaches for. It never prompts,
    because the thing importing it may be a cron job, a load test or a tool
    with no terminal at all; the apps prompt in their own entry scripts.
    """
    if not exists(path):
        return ""
    from_env = key_from_environment(path)
    if from_env:
        return from_env
    stored = password_from_keyring(path)
    if not stored:
        return ""
    try:
        return unlock(path, stored)["private_key"]
    except BadPassword:
        return ""   # a stale keyring entry is not an error worth raising here


# ── Two-factor codes (RFC 6238 TOTP, SHA-1, as every authenticator app does) ──

def new_totp_secret(length: int = 20) -> str:
    """A fresh shared secret, base32 as authenticator apps expect it."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _totp_key(secret: str) -> bytes:
    text = "".join(str(secret).split()).upper()
    padding = "=" * (-len(text) % 8)
    try:
        return base64.b32decode(text + padding, casefold=True)
    except Exception as exc:
        raise VaultError("that two-factor secret is not valid base32") from exc


def totp_code(secret: str, at: float | None = None, *,
              step: int = TOTP_STEP, digits: int = TOTP_DIGITS,
              digest=hashlib.sha1) -> str:
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(_totp_key(secret), struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** digits)).zfill(digits)


def totp_matches(secret: str, code: str, at: float | None = None, *,
                 drift: int = TOTP_DRIFT, step: int = TOTP_STEP,
                 digits: int = TOTP_DIGITS) -> bool:
    given = "".join(str(code or "").split())
    if not given.isdigit():
        return False
    now = time.time() if at is None else at
    for window in range(-drift, drift + 1):
        expected = totp_code(secret, now + window * step, step=step, digits=digits)
        # Constant-time: a code is a secret for thirty seconds.
        if hmac.compare_digest(expected, given.zfill(digits)):
            return True
    return False


def otpauth_uri(secret: str, account: str, issuer: str = "FileTrust") -> str:
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}"
    )


# Which app the authenticator should name. "FileTrust" alone is no help to
# someone running both apps, or several accounts: the phone lists them by this
# line, so it has to say which one it unlocks.
ISSUER_BY_FIELD = {
    "do_private_key": "FileTrust DO",
    "req_private_key": "FileTrust REQ",
}


def issuer_for_field(field: str) -> str:
    return ISSUER_BY_FIELD.get(str(field or "").strip().lower(), "FileTrust")


def qr_text(uri: str) -> str:
    """The QR code as text for a terminal, or "" when qrcode is not installed.

    A missing drawing is never a reason to withhold the secret itself: the
    caller prints the URI and the base32 string instead, which can be typed
    into any authenticator app by hand.
    """
    try:
        import io

        import qrcode
    except ImportError:
        return ""
    try:
        code = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
        code.add_data(uri)
        code.make(fit=True)
        out = io.StringIO()
        code.print_ascii(out=out, invert=True)
        return out.getvalue()
    except Exception:
        return ""


# ── Command line, used by install.sh and runnable by hand ────────────────────
#
#   python3 -m core.ft_keyvault status  --dir .   # 0 = protected, 1 = not
#   python3 -m core.ft_keyvault has-2fa --dir .   # 0 = yes, 1 = no, quiet
#   python3 -m core.ft_keyvault keyring-check --dir .          # usable keyring?
#   python3 -m core.ft_keyvault keyring-holds-password --dir . # password there?
#   python3 -m core.ft_keyvault use-keyring  --dir .   # stop typing a password
#   python3 -m core.ft_keyvault use-password --dir .   # start typing one
#   python3 -m core.ft_keyvault import-key --config config.json \
#                                       --field do_private_key   # key in
#                                       FILETRUST_IMPORT_KEY
#   python3 -m core.ft_keyvault protect --dir . --config config.json \
#                                       --field do_private_key [--two-factor]
#   python3 -m core.ft_keyvault add-2fa --dir .
#   python3 -m core.ft_keyvault passwd  --dir .
#
# The password arrives in FILETRUST_KEY_PASSWORD (and FILETRUST_NEW_PASSWORD for
# passwd), never as an argument: arguments are visible in `ps` to every account
# on the machine.

def _cli_password(variable: str = PASSWORD_ENV) -> str:
    password = os.environ.get(variable, "")
    if not password:
        raise SystemExit(f"set {variable} before running this command")
    return password


def _password_for(path) -> str:
    """The password for an existing vault: the keyring's, or the environment's.

    A keyring install has no password the user could type, so a command that
    asked for one would be impossible to run on the very setup the installer
    recommends.
    """
    stored = password_from_keyring(path)
    if stored:
        return stored
    if keyring_id_in(path):
        raise SystemExit(
            "this vault's password should be in the keyring, but it is not "
            f"there. Set {PASSWORD_ENV} to the password printed at setup."
        )
    return _cli_password()


def _key_in_config(config_path, field: str) -> str:
    try:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"{config_path} cannot be read: {exc}")
    return str(config.get(field) or "").strip()


def _clear_key_in_config(config_path, field: str) -> None:
    """Empty the plain key in config.json, once the vault holds it.

    Emptied rather than deleted: the field is documented, the installer merges
    on it, and a missing field reads as "this config is from another version".
    """
    path = Path(config_path)
    config = json.loads(path.read_text(encoding="utf-8"))
    if str(config.get(field) or "").strip():
        config[field] = ""
        _write_private_json(path, config)


def _confirm_two_factor(secret: str, account: str, issuer: str = "FileTrust") -> None:
    """Show the QR, then make the user prove the app really has the secret.

    Without this, a typo in the scan is only discovered the next time they
    start the app -- by which time the key is already locked behind the code
    they cannot produce.
    """
    uri = otpauth_uri(secret, account or "account", issuer)
    drawing = qr_text(uri)
    print()
    if drawing:
        print(drawing)
    else:
        print("  (install the 'qrcode' package to see this as a QR code)")
    print("  Scan the code above with Google Authenticator, Aegis, 1Password,")
    print("  or any other authenticator app. If you cannot scan it, add the")
    print("  account by hand with this secret:")
    print()
    print(f"      {secret}")
    print()
    print(f"  it will appear as \"{issuer}\" for address {account}")
    if not os.isatty(0):
        print("  not a terminal, so the code cannot be confirmed here")
        return
    for attempt in range(3):
        given = input("  Type the 6-digit code it shows now: ").strip()
        if totp_matches(secret, given):
            print("  confirmed")
            return
        print("  that code does not match" + (", try again" if attempt < 2 else ""))
    raise SystemExit("two-factor was not confirmed, so nothing was changed")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="ft_keyvault", description=__doc__)
    parser.add_argument("command",
                        choices=("status", "has-2fa", "keyring-check",
                                 "keyring-holds-password",
                                 "import-key", "protect", "add-2fa",
                                 "remove-2fa", "passwd", "use-password",
                                 "use-keyring"))
    parser.add_argument("--dir", default=".", help="the app directory holding keyvault.json")
    parser.add_argument("--config", default="", help="config.json, for 'protect'")
    parser.add_argument("--field", default="", help="the key's name in config.json")
    parser.add_argument("--two-factor", action="store_true",
                        help="also set up an authenticator app")
    parser.add_argument("--app", default="",
                        help="which app this is (do_private_key / "
                             "req_private_key), so the authenticator names it")
    parser.add_argument("--keyring", action="store_true",
                        help="keep a random password in the OS keyring, so the "
                             "app asks for nothing at start-up")
    args = parser.parse_args(argv)

    path = vault_path(args.dir)

    if args.command == "status":
        if not exists(path):
            print("  no password protection yet; the key is in config.json")
            return 1
        address = address_in(path) or "(unknown)"
        extra = ", with a code from your authenticator app" \
            if has_two_factor(path) else ""
        stored = keyring_id_in(path)
        if stored and keyring_fetch(stored):
            where = "this computer opens it for you"
        elif stored:
            where = ("this computer should open it, but the keyring no longer "
                     "has the password, so the app will ask you for it")
        else:
            where = "the app asks you for the password"
        print(f"  your key is locked{extra}; {where}")
        print(f"  address {address}")
        return 0

    if args.command == "keyring-check":
        # Quiet: these two exist for `if ...; then` in the installer.
        return 0 if keyring_available() else 1

    if args.command == "keyring-holds-password":
        return 0 if exists(path) and password_from_keyring(path) else 1

    if args.command == "import-key":
        # For someone who already has an account -- funded, or with files
        # stored under it -- and is installing on a second machine. The key
        # arrives in the environment, never as an argument, and is checked
        # before it is written so a mistyped key fails here rather than at
        # the first transaction.
        if not args.config or not args.field:
            raise SystemExit("import-key needs --config and --field")
        if exists(path):
            raise SystemExit(
                f"{path} already holds a protected key; nothing was changed"
            )
        key = os.environ.get("FILETRUST_IMPORT_KEY", "").strip()
        if not key:
            raise SystemExit("set FILETRUST_IMPORT_KEY before running this command")
        if not key.startswith("0x"):
            key = "0x" + key
        address = _address_of(key)   # raises VaultError on a bad key
        config_path = Path(args.config)
        config = json.loads(config_path.read_text(encoding="utf-8")) \
            if config_path.is_file() else {}
        if str(config.get(args.field) or "").strip():
            raise SystemExit(
                f"{args.config} already has a {args.field}; nothing was changed"
            )
        config[args.field] = key
        _write_private_json(config_path, config)
        print(f"  key accepted. your address: {address}")
        return 0

    if args.command == "has-2fa":
        # Quiet on purpose: this one exists for `if ...; then` in the installer.
        return 0 if exists(path) and has_two_factor(path) else 1

    if args.command == "protect":
        if exists(path):
            print("  already protected; leaving it alone")
            return 0
        if not args.config or not args.field:
            raise SystemExit("protect needs --config and --field")
        keyring_id = ""
        if args.keyring:
            if not keyring_available():
                raise SystemExit(
                    "this computer has no keyring the app can use; choose a "
                    "password instead"
                )
            password = new_random_password()
            keyring_id = new_keyring_id()
        else:
            password = _cli_password()
        key = _key_in_config(args.config, args.field)
        if not key:
            raise SystemExit(f"{args.config} has no {args.field} to protect")
        secret = new_totp_secret() if args.two_factor else None
        if secret:
            # Before the vault is written and before config.json is touched:
            # an unconfirmed second factor must leave the install exactly as
            # it was, not half-moved.
            _confirm_two_factor(secret, _address_of(key),
                                issuer_for_field(args.field or args.app))
        if keyring_id and not keyring_store(keyring_id, password):
            raise SystemExit(
                "the keyring would not store the password, so nothing was "
                "changed. Choose a password you type instead."
            )
        header = create(path, key, password, totp_secret=secret, keyring_id=keyring_id)
        # Read it back before taking away the only other copy -- and for the
        # keyring, read the password back out of the keyring too, so a backend
        # that forgets is found now rather than at the next start-up.
        check = password_from_keyring(path) if keyring_id else password
        why = ""
        if not check:
            why = "the keyring did not give the password back"
        else:
            try:
                if unlock(path, check)["private_key"] != key:
                    why = "the protected copy holds a different key"
            except VaultError as exc:
                why = str(exc)
        if why:
            keyring_forget(keyring_id)
            try:
                Path(path).unlink()
            except OSError:
                pass
            raise SystemExit(
                f"{why}, so your key is still in {args.config} and nothing was "
                f"changed"
            )
        _clear_key_in_config(args.config, args.field)
        print(f"  key moved into {path}")
        print(f"  address: {header['address']}")
        if keyring_id:
            # The password itself is deliberately not printed. It is the app's
            # own business, like a session token, and a long random string on
            # screen only teaches the user to keep something they do not need.
            # What they do need is a backup of the account key -- the same
            # advice every wallet gives -- and that is said here instead.
            print(f"  password kept in this computer's keyring "
                  f"({keyring_backend_name()}); the app will not ask for it")
            print("  Keep a safe backup of your account key: a new system, or a")
            print("  reset keyring, leaves this file unopenable, and the key is")
            print("  what gets you back in.")
        else:
            print("  There is no way to recover this password. Write it down "
                  "somewhere safe:")
            print("  without it the account, and everything stored under it, "
                  "is gone.")
        return 0

    if args.command in ("add-2fa", "remove-2fa"):
        if not exists(path):
            raise SystemExit("protect the key with a password first")
        password = _password_for(path)
        if args.command == "remove-2fa":
            rewrite(path, password, totp_secret=None)
            print("  two-factor removed; the password alone opens the app now")
            return 0
        current = unlock(path, password)
        if current["totp_secret"]:
            print("  two-factor is already set up; leaving it alone")
            return 0
        secret = new_totp_secret()
        _confirm_two_factor(secret, address_in(path), issuer_for_field(args.app))
        rewrite(path, password, totp_secret=secret)
        print("  two-factor added")
        return 0

    if args.command == "passwd":
        if not exists(path):
            raise SystemExit("protect the key with a password first")
        if keyring_id_in(path):
            raise SystemExit(
                "this vault's password is kept in the keyring, so there is "
                "nothing to retype. Use use-password to take it out of the "
                "keyring and choose one of your own."
            )
        rewrite(path, _cli_password(), new_password=_cli_password("FILETRUST_NEW_PASSWORD"))
        print("  password changed")
        return 0

    if args.command == "use-password":
        # Out of the keyring, onto a password of the user's own: more to
        # remember, and proof against anything running as this user.
        if not exists(path):
            raise SystemExit("protect the key with a password first")
        stored = keyring_id_in(path)
        current = _password_for(path)
        chosen = _cli_password("FILETRUST_NEW_PASSWORD")
        rewrite(path, current, new_password=chosen, keyring_id="")
        if unlock(path, chosen)["private_key"]:
            keyring_forget(stored)
        print("  the app will ask you for this password from now on")
        return 0

    if args.command == "use-keyring":
        if not exists(path):
            raise SystemExit("protect the key with a password first")
        if keyring_id_in(path):
            print("  the password is already in the keyring; leaving it alone")
            return 0
        if not keyring_available():
            raise SystemExit("this computer has no keyring the app can use")
        current = _cli_password()
        unlock(path, current)   # refuse before changing anything
        password = new_random_password()
        keyring_id = new_keyring_id()
        if not keyring_store(keyring_id, password):
            raise SystemExit("the keyring would not store the password; "
                             "nothing was changed")
        rewrite(path, current, new_password=password, keyring_id=keyring_id)
        if password_from_keyring(path) != password:
            # Put it back the way it was rather than leave a vault whose
            # password is in neither place.
            rewrite(path, password, new_password=current, keyring_id="")
            keyring_forget(keyring_id)
            raise SystemExit("the keyring did not keep the password; nothing "
                             "was changed")
        print(f"  password moved into this computer's keyring "
              f"({keyring_backend_name()}); the app will not ask for it")
        print("  Keep a safe backup of your account key: a new system, or a")
        print("  reset keyring, leaves this file unopenable.")
        return 0

    return 2


if __name__ == "__main__":  # pragma: no cover
    # A bad password or a mistyped key is a normal thing for a person to do,
    # not a bug, so it gets one line rather than a traceback nobody can read.
    try:
        raise SystemExit(main())
    except VaultError as _exc:
        print(f"  {_exc}")
        raise SystemExit(1)
