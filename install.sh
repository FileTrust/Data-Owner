#!/usr/bin/env bash
# BEGIN FILETRUST INSTALL BANNER — from root singature.txt
filetrust_install_banner() {
  local banner_dir banner_version='unknown' banner_line
  banner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -r "$banner_dir/VERSION" ]]; then
    IFS= read -r banner_version < "$banner_dir/VERSION" || [[ -n $banner_version ]]
    banner_version=${banner_version%$'\r'}
  fi
  cat <<'FILETRUST_BANNER_TOP'
███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝


Author: Ali Farahpoor
Company: Electra Sphere Innovations (ElectraSI.es)
Location: Barcelona, Spain
Contact: support@filetrust.io

FILETRUST_BANNER_TOP
  printf 'Version: %s %s\n' 'DO' "$banner_version"
  cat <<'FILETRUST_BANNER_BOTTOM'
Release Date: 26 October 2026

Documentation: https://docs.filetrust.io
Website: https://www.filetrust.io
FILETRUST_BANNER_BOTTOM
  printf '\n'
}
if [[ ${FILETRUST_INSTALL_BANNER_SHOWN:-0} != 1 ]]; then filetrust_install_banner; fi
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
#
# One-command setup for the FileTrust Data Owner app.
#
#   ./install.sh             set up, then tell you how to start
#   ./install.sh --menu      also add it to the desktop application menu
#   ./install.sh --yes       answer yes to every question: install the system
#                            packages, and create an account if there is none
#   ./install.sh --dry-run   show what would be installed, change nothing
#   ./install.sh --verbose   show every check, not only what needs doing
#   ./install.sh --new-account   create an account without asking, rather than
#                            offering to use a key you already have
#   ./install.sh --no-account    do not create one; you will add a key yourself
#   ./install.sh --protect-key   move the key into an encrypted file, asking
#                            for a password to encrypt it with
#   ./install.sh --2fa       also set up an authenticator app (needs a
#                            password-protected key)
#   ./install.sh --keyring   hold the password in the operating system's
#                            keyring, so the app asks for nothing (default)
#   ./install.sh --own-password   choose a password yourself instead, typed
#                            each time the app starts
#   ./install.sh --no-protect-key, --no-2fa   do not ask about either
#
# What this exists to solve: two of the things the app needs cannot come from
# pip at all. Tkinter, which draws the window, and the GTK bindings behind the
# tray icon are operating-system packages, named differently on every
# distribution. A user who only runs `pip install -r requirements.txt` gets a
# clean install and then "ModuleNotFoundError: No module named '_tkinter'" the
# first time they start the app, with nothing to tell them why. So this script
# installs them, asking first, instead of printing advice and giving up.
#
# It also fetches `vaultmesh`, the Go binary that moves the actual file pieces.
# That binary is deliberately not in the repository -- it is ~31 MB and
# per-platform -- so it comes from a release, or from a local build if you have
# the source.

set +x
set -euo pipefail
umask 077

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"
# Preserve all installer options when selecting the Docker backend.
DOCKER_MODE=""
DOCKER_ARGUMENTS=()
for option in "$@"; do
  case "$option" in
    --docker) DOCKER_MODE=docker ;;
    --browser) DOCKER_MODE=browser ;;
    *) DOCKER_ARGUMENTS+=("$option") ;;
  esac
done
if [[ -n $DOCKER_MODE ]]; then
  if [[ $DOCKER_MODE == browser ]]; then DOCKER_ARGUMENTS=(--mode browser "${DOCKER_ARGUMENTS[@]}"); fi
  FILETRUST_INSTALL_BANNER_SHOWN=1 exec bash "$APP_DIR/docker.sh" install "${DOCKER_ARGUMENTS[@]}"
fi
VAULTMESH="$APP_DIR/core/vaultmesh"
APP_NAME="FileTrust Data Owner"
ENTRY="DO.py"
WANT_MENU=0
ASSUME_YES=0
DRY_RUN=0
VERBOSE=0
NEW_ACCOUNT=""   # unset = ask; 1 = yes; 0 = no
PROTECT_KEY=""   # unset = ask; 1 = yes; 0 = no -- password on the key
WANT_2FA=""      # unset = ask; 1 = yes; 0 = no -- authenticator code
WANT_OWN_PASSWORD="" # unset = ask; 1 = type one; 0 = use the OS keyring
FT_PW=""

for arg in "$@"; do
  case "$arg" in
    --menu) WANT_MENU=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --verbose|-v) VERBOSE=1 ;;
    --new-account) NEW_ACCOUNT=1 ;;
    --no-account) NEW_ACCOUNT=0 ;;
    --protect-key) PROTECT_KEY=1 ;;
    --no-protect-key) PROTECT_KEY=0 ;;
    --2fa) WANT_2FA=1 ;;
    --own-password) WANT_OWN_PASSWORD=1 ;;
    --keyring) WANT_OWN_PASSWORD=0 ;;
    --no-2fa) WANT_2FA=0 ;;
    # Print the header block, however long it grows, rather than fixed lines.
    -h|--help) printf '%s\n' "Usage: bash install.sh [options]" "Native: --yes --menu --new-account --no-account --protect-key --own-password --2fa" "Docker: bash docker.sh install --mode desktop|browser" "Uninstall: python3 uninstall.py [--purge]"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
# A check that passes is not news. The installer used to narrate every one of
# them -- Python found, Tkinter present, bindings present -- which reads as a
# test log and buries the two or three lines that need the user to do
# something. These two print only with --verbose, and everything that asks for
# a decision, installs, or fails still speaks up.
step() { [ "$VERBOSE" = 1 ] && say "$*"; return 0; }
note() { [ "$VERBOSE" = 1 ] && printf '%s\n' "$*"; return 0; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# ── System packages, the part pip cannot do ──────────────────────────────────
PM=""
PM_INSTALL=""
if   command -v apt-get >/dev/null 2>&1; then PM=apt;    PM_INSTALL="apt-get install -y"
elif command -v dnf     >/dev/null 2>&1; then PM=dnf;    PM_INSTALL="dnf install -y"
elif command -v pacman  >/dev/null 2>&1; then PM=pacman; PM_INSTALL="pacman -S --needed --noconfirm"
elif command -v zypper  >/dev/null 2>&1; then PM=zypper; PM_INSTALL="zypper install -y"
elif command -v apk     >/dev/null 2>&1; then PM=apk;    PM_INSTALL="apk add"
fi

# Which package carries a feature, per distribution. This table is the whole
# reason a user cannot be told one command that works everywhere.
pkg_names() {
  case "$1:$PM" in
    tk:apt)       echo "python3-tk" ;;
    tk:dnf)       echo "python3-tkinter" ;;
    tk:pacman)    echo "tk" ;;
    tk:zypper)    echo "python3-tk" ;;
    tk:apk)       echo "python3-tkinter" ;;
    tray:apt)     echo "python3-gi gir1.2-ayatanaappindicator3-0.1" ;;
    tray:dnf)     echo "python3-gobject libayatana-appindicator-gtk3" ;;
    tray:pacman)  echo "python-gobject libayatana-appindicator" ;;
    tray:zypper)  echo "python3-gobject typelib-1_0-AyatanaAppIndicator3-0_1" ;;
    tray:apk)     echo "py3-gobject3" ;;
  esac
}

as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

# Defaults to yes, because the user asked for this by running the installer.
# Returns no without blocking when there is nobody there to answer.
ask() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  printf '%s [Y/n] ' "$1"
  local reply=""
  read -r reply || return 1
  case "$reply" in [Nn]*) return 1 ;; *) return 0 ;; esac
}

# install_system_packages <what it is for> <package>...
install_system_packages() {
  local label="$1"; shift
  [ "$#" -gt 0 ] || return 1
  if [ -z "$PM" ]; then
    warn "  unknown package manager; install this yourself: $*"
    return 1
  fi
  if [ "$(id -u)" != 0 ] && ! command -v sudo >/dev/null 2>&1; then
    warn "  sudo is not installed here. As root, run:  $PM_INSTALL $*"
    return 1
  fi
  echo "  needed system package(s): $*"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  would run: $PM_INSTALL $*"
    return 0
  fi
  ask "  Install $label now? This asks for your password." || { warn "  skipped"; return 1; }
  # shellcheck disable=SC2086  # both must word-split: command and package list
  if as_root $PM_INSTALL $*; then
    return 0
  fi
  # A stale package index is the usual reason the first attempt fails on a
  # freshly installed system, so refresh once and try again before giving up.
  if [ "$PM" = apt ]; then
    echo "  refreshing the package list and trying once more"
    as_root apt-get update -qq || true
    # shellcheck disable=SC2086
    as_root $PM_INSTALL $* && return 0
  fi
  warn "  that did not work. Run it yourself:  $PM_INSTALL $*"
  return 1
}

# ── 1. Python ────────────────────────────────────────────────────────────────
source "$APP_DIR/package_prerequisites.sh"
if [ "$DRY_RUN" = 0 ]; then filetrust_prerequisites 1 || die "Missing operating-system prerequisites"; fi
step "Checking Python"
PY=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1; then
    # 3.11 is the floor: the app uses `X | Y` type syntax and tomllib.
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
      PY="$candidate"
      break
    fi
  fi
done
[ -n "$PY" ] || die "Python 3.11 or newer is required. Install python3 and run this again."
note "  using $PY ($("$PY" -V 2>&1))"
if [ "$DRY_RUN" = 0 ]; then
  "$PY" "$APP_DIR/ft_update_bootstrap.py" --installer-check
  command -v flock >/dev/null || die "Install util-linux (flock), then run this installer again."
  exec 9< "$APP_DIR/.filetrust-updates/update.lock"
  flock -n 9 || die "An update or another installer is running."
  exec 8< "$APP_DIR/.filetrust-updates/run.lock"
  flock -n 8 || die "Close the app and finish its transfers before installing."
fi

# ── 2. Tkinter, the part pip cannot do ───────────────────────────────────────
step "Checking the graphical toolkit (Tkinter)"
if "$PY" -c 'import tkinter' 2>/dev/null; then
  note "  already present"
else
  say "Installing the graphical toolkit (Tkinter)"
  warn "  Tkinter is missing. It is an operating-system package, not a pip one."
  install_system_packages "Tkinter" $(pkg_names tk) || true
  if "$PY" -c 'import tkinter' 2>/dev/null; then
    echo "  installed"
  elif [ "$DRY_RUN" = 1 ]; then
    echo "  (dry run: not installed)"
  else
    echo
    echo "  The window cannot open without it. Install it, then run this again:"
    if [ -n "$PM" ]; then echo "      sudo $PM_INSTALL $(pkg_names tk)"
    else echo "      your distribution's python3 tk package"
    fi
    echo
    die "Tkinter is required."
  fi
fi

# ── 2b. Tray icon bindings, also not pip's to give ───────────────────────────
# Checked against the system Python on purpose: these bindings live in the
# distribution's own directory, which the app adds to its path at run time. A
# virtual environment cannot see them, so testing inside the venv would report
# them missing even when they are installed.
step "Checking the tray icon bindings"
if [ "${FILETRUST_CONTAINER:-0}" = 1 ]; then
  note "  tray disabled in container; closing the window exits the app"
elif "$PY" -c 'import gi' 2>/dev/null; then
  note "  already present"
else
  say "Checking the tray icon bindings"
  echo "  missing, so the tray icon can be absent on GNOME-style desktops"
  if install_system_packages "the tray bindings" $(pkg_names tray); then
    "$PY" -c 'import gi' 2>/dev/null && echo "  installed" \
      || warn "  still missing. The app is fine; only the tray icon may not show."
  else
    warn "  the app is fine without them; only the tray icon may not show"
  fi
fi

# ── 3. Virtual environment and Python packages ───────────────────────────────
if [ "${FILETRUST_CONTAINER:-0}" = 1 ]; then
  "$VENV/bin/python" -m pip check || die "Container Python dependencies are incomplete"
else
say "Installing Python packages"
# A virtual environment normally points at the system interpreter with a
# symlink. That breaks when the app lives on a Windows-formatted disk: the two
# NTFS drivers write reparse points differently, so a venv made under one is
# unreadable under the other, and after a remount `.venv/bin/python` is simply
# "no such file" -- which this app then survives by falling back to the system
# interpreter, quietly losing every package it installed here.
#
# So the interpreter is tested rather than assumed, and rebuilt with a real copy
# of itself when the link cannot be followed. Costs a few megabytes; removes the
# whole failure mode.
# Deleting fails on a Windows-formatted disk -- rm reports "Directory not
# empty" on entries whose reparse points the driver cannot read -- so the
# broken environment is moved out of the way instead. Nothing is destroyed,
# and the rebuild gets a clean path either way.
discard_venv() {
  rm -rf "$VENV" 2>/dev/null || true
  if [ -d "$VENV" ]; then
    local aside="$VENV.broken-$(date +%Y%m%d-%H%M%S)"
    mv "$VENV" "$aside" || die "Could not clear $VENV; remove it yourself and run this again."
    echo "  the old environment was moved to $(basename "$aside")"
  fi
}

venv_interpreter_runs() {
  # Must actually answer, not merely exit 0. On a Windows-formatted disk the
  # interpreter link can survive as a seven-byte text file that the shell runs
  # as a script: it succeeds, prints nothing, and a test for a clean exit calls
  # that a working Python.
  [ -x "$VENV/bin/python" ] || return 1
  [ "$("$VENV/bin/python" -c 'print("filetrust-ok")' 2>/dev/null)" = "filetrust-ok" ]
}

if venv_interpreter_runs && ! "$VENV/bin/python" -c "import tkinter" >/dev/null 2>&1; then
  echo "The old environment lacks Tkinter; rebuilding its Python environment, preserving your account and files."
  discard_venv
fi
if ! venv_interpreter_runs; then
  # -d, not -e on the interpreter: a dangling symlink fails every existence
  # test that follows it, so the broken environment was left in place and the
  # rebuild then tripped over its own leftovers.
  if [ -d "$VENV" ]; then
    warn "  the existing environment's interpreter cannot be run; rebuilding it"
    discard_venv
  fi
  "$PY" -m venv "$VENV" || die "Could not create a virtual environment in $VENV"
  if ! venv_interpreter_runs; then
    echo "  this filesystem does not keep symlinks; using a copied interpreter"
    discard_venv
    "$PY" -m venv --copies "$VENV" \
      || die "Could not create a virtual environment in $VENV"
    venv_interpreter_runs \
      || die "The environment in $VENV still cannot run. Try a different folder."
  fi
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$APP_DIR/requirements.txt" \
  || die "Package installation failed. The versions in requirements.txt are pinned; see the file."
echo "  done"

# Some packages are imported behind a try/except so the app still opens without
# them. That is right for robustness and wrong for diagnosis: the feature just
# is not there, and nobody can tell whether that is by design. Name them here,
# while the person who could fix it is still looking at the terminal.
for feature in "keeper map:tkintermapview" "drag and drop:tkinterdnd2" "tray package:pystray"; do
  if "$VENV/bin/python" -c "import ${feature#*:}" 2>/dev/null; then
    note "  ${feature%%:*}: ready"
  else
    warn "  ${feature%%:*}: unavailable (${feature#*:} did not import)"
  fi
done

fi

# ── 4. vaultmesh, the piece-transfer binary ──────────────────────────────────
if [ "$DRY_RUN" = 1 ]; then
  echo "Would download and verify the release-pinned transfer program."
else
  say "Installing the transfer program"
  "$VENV/bin/python" "$APP_DIR/ft_transfer.py" || die "The transfer program is required. Installation is incomplete; rerun to resume."
fi

# ── 5. Optional desktop menu entry ───────────────────────────────────────────
if [ "$WANT_MENU" = "1" ]; then
  say "Adding it to the application menu"
  DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
  mkdir -p "$DESKTOP_DIR"
  # Absolute paths: a .desktop entry is launched from an unknown directory.
  cat > "$DESKTOP_DIR/filetrust-do.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Comment=Store and share files on the FileTrust network
Exec=$VENV/bin/python $APP_DIR/$ENTRY
Path=$APP_DIR
Icon=$APP_DIR/core/assets/icon.png
Terminal=false
Categories=Network;FileTransfer;
EOF
  command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
  echo "  added: $DESKTOP_DIR/filetrust-do.desktop"
  [ -f "$APP_DIR/core/assets/icon.png" ] \
    || warn "  no icon at core/assets/icon.png, so the menu entry shows a default one"
fi

# ── 5b. Your account ──────────────────────────────────────────────────────────
# The app signs everything with a private key, and until now the repository
# shipped one: a well-known test key, identical for every person who cloned it.
# Nothing secret leaks, but everyone starts out sharing one identity, which is
# the wrong habit for a file-storage app to teach. So offer to make a fresh one.
#
# Generated with the same library the app itself signs with, so there is no
# second implementation of key generation to get wrong.
# ── Your settings file ───────────────────────────────────────────────────────
# The repository ships config.default.json and ignores config.json, because that
# file holds your private key and has to survive every update. A tracked copy
# collided with its own upstream version on every pull, naming the one file a
# user must never lose.
#
# New settings still reach you: anything in the default and missing here is
# added, and nothing you have already set is touched.
# On a Windows-formatted disk every file reads as executable, so git reports
# files as modified when only the permission bit differs -- which is how a
# clean clone comes to show changes nobody made, and how a pull comes to be
# refused. Telling git to ignore the mode is the standard remedy, and it is set
# here rather than explained in a README nobody reaches at the right moment.
if [ -d "$APP_DIR/.git" ] && command -v git >/dev/null 2>&1; then
  if [ "$(git -C "$APP_DIR" config --get core.fileMode || echo true)" != "false" ]; then
    git -C "$APP_DIR" config core.fileMode false 2>/dev/null \
      && echo "  told git to ignore permission bits on this filesystem"
  fi
fi

step "Checking your settings file"
DEFAULT_CONFIG="$APP_DIR/config.default.json"
if [ ! -f "$DEFAULT_CONFIG" ]; then
  note "  this copy ships config.json directly; nothing to merge"
elif [ ! -f "$APP_DIR/config.json" ]; then
  cp "$DEFAULT_CONFIG" "$APP_DIR/config.json"
  chmod 600 "$APP_DIR/config.json" 2>/dev/null || true
  say "Your settings file"
  echo "  created config.json from the shipped defaults"
else
  FT_CONFIG="$APP_DIR/config.json" FT_DEFAULT="$DEFAULT_CONFIG" \
  "$VENV/bin/python" <<'SETTINGS_MERGE'
import json, os
from pathlib import Path

mine = Path(os.environ["FT_CONFIG"])
shipped = Path(os.environ["FT_DEFAULT"])
KEEP_ALWAYS = ("do_private_key", "req_private_key")
try:
    current = json.loads(mine.read_text(encoding="utf-8"))
    defaults = json.loads(shipped.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    print(f"  could not read the settings files ({exc}); leaving yours alone")
    raise SystemExit(0)

def is_heading(key):
    # Section titles, not settings: "## THE NETWORK" now, "_03_..." before it.
    # Counting them as added or removed told the user that thirteen settings
    # had appeared when nothing of theirs had changed at all.
    return key.startswith("##") or key.startswith("_")

added = [k for k in defaults if k not in current and not is_heading(k)]
# A key the app no longer reads is clutter. The private key is never in the
# defaults and must never be taken out by this rule.
removed = [k for k in current
           if k not in defaults and k not in KEEP_ALWAYS and not is_heading(k)]
rewritten = [k for k in current if is_heading(k) and k not in defaults]
if not added and not removed and not rewritten:
    raise SystemExit(0)

merged = {key: current.get(key, value) for key, value in defaults.items()}
for key in KEEP_ALWAYS:
    if key in current:
        merged[key] = current[key]
mine.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
if added:
    shown = ", ".join(added[:4]) + (" ..." if len(added) > 4 else "")
    print(f"  added {len(added)} new setting(s): {shown}")
if removed:
    print(f"  removed {len(removed)} setting(s) the app no longer reads")
SETTINGS_MERGE
fi

# ── Current validated network settings ───────────────────────────────────────
if [ "$DRY_RUN" = 1 ]; then
  note "  would fetch and validate current network settings"
else
  say "Network settings"
  FILETRUST_NETWORK_INSTALL_LOCK_FD=8 "$VENV/bin/python" "$APP_DIR/network-config.py" bootstrap --home "$APP_DIR" || die "Current network settings could not be validated. Retry this installer; completed work is retained."
fi

step "Checking your account"
ACCOUNT_KEY_FIELD="do_private_key"
have_account() {
  # A protected key counts as an account even though config.json looks empty:
  # without this the installer would offer to generate a second account over
  # the top of a key it simply cannot see.
  [ -f "$APP_DIR/keyvault.json" ] && return 0
  FT_CONFIG="$APP_DIR/config.json" FT_FIELD="$ACCOUNT_KEY_FIELD" \
  "$VENV/bin/python" <<'PY'
# Values arrive in the environment, not as arguments: a script fed on stdin
# does not receive trailing arguments the same way on every Python, and one
# that silently drops them turns "you have an account" into a crash.
import json, os
try:
    with open(os.environ["FT_CONFIG"], encoding="utf-8") as fh:
        raise SystemExit(0 if str(json.load(fh).get(os.environ["FT_FIELD"]) or "").strip() else 1)
except (OSError, ValueError, KeyError):
    raise SystemExit(1)
PY
}

if have_account; then
  # Never regenerate over an existing key. That key owns everything already
  # uploaded under it; replacing it does not move those files, it abandons
  # them. This is a refusal, not a question.
  note "  this install already has an account; leaving it alone"
  # The address is public, and the vault stores it in clear text for exactly
  # this: saying which account an install belongs to without the password.
  FT_CONFIG="$APP_DIR/config.json" FT_FIELD="$ACCOUNT_KEY_FIELD" \
  FT_VAULT="$APP_DIR/keyvault.json" FT_VERBOSE="$VERBOSE" \
  "$VENV/bin/python" <<'PY'
import json, os
from web3 import Web3
vault = os.environ.get("FT_VAULT", "")
if vault and os.path.isfile(vault):
    with open(vault, encoding="utf-8") as fh:
        address = str(json.load(fh).get("address") or "")
    print(f"  your address: {address or '(the vault does not say)'}"
          if os.environ.get("FT_VERBOSE") == "1" else "", end="")
    raise SystemExit(0)
with open(os.environ["FT_CONFIG"], encoding="utf-8") as fh:
    key = str(json.load(fh).get(os.environ["FT_FIELD"]) or "").strip()
try:
    if os.environ.get("FT_VERBOSE") == "1":
        print(f"  your address: {Web3().eth.account.from_key(key).address}")
except Exception as exc:
    print(f"  the key in config.json cannot be used: {exc}")
PY
elif [ "$NEW_ACCOUNT" = "0" ]; then
  warn "  no account, and --no-account was given"
  echo "  Put your own private key in config.json as $ACCOUNT_KEY_FIELD before starting."
elif [ "$DRY_RUN" = 1 ]; then
  echo "  would generate a new account and write it to config.json"
elif [ -t 0 ] && [ "$NEW_ACCOUNT" != "1" ] \
     && ask "  Do you already have a private key you want to use here?"; then
  # For someone installing on a second machine, or moving an account across.
  # Read without echoing and never printed back: a key in the scrollback
  # outlives the install, and these sessions get shared when something goes
  # wrong. Checked by the signing library itself, so a mistyped key fails now
  # rather than at the first transaction.
  printf '  Paste your private key (it will not be shown): '
  read -r -s FT_IMPORT_KEY || FT_IMPORT_KEY=""
  echo
  if ( cd "$APP_DIR" \
       && FILETRUST_IMPORT_KEY="$FT_IMPORT_KEY" "$VENV/bin/python" \
            -m core.ft_keyvault import-key \
            --config "$APP_DIR/config.json" --field "$ACCOUNT_KEY_FIELD" ); then
    :
  else
    warn "  that key was not accepted; this install still has no account"
  fi
  FT_IMPORT_KEY=""
elif [ "$NEW_ACCOUNT" = "1" ] || ask "  Generate a new account for this app?"; then
  FT_CONFIG="$APP_DIR/config.json" FT_FIELD="$ACCOUNT_KEY_FIELD" \
  "$VENV/bin/python" <<'PY'
import json, os, stat, tempfile
from pathlib import Path
from web3 import Web3

path, field = Path(os.environ["FT_CONFIG"]), os.environ["FT_FIELD"]
config = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
account = Web3().eth.account.create()
config[field] = account.key.hex()
if not config[field].startswith("0x"):
    config[field] = "0x" + config[field]

# Write through a temporary file in the same directory, created 0600, so the
# key is never briefly world-readable and a crash mid-write cannot leave the
# config truncated.
fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".config-", suffix=".json")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
except BaseException:
    os.unlink(tmp)
    raise

mode = stat.S_IMODE(os.stat(path).st_mode)
# The private key is deliberately not printed: terminal scrollback outlives
# the install, and these sessions get shared when something goes wrong.
print(f"  created. your address: {account.address}")
if mode & 0o077:
    print(f"  NOTE: {path} is mode {mode:04o} -- this filesystem cannot keep")
    print("        permissions, so other accounts on this machine can read the key.")
PY
  echo
  echo "  Two things to know:"
  echo "    - A new account has no funds. Uploading costs a small fee, so it"
  echo "      needs funding before the first upload."
  echo "    - config.json now holds your private key. It is yours alone; never"
  echo "      send it to anyone. If you ever have to share it for help, delete"
  echo "      the $ACCOUNT_KEY_FIELD line from the copy you send."
else
  warn "  skipped"
  echo "  Put your own private key in config.json as $ACCOUNT_KEY_FIELD before starting."
fi

# ── 5c. Protecting your key ───────────────────────────────────────────────────
# A key in config.json is owned by anything that can read the file: a backup, a
# folder that syncs to a cloud drive, a support session where someone pastes
# their settings. So move it into keyvault.json, encrypted.
#
# Two ways to hold the password, and the default is the keyring your desktop
# already unlocks when you log in: the app invents a long random password,
# keeps it there, and asks you for nothing at start-up. A password you choose
# is the other option -- more to remember, and proof against other programs
# running as you, which can ask the keyring just as the app does.
#
# Offered, not forced, either way. A protected key that cannot be opened is a
# real risk of its own, and that is the user's call to make.
step "Protecting your key"
KEYVAULT_TOOL=("$VENV/bin/python" -m core.ft_keyvault)
run_keyvault() { ( cd "$APP_DIR" && "${KEYVAULT_TOOL[@]}" "$@" ); }
# Reports whether the key is locked, and says how only when asked: the Ready
# block at the end tells the user what they need to know in one sentence.
quiet_status() {
  if [ "$VERBOSE" = 1 ]; then
    run_keyvault status --dir "$APP_DIR"
  else
    run_keyvault status --dir "$APP_DIR" >/dev/null
  fi
}

# Reads a password twice, without echoing it, into FT_PW.
read_new_password() {
  local first="" second=""
  while :; do
    printf '  Choose a password (at least 8 characters): '
    read -r -s first || return 1
    echo
    if [ "${#first}" -lt 8 ]; then
      warn "  too short"
      continue
    fi
    printf '  Type it again: '
    read -r -s second || return 1
    echo
    if [ "$first" != "$second" ]; then
      warn "  those two do not match"
      continue
    fi
    FT_PW="$first"
    return 0
  done
}

want_two_factor() {
  case "$WANT_2FA" in
    1) return 0 ;;
    0) return 1 ;;
    *) ask "  Also ask for a code from an authenticator app (two-factor)?" ;;
  esac
}

if quiet_status; then
  # Already protected. The only thing left to offer is the second factor, and
  # adding it means opening the vault, so it needs the password.
  if run_keyvault has-2fa --dir "$APP_DIR"; then
    # Say so. A user who ran --2fa deserves an answer, and silence reads as
    # "the flag did nothing", which is what it looked like.
    say "Protecting your key"
    echo "  two-factor is already set up; leaving it alone"
    echo "  To scan a new code, remove it and add it again:"
    echo "    .venv/bin/python -m core.ft_keyvault remove-2fa --dir ."
    echo "    .venv/bin/python -m core.ft_keyvault add-2fa --dir . --app $ACCOUNT_KEY_FIELD"
  else
    if [ "$DRY_RUN" = 1 ]; then
      echo "  would offer to add two-factor"
    elif [ ! -t 0 ]; then
      : # nobody to ask
    elif want_two_factor; then
      # A keyring install has no password to ask for: the tool reads it from
      # the keyring itself. Only a user who chose their own has to type it.
      FT_PW=""
      if ! run_keyvault keyring-holds-password --dir "$APP_DIR"; then
        printf '  Your password: '
        read -r -s FT_PW || FT_PW=""
        echo
      fi
      if FILETRUST_KEY_PASSWORD="$FT_PW" run_keyvault add-2fa --dir "$APP_DIR" \
           --app "$ACCOUNT_KEY_FIELD"; then
        :
      else
        warn "  two-factor was not added"
      fi
      FT_PW=""
    fi
  fi
elif ! have_account; then
  echo "  no key to protect yet"
elif [ "$DRY_RUN" = 1 ]; then
  echo "  would offer to move the key into an encrypted keyvault.json"
elif [ "$PROTECT_KEY" = "0" ]; then
  note "  skipped; the key stays in config.json in clear text"
elif [ ! -t 0 ]; then
  echo "  not a terminal, so no password can be chosen here"
  echo "  Run ./install.sh again from a terminal to protect the key."
elif say "Protecting your key" && { [ "$PROTECT_KEY" = "1" ] \
     || ask "  Lock your private key, so nobody else can use it?"; }; then
  # One question at a time, in the order the user thinks about them: how the
  # password is kept first, because that is what locking the key means, and the
  # authenticator code second, because it is a separate thing on top. Asked the
  # other way round, the code question arrived before there was anything to put
  # a code in front of.
  # The keyring unless this computer has none, or the user asks to type one.
  USE_KEYRING=0
  if ! run_keyvault keyring-check --dir "$APP_DIR"; then
    echo "  this computer has no keyring the app can use, so you will need a"
    echo "  password of your own"
  elif [ "$WANT_OWN_PASSWORD" = "1" ]; then
    :
  elif [ "$WANT_OWN_PASSWORD" = "0" ]; then
    USE_KEYRING=1
  else
    echo
    echo "  Two ways to do this:"
    echo "    - let your computer remember it (nothing to type, ever, but it"
    echo "      is gone if this system is reinstalled)"
    echo "    - choose a password yourself (typed each time the app starts,"
    echo "      and it still works on another machine -- your computer login"
    echo "      password is a fine choice, so there is nothing new to learn)"
    echo
    if ask "  Let your computer remember it?"; then USE_KEYRING=1; fi
  fi

  TWO_FACTOR_FLAG=""
  want_two_factor && TWO_FACTOR_FLAG="--two-factor"

  if [ "$USE_KEYRING" = 1 ]; then
    if run_keyvault protect --dir "$APP_DIR" --config "$APP_DIR/config.json" \
         --field "$ACCOUNT_KEY_FIELD" --keyring $TWO_FACTOR_FLAG; then
      :
    else
      # A keyring can be present and still refuse -- a locked wallet, a
      # session bus that is not really there. The key is untouched, so the
      # honest next step is the other option rather than giving up on
      # protecting it at all.
      warn "  the keyring could not hold the password"
      echo "  Choose a password instead; the app will ask for it at start-up."
      USE_KEYRING=0
    fi
  fi
  if [ "$USE_KEYRING" = 0 ]; then
    echo
    echo "  There is no way to recover this password. If you lose it you lose"
    echo "  the account, and every file stored under it, for good."
    echo
    if read_new_password; then
      if FILETRUST_KEY_PASSWORD="$FT_PW" run_keyvault protect \
           --dir "$APP_DIR" --config "$APP_DIR/config.json" \
           --field "$ACCOUNT_KEY_FIELD" $TWO_FACTOR_FLAG; then
        echo "  The app will ask for this password each time it starts."
      else
        warn "  the key was not protected; it is still in config.json"
      fi
      FT_PW=""
    else
      warn "  skipped"
    fi
  fi
else
  note "  skipped; the key stays in config.json in clear text"
  note "  You can do it later with:  ./install.sh --protect-key"
fi

# The address belongs to the key, wherever the key is kept. Read from the vault
# when there is one, because the vault stores it in clear text for exactly this.
account_address() {
  FT_CONFIG="$APP_DIR/config.json" FT_FIELD="$ACCOUNT_KEY_FIELD" \
  FT_VAULT="$APP_DIR/keyvault.json" \
  "$VENV/bin/python" - <<'ADDRESS' 2>/dev/null || true
import json, os
vault = os.environ.get("FT_VAULT", "")
if vault and os.path.isfile(vault):
    with open(vault, encoding="utf-8") as fh:
        print(str(json.load(fh).get("address") or ""))
    raise SystemExit(0)
try:
    with open(os.environ["FT_CONFIG"], encoding="utf-8") as fh:
        key = str(json.load(fh).get(os.environ["FT_FIELD"]) or "").strip()
    if key:
        from web3 import Web3
        print(Web3().eth.account.from_key(key).address)
except Exception:
    pass
ADDRESS
}

# What a user needs at the end is their address, how to start the app, and one
# sentence about their key. Everything else that used to be here was written
# for whoever built this.
say "Ready"
ACCOUNT_ADDRESS="$(account_address)"
[ -n "$ACCOUNT_ADDRESS" ] && echo "Your address: $ACCOUNT_ADDRESS"
echo "Start the app with:"
echo "    $VENV/bin/python $APP_DIR/$ENTRY"
[ "$WANT_MENU" = "1" ] || echo "Or add it to your application menu:  ./install.sh --menu"
echo
if [ -f "$APP_DIR/keyvault.json" ]; then
  echo "Your private key is in keyvault.json, encrypted."
  if run_keyvault keyring-holds-password --dir "$APP_DIR"; then
    echo "Its password is in this computer's keyring, so the app will not ask"
    echo "for it. Keep a backup of your account key: a keyring is not a backup,"
    echo "and the key is what gets you back in on a new system."
  else
    echo "The app will ask for your password each time it starts."
  fi
else
  echo "Your key is in config.json, in clear text. Keep that file to yourself,"
  echo "or lock it:  ./install.sh --protect-key"
fi
