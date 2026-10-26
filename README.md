# FileTrust Data Owner

The Data Owner application connects to the FileTrust network with a desktop
interface. Install it directly on Linux, or run the same interface in Docker
and use a desktop window or a browser.

## Get the application

```bash
git clone https://github.com/FileTrust/Data-Owner.git
cd Data-Owner
```

While this repository and its downloads are private, first sign in with
`gh auth login`. Public repositories and public downloads need no GitHub login.
No GitHub credential is included in the image or saved in the application.

## Native installation

```bash
bash install.sh
.venv/bin/python DO.py
```

Run this as the desktop user. The installer checks Python, installs missing
OS prerequisites on Debian/Ubuntu through sudo, creates a Python environment,
and downloads the required, checksum-pinned transfer program. It then validates
current network settings and offers to import or create a wallet and protect
it with a password. Existing accounts are preserved when installation resumes.
Do not pass private keys as command arguments.

Use `bash install.sh --menu` to add a desktop menu entry, or `--help` for
options. Close the app normally before reinstalling or updating.

Native requirements: Linux x86_64, Python 3.11 or later with Tk, and HTTPS
access to the network and package repositories. Docker provides the tested
Debian 12/Python 3.11 environment. Other Linux distributions may require their
own OS packages; this release has no ARM transfer binary.

## Docker installation

Install [Docker Engine and its Compose plugin](https://docs.docker.com/engine/install/),
then choose the interface:

```bash
# Same Python application, displayed in a browser:
bash docker.sh install --mode browser
bash docker.sh start

# Or a normal window on a local Linux X11/XWayland desktop:
# bash docker.sh install --mode desktop
```

Installation asks for a separate browser access password. It must contain
exactly eight printable characters because the local VNC transport uses that
format. The wallet password and optional two-factor check stay separate and
keep their normal protection. A fresh installation asks about its wallet;
a repeated installation keeps the existing one.

The browser URL appears after start. Browser and VNC listeners accept local
connections only. For remote use, forward the browser port over SSH; keep
these ports private. This mode displays the Python GUI through noVNC; it does
not add MetaMask, Trust Wallet, or browser-based transaction signing.

Docker uses Linux host networking. The supported Docker host is Linux x86_64.
Desktop mode requires a local display and `xauth`; no `xhost +` is needed.
The browser mode also works on a headless Linux server.

### Commands

```bash
bash docker.sh status
bash docker.sh logs
bash docker.sh stop
bash docker.sh start
bash docker.sh restart
bash docker.sh doctor
```

Stop/restart preserve the wallet, settings and files. Closing a Docker desktop
window exits the app instead of hiding it in a system tray. Stop waits for
active application work; it does not force-kill a running transfer.

To change the display while stopped:

```bash
bash docker.sh stop
bash docker.sh configure --mode desktop
# Or: bash docker.sh configure --mode browser --web-port 6080 --vnc-port 15900
bash docker.sh start
```

### Files and settings

Native settings and wallet files stay beside `DO.py`. Docker keeps its own
working application, wallet and settings in the project's named `app` volume.
It never adopts a native wallet automatically. Back up the whole application
state, including the encrypted wallet and its chosen unlock method.

Docker exposes the checkout's `files/` directory at `/files` in the file
picker. Place files there to select them for upload.
`FILETRUST_FILES_DIR` selects another absolute host folder. The folder must
be writable by the desktop user's uid/gid; existing host-folder ownership is
never changed automatically.

An advanced operator can set `FILETRUST_DOCKER_PROJECT` to give a second
installation its own volume and container. Choose different browser/VNC ports
for each instance and use the same project name for every later command.
Native and Docker accounts and settings remain separate.

### Updates and removal

For Docker, finish work and use:

```bash
git pull --ff-only
bash docker.sh update
# To restore the previous image/code if needed:
# bash docker.sh rollback
```

Docker updates preserve application state. Update notices remain available;
the native Python updater does not replace files inside a running container.

```bash
# Native runtime removal; wallet and settings are kept:
python3 uninstall.py
# Also delete the native account/settings and managed data (asks for DELETE):
python3 uninstall.py --purge

# Docker container removal; named volume is kept:
bash docker.sh uninstall
# Also delete this Docker application's named volume (asks for DELETE):
bash docker.sh uninstall --purge
```

Source checkouts, shared host files and Docker images are kept. Remove those
separately when no longer needed. Purging is irreversible; back up any wallet
and complete outstanding network duties first.

## Your account, and your config file

`config.json` ships with no key, so the app has no account until you make
one. The installer offers to do it; the app also refuses to open and tells
you how if there is no account yet.

Your address is worked out from your key, so it is not stored separately and
cannot disagree with it. The app shows you the address.

Keep `config.json` to yourself -- it holds your private key, and whoever has
that key *is* you on the network. If you ever need to send it to somebody for
help, delete the `do_private_key` line from the copy you send. Better still, put the
key behind a password, as described below, and then `config.json` holds no
secret at all.

A brand-new account has no funds, and the network charges a small fee per
transaction, so it needs funding before the first upload.

## Where the chain settings come from

`config.json` holds the contract addresses, the RPC URL and the discovery
nodes. The install reads them from the network's own config service, so a
fresh install is never stuck with whatever shipped in the repository:

```json
"network_config_url": "https://config.filetrust.io/v1/network-config"
```

After that it is never read on a timer. When the network is redeployed, pick
**Update network settings** from the tray icon; the app fetches once, writes
what changed, and asks you to restart. A redeploy happens a few times a year
and the answer carries every contract description on the chain, so polling it
would cost one small server a great deal for nothing.

Anything that goes wrong -- no network, service down, bad answer -- leaves the
settings exactly as they were, and a contract the service does not list keeps
the address it has rather than losing it.

That URL decides which chain this app talks to, so treat it as a setting you
own. The service uses HTTPS at `https://config.filetrust.io`; certificate
verification stays enabled. Set it to `""` to pin an install to the
addresses you put there yourself.

### Your own directory servers

The app finds keepers through directory servers. `discovery_urls` is the
network's list: it ships empty, the install fills it from the config service,
and **Update network settings** refreshes it -- so a server you add there
would be lost on the next update. Put yours here instead:

```json
"my_discovery_urls": ["http://my-node.example:4601"],
"use_only_my_discovery_urls": false
```

Your servers are asked first, then the network's, and nothing in the app ever
writes `my_discovery_urls`. Anyone can run a directory server; if you trust
only your own, set `use_only_my_discovery_urls` to true and the network's list
is ignored. Leaving it true with an empty list of your own falls back to the
network's, because an app with no directory server cannot find a keeper at
all.

## Protecting your key

Left alone, the private key sits in `config.json` in clear text, where anything
that can read the file owns the account: a backup, a folder that syncs to a
cloud drive, a support session where you paste your settings.

The installer offers to move it into `keyvault.json`, encrypted (scrypt on the
password, AES-256-GCM on the key). You can do it at any time later:

```bash
./install.sh --protect-key
```

There are two ways to hold the password, and setup asks which you want:

- **Your computer remembers it** (the default). The app invents a long random
  password and keeps it in the keyring your desktop already unlocks when you
  log in -- Keyring or KWallet on Linux, Keychain on macOS, Credential Manager
  on Windows. Nothing to remember, nothing typed at start-up. The password
  itself is never shown -- it is the app's own business. A keyring is not a
  backup though: on a new system, or after the keyring is reset, this file
  cannot be opened, so keep a safe backup of your account key, which is what
  gets you back in.
- **You choose a password**, typed each time the app starts. More to remember,
  and proof against other programs running as you, which can ask the keyring
  for the password exactly as the app does. The keyring protects a stolen file,
  a backup or a copied disk; a typed password protects that case too.

On a Windows-formatted disk (NTFS or exFAT, common for a second drive) file
permissions cannot be kept, so other accounts on the same machine can read
`keyvault.json`. It is encrypted, so they get nothing without the password --
worth knowing, not worth worrying about.

Either choice can be changed later, without a new account:

```bash
.venv/bin/python -m core.ft_keyvault use-keyring  --dir .   # stop typing it
FILETRUST_KEY_PASSWORD=yours \
  .venv/bin/python -m core.ft_keyvault use-password --dir .  # start typing it
```

It can also ask for a six-digit code from an authenticator app -- Google
Authenticator, Aegis, 1Password, anything that reads a standard TOTP QR code.
Setup prints the code in the terminal for you to scan, then makes you type one
code back before anything is changed:

```bash
./install.sh --2fa
```

Be clear about what the code buys. It is a second thing to present when *this
app* starts, and it stops somebody who watched you type the password. It is not
a second lock on the file: whoever has both `keyvault.json` and the password can
decrypt it with their own script and never meet the code prompt. The password
is the protection; the code is a gate on the app.

**Nobody can recover a password you chose -- not us, not a reinstall.** Lose
it and you lose the account and everything stored under it. Many people use
their computer's login password here, so there is nothing new to remember and
it still works on another machine.

With the keyring there is nothing to lose, but also nothing to carry: keep a
backup of your account key and you can always start again on a new system.

To see how an install is protected, change a password you chose yourself, or
turn the code off again:

```bash
.venv/bin/python -m core.ft_keyvault status --dir .
FILETRUST_KEY_PASSWORD=old FILETRUST_NEW_PASSWORD=new \
  .venv/bin/python -m core.ft_keyvault passwd --dir .
.venv/bin/python -m core.ft_keyvault remove-2fa --dir .
```

Command-line tools that import the app's modules can unlock without a prompt by
exporting `FILETRUST_KEY_PASSWORD` for that one command.

## The vaultmesh binary

`core/vaultmesh` moves the actual file pieces. It is not committed here:
it is about 31 MB and differs per platform. `install.sh` will fetch it
when a release is available for your machine; until then it says so and
finishes anyway, and everything except transfers works.

If you have the Vault Keeper source and Go installed, you can build it:

```bash
VAULTMESH_SOURCE=/path/to/FileTrust-VK/App/VK/code ./install.sh
```

## Running it as part of a load test instead

This app is also driven by the `load_test` role, which needs the other
repositories as well:

```bash
python3 scripts/network/checkout_role.py --role load_test
python3 run_filetrust_load_test.py
```

That is a developer path and needs the `FileTrust-scripts` checkout; it
is not required to use the app itself.

## Licence

Copyright 2026 **Electra Sphere Innovations** — [electrasi.es](https://electrasi.es)

FileTrust is a product of Electra Sphere Innovations — [filetrust.io](https://filetrust.io)

Functional Source License 1.1 with an Apache-2.0 future licence
(`FSL-1.1-ALv2`). You may read, run and change this software for any purpose,
including inside a company, and you may not use it to build a competing
product. Two years after a version is published, that version is also
available under Apache-2.0. The full terms are in [LICENSE](LICENSE).


## Signed native application updates

Native installations check signed release metadata and show a notice. Updates
are never applied automatically. Use the app's Updates menu to check and prepare
a compatible release, close the app and its workers, then follow its apply
instructions. Back up the wallet before maintenance. While releases are private,
the desktop user's GitHub read access is required. Docker uses the image update
commands above instead.

### Repair an empty Discovery list

Fresh installation fills the network Discovery list from the config service.
A nonempty custom list is preserved. To repair an older installation whose
network list is empty, stop the app and run:

```bash
# Docker:
bash docker.sh stop
bash docker.sh network-config repair-discovery
bash docker.sh start

# Native, after closing the app:
.venv/bin/python network-config.py repair-discovery
```

This command fills only an empty Discovery list. It preserves wallet, 2FA,
custom directory choices, contract addresses and ABI files.
