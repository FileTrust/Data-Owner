"""Install the release-pinned consumer transfer executable, never setup keys."""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import sys
from urllib.parse import urljoin, urlsplit

import requests
from github_auth import github_token

HERE = Path(__file__).resolve().parent


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''): h.update(part)
    return h.hexdigest()


class Downloads:
    def __init__(self): self.token = github_token(); self.session = requests.Session()
    def get(self, url, **headers):
        for _ in range(6):
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.hostname not in {
                'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}:
                raise ValueError('Unapproved executable download host')
            request_headers = {'User-Agent': 'FileTrust-installer/1', 'Accept-Encoding': 'identity', **headers}
            if self.token and parsed.hostname == 'api.github.com': request_headers['Authorization'] = 'Bearer ' + self.token
            response = self.session.get(url, headers=request_headers, stream=True, allow_redirects=False, timeout=(10, 60))
            if response.status_code == 401 and 'Authorization' in request_headers:
                response.close(); self.token = None; continue
            if response.is_redirect:
                redirect = response.headers['Location']; response.close(); url = urljoin(url, redirect); continue
            if response.status_code in (401, 404):
                response.close(); raise ValueError('Transfer release unavailable. While private, use gh auth login for this repository and retry.')
            response.raise_for_status()
            return response
        raise ValueError('Too many executable download redirects')


def install(here=HERE):
    here = Path(here)
    descriptor = json.loads((here / 'vaultmesh-release.json').read_text())
    source = json.loads((here / 'update-source.json').read_text())
    repository = source['repository']; tag = descriptor['tag']
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository) or not re.fullmatch(r'[\w.-]+', tag):
        raise ValueError('Invalid transfer release location')
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    row = descriptor.get('assets', {}).get('linux-' + str(architecture))
    if platform.system() != 'Linux' or not row:
        raise ValueError('No verified transfer executable is published for this platform')
    if not re.fullmatch(r'[a-f0-9]{64}', row['sha256']) or not 0 < row['size'] < 100 * 1024**2:
        raise ValueError('Invalid executable hash or size')
    target = here / 'core/vaultmesh'; partial = target.with_suffix('.part')
    if target.parent.is_symlink() or target.is_symlink() or partial.is_symlink(): raise ValueError('Executable paths cannot be symbolic links')
    if target.is_file() and target.stat().st_size == row['size'] and digest(target) == row['sha256']:
        target.chmod(0o755); print('Transfer program: installed and checksum verified', flush=True); return
    remote = Downloads()
    with remote.get(f'https://api.github.com/repos/{repository}/releases/tags/{tag}', Accept='application/vnd.github+json') as response:
        raw = response.raw.read(4 * 1024**2 + 1)
        if len(raw) > 4 * 1024**2: raise ValueError('Release metadata exceeds size limit')
        release = json.loads(raw)
    asset = next((asset for asset in release['assets'] if asset['name'] == row['name'] and asset['size'] == row['size']), None)
    if not asset: raise ValueError('The pinned transfer executable is missing from its release')
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > row['size']: partial.unlink(); offset = 0
    headers = {'Accept': 'application/octet-stream'}
    if offset: headers['Range'] = f'bytes={offset}-'
    if offset < row['size']:
        with remote.get(asset['url'], **headers) as response:
            if response.status_code == 206:
                if not response.headers.get('Content-Range', '').startswith(f'bytes {offset}-'):
                    raise ValueError('Invalid transfer download resume response')
            elif response.status_code == 200: offset = 0
            else: raise ValueError('Unexpected executable download response')
            with partial.open('ab' if offset else 'wb') as output:
                last = -1
                for chunk in response.iter_content(1024 * 1024):
                    offset += len(chunk)
                    if offset > row['size']: raise ValueError('Executable exceeds its pinned size')
                    output.write(chunk)
                    percent = offset * 100 // row['size']
                    if percent != last:
                        print(f'Downloading transfer program: {percent}% ({offset}/{row["size"]} bytes)', flush=True); last = percent
    if partial.stat().st_size != row['size'] or digest(partial) != row['sha256']:
        partial.unlink(); raise ValueError('Transfer executable checksum failed; file discarded')
    with partial.open('rb') as stream:
        if stream.read(4) != b'\x7fELF': raise ValueError('Release asset is not a Linux executable')
    partial.chmod(0o755); os.replace(partial, target)
    print('Transfer program installed; pinned checksum verified', flush=True)


if __name__ == '__main__':
    try: install()
    except Exception as exc:
        print('Transfer setup stopped: ' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__) + '. Rerun installation to resume.', file=sys.stderr)
        raise SystemExit(1)
