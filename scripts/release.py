#!/usr/bin/env python3
"""Fail-closed release gate and resumable publisher. No third-party Python packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPO = 'cybrota/scharf'
VERSION_FILE = 'release/version.txt'
VERSION_RE = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
ARCHIVES = {'scharf_Darwin_arm64.zip', 'scharf_Darwin_x86_64.zip',
            'scharf_Linux_arm64.zip', 'scharf_Linux_armv6.zip', 'scharf_Linux_x86_64.zip'}


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def version(text):
    # A single final newline is allowed, whitespace and leading zeroes are not.
    value = text.removesuffix('\n')
    match = VERSION_RE.fullmatch(value)
    if not match:
        raise ValueError('Expected exactly vMAJOR.MINOR.PATCH')
    return value, tuple(map(int, match.groups()))


def api(endpoint, method='GET', payload=None, missing_ok=False):
    args = ['gh', 'api', '--method', method, '-H', 'X-GitHub-Api-Version: 2022-11-28', endpoint]
    if payload is not None:
        args += ['--input', '-']
    result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True)
    if result.returncode:
        if missing_ok and result.returncode == 1 and result.stderr.rstrip().endswith('(HTTP 404)'):
            return None
        raise RuntimeError(f'GitHub API {method} {endpoint} failed: {result.stderr}')
    return json.loads(result.stdout) if result.stdout else None


def tag_commit(tag):
    obj = api(f'repos/{REPO}/git/ref/tags/{tag}', missing_ok=True)
    if obj is None:
        return None
    obj = obj['object']
    for _ in range(8):
        if obj['type'] == 'commit':
            return obj['sha']
        if obj['type'] != 'tag':
            break
        obj = api(f'repos/{REPO}/git/tags/{obj["sha"]}')['object']
    raise ValueError('Tag does not resolve to a commit')


def check_versions(wanted, tags, existing, sha):
    _, target = version(wanted)
    if existing is not None and existing != sha:
        raise ValueError('Existing tag points at a different commit; never move it')
    for tag in tags:
        if VERSION_RE.fullmatch(tag) and tag != wanted and version(tag)[1] >= target:
            raise ValueError(f'{wanted} does not exceed existing semantic tag {tag}')


def context(env, event):
    if (env.get('GITHUB_REPOSITORY') != REPO or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') != 'push' or event.get('deleted')):
        raise ValueError('Publishing is allowed only for a push to cybrota/scharf main')
    sha, before = env.get('GITHUB_SHA', ''), event.get('before', '')
    if not re.fullmatch('[0-9a-f]{40}', sha) or event.get('after') != sha:
        raise ValueError('Event/checkout commit mismatch')
    if not re.fullmatch('[0-9a-f]{40}', before) or before == '0' * 40:
        raise ValueError('Missing prior main commit')
    return sha, before


def intent():
    wanted, _ = version(Path(VERSION_FILE).read_text())
    notes = Path('release/notes.md').read_text()
    if not notes.startswith(f'# Scharf {wanted}\n') or len(notes.strip()) < 40:
        raise ValueError('Release notes must match the version')
    return wanted


def prepare():
    sha, before = context(os.environ, json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()))
    if run('git', 'rev-parse', 'HEAD') != sha:
        raise ValueError('Checkout must be the exact event commit')
    subprocess.check_call(['git', 'merge-base', '--is-ancestor', before, sha])
    wanted = intent()
    changed = run('git', 'diff', '--name-only', before, sha, '--', VERSION_FILE)
    if changed != VERSION_FILE:
        raise ValueError('This push did not change the release version')
    subprocess.check_call(['git', 'fetch', '--tags', 'origin'])
    check_versions(wanted, run('git', 'tag', '--list').splitlines(), tag_commit(wanted), sha)
    local = subprocess.run(['git', 'rev-parse', '--verify', f'refs/tags/{wanted}^{{commit}}'],
                           capture_output=True, text=True)
    if local.returncode == 0:
        if local.stdout.strip() != sha:
            raise ValueError('Local tag mismatch')
    else:
        subprocess.check_call(['git', 'tag', wanted, sha])
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'version={wanted}\n')


def assets(directory, wanted):
    directory = Path(directory)
    names = ARCHIVES | {f'scharf_{wanted[1:]}_checksums.txt'}
    found = {p.name for p in directory.glob('*.zip')} | {p.name for p in directory.glob('*checksums.txt')}
    if found != names:
        raise ValueError(f'Unexpected or missing release files: {found ^ names}')
    hashes = {}
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f'Invalid artifact {name}')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = directory / f'scharf_{wanted[1:]}_checksums.txt'
    lines = manifest.read_text().splitlines()
    expected = {f'{hashes[name]}  {name}' for name in ARCHIVES}
    if len(lines) != len(expected) or set(lines) != expected:
        raise ValueError('Checksum manifest does not match the exact archive set')
    return hashes


def remote_digest(asset_id):
    # Pin the API object, not a mutable release tag/name lookup.
    data = subprocess.check_output(['gh', 'api',
        f'repos/{REPO}/releases/assets/{asset_id}',
        '-H', 'Accept: application/octet-stream', '-H', 'X-GitHub-Api-Version: 2022-11-28'])
    return hashlib.sha256(data).hexdigest()


def publish():
    sha, _ = context(os.environ, json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()))
    wanted, _ = version(Path(VERSION_FILE).read_text())
    if run('git', 'rev-parse', 'HEAD') != sha:
        raise ValueError('Checkout changed after testing')
    hashes = assets('dist', wanted)
    existing = tag_commit(wanted)
    subprocess.check_call(['git', 'fetch', '--tags', 'origin'])
    check_versions(wanted, run('git', 'tag', '--list').splitlines(), existing, sha)
    if existing is None:
        # Atomic create; another creator wins rather than being overwritten.
        api(f'repos/{REPO}/git/refs', 'POST', {'ref': f'refs/tags/{wanted}', 'sha': sha})
    if tag_commit(wanted) != sha:
        raise ValueError('Remote tag changed; abort')
    release = api(f'repos/{REPO}/releases/tags/{wanted}', missing_ok=True)
    if release is None:
        release = api(f'repos/{REPO}/releases', 'POST', {
            'tag_name': wanted, 'target_commitish': sha, 'name': f'Scharf {wanted}',
            'body': Path('release/notes.md').read_text(), 'draft': True, 'prerelease': False})
    if release['prerelease'] or release['tag_name'] != wanted:
        raise ValueError('Unexpected release metadata')
    uploaded = {}
    page = 1
    while True:
        batch = api(f'repos/{REPO}/releases/{release["id"]}/assets?per_page=100&page={page}')
        for asset in batch:
            name = asset['name']
            if name not in hashes or name in uploaded or asset['state'] != 'uploaded':
                raise ValueError('Unexpected, duplicate, or incomplete remote asset')
            digest = remote_digest(asset['id'])
            if digest != hashes[name]:
                raise ValueError(f'Remote asset mismatch: {name}; will not overwrite')
            uploaded[name] = asset['id']
        if len(batch) < 100:
            break
        page += 1
    if not release['draft']:
        if set(uploaded) != set(hashes):
            raise ValueError('Published release is incomplete; never modify it')
        print(f'{wanted} already published with identical assets; nothing to do')
        return
    for name in sorted(hashes.keys() - uploaded.keys()):
        # Deliberately omit --clobber. Interrupted uploads are safe to retry only
        # when existing bytes match the current build exactly.
        subprocess.check_call(['gh', 'release', 'upload', wanted, f'dist/{name}', '--repo', REPO])
    if tag_commit(wanted) != sha:
        raise ValueError('Remote tag changed before publish')
    final = api(f'repos/{REPO}/releases/{release["id"]}/assets?per_page=100')
    if len(final) != len(hashes) or {a['name'] for a in final if a['state'] == 'uploaded'} != set(hashes):
        raise ValueError('Release upload is incomplete')
    for asset in final:
        if remote_digest(asset['id']) != hashes[asset['name']]:
            raise ValueError('Final remote asset bytes do not match attested build')
    if tag_commit(wanted) != sha:
        raise ValueError('Remote tag changed during verification')
    api(f'repos/{REPO}/releases/{release["id"]}', 'PATCH', {'draft': False, 'make_latest': 'true'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['lint', 'prepare', 'assets', 'publish'])
    command = parser.parse_args().command
    if command == 'lint':
        intent()
    elif command == 'assets':
        assets('dist', version(Path(VERSION_FILE).read_text())[0])
    else:
        {'prepare': prepare, 'publish': publish}[command]()
