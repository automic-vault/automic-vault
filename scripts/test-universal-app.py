#!/usr/bin/env python3
"""Reject missing slices and invalid signatures in a Universal 2 app."""
import pathlib
import plistlib
import subprocess
import tempfile

verify = pathlib.Path(__file__).with_name('verify-universal-app.sh').resolve()


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    source = root / 'main.c'
    source.write_text('int main(void) { return 0; }\n')
    thin = root / 'thin'
    fat = root / 'fat'
    run('xcrun', 'clang', '-arch', 'arm64', str(source), '-o', str(thin))
    run('xcrun', 'clang', '-arch', 'arm64', '-arch', 'x86_64', str(source), '-o', str(fat))
    app = root / 'Test.app'
    contents = app / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    (contents / 'Resources').mkdir()
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleExecutable': 'AutomicVaultMenubar',
        'CFBundleIdentifier': 'com.automicvault.universal-test',
        'CFBundlePackageType': 'APPL',
    }))
    executables = [contents / 'MacOS' / name for name in
                   ['AutomicVaultMenubar', 'av', 'av-gpg', 'av-brew-stub', 'av-proxy-helper']]
    executables += [contents / 'Resources' / name for name in
                    ['AutomicVaultLauncher', 'AutomicVaultVarlockPlugin']]
    for path in executables:
        path.write_bytes(fat.read_bytes())
        path.chmod(0o755)
        run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(path))
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(app))
    run(str(verify), str(app))
    helper = executables[-1]
    helper.write_bytes(thin.read_bytes())
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(helper))
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(app))
    assert subprocess.run([str(verify), str(app)], capture_output=True).returncode != 0
    helper.write_bytes(fat.read_bytes())
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(helper))
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(app))
    run('codesign', '--remove-signature', str(helper))
    assert subprocess.run([str(verify), str(app)], capture_output=True).returncode != 0
print('Universal app checks passed')
