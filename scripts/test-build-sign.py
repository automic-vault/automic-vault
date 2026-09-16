#!/usr/bin/env python3
"""Exercise incremental signing with real Mach-O binaries and codesign."""
import json
import os
from pathlib import Path
import plistlib
import runpy
import shutil
import subprocess
import tempfile

HELPER = Path(__file__).with_name("build-sign.py").resolve()
with tempfile.TemporaryDirectory(prefix="av-sign-test-") as tmp:
    root = Path(tmp)
    source = root / "source"
    subprocess.run(["cc", "-x", "c", "-", "-o", str(source)], input="int main(void) { return 0; }", text=True, check=True)
    target = root / "av"
    cache = root / "cache"
    identity = os.environ.get("AV_TEST_SIGNING_IDENTITY", "-")
    args = ["--force", "--sign", identity, "--options", "runtime", "--identifier", "com.automicvault.sign-test"]
    if identity != "-":
        args.append("--timestamp")

    def sign(expected_reuse, flags=None, artifact=target):
        result = subprocess.run(["python3", str(HELPER), str(cache), *(flags or args), str(artifact)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert ("Reused signature:" in result.stdout) == expected_reuse, result.stdout + result.stderr
        subprocess.run(["codesign", "--verify", "--strict", str(artifact)], check=True)

    shutil.copy2(source, target)
    sign(False)
    signed = target.read_bytes()
    shutil.copy2(source, target)
    sign(True)
    assert target.read_bytes() == signed, "Unchanged build must preserve signature bytes"

    # A different identifier/options/entitlements must not reuse an old signature.
    shutil.copy2(source, target)
    changed_identifier = args.copy()
    changed_identifier[changed_identifier.index("--identifier") + 1] = "com.automicvault.changed"
    sign(False, changed_identifier)
    entitlements = root / "entitlements.plist"
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.network.client": True}))
    flags = [*args, "--entitlements", str(entitlements)]
    shutil.copy2(source, target)
    sign(False, flags)
    shutil.copy2(source, target)
    sign(True, flags)
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.network.client": False}))
    shutil.copy2(source, target)
    sign(False, flags)

    # Corrupted cache bytes must never be reused, even when inputs match.
    with (cache / "av/av").open("ab") as f:
        f.write(b"corruption")
    shutil.copy2(source, target)
    sign(False, flags)
    # Even a matching checksum cannot substitute for signature verification.
    cached = cache / "av/av"
    data = bytearray(cached.read_bytes())
    data[4096] ^= 1
    cached.write_bytes(data)
    state_file = cache / "av/state.json"
    state = json.loads(state_file.read_text())
    state["output"] = runpy.run_path(str(HELPER))["fingerprint"](cached)
    state_file.write_text(json.dumps(state))
    shutil.copy2(source, target)
    sign(False, flags)

    # Changing signing identity (or hardened-runtime flags) invalidates reuse.
    changed_flags = args.copy()
    changed_flags[changed_flags.index("--options") + 1] = "kill,runtime"
    shutil.copy2(source, target)
    sign(False, changed_flags)
    if identity != "-":
        changed_identity = args.copy()
        changed_identity[changed_identity.index("--sign") + 1] = "-"
        changed_identity.remove("--timestamp")
        shutil.copy2(source, target)
        sign(False, changed_identity)
    subprocess.run(["cc", "-x", "c", "-", "-o", str(source)], input="int main(void) { return 1; }", text=True, check=True)
    shutil.copy2(source, target)
    sign(False, flags)

    # Bundle signing includes resources, nested code and the provisioning profile.
    app = root / "Test.app"
    def bundle(resource):
        if app.exists():
            shutil.rmtree(app)
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Resources").mkdir()
        shutil.copy2(source, app / "Contents/MacOS/Test")
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "Test", "CFBundleIdentifier": "com.automicvault.sign-test",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1"}))
        (app / "Contents/Resources/data").write_text(resource)
    bundle("one")
    resource = app / "Contents/Resources/data"
    subprocess.run(["xattr", "-w", "com.apple.quarantine", "0081;65000000;test;", str(resource)], check=True)
    sign(False, artifact=app)
    bundle("one")
    subprocess.run(["xattr", "-w", "com.apple.quarantine", "0081;65000001;test;", str(resource)], check=True)
    sign(True, artifact=app)
    assert b"65000001" in subprocess.check_output(["xattr", "-p", "com.apple.quarantine", str(resource)])
    bundle("two")
    sign(False, artifact=app)
    bundle("two")
    (app / "Contents/embedded.provisionprofile").write_bytes(b"changed profile")
    sign(False, artifact=app)
    print("PASS: unchanged inputs reuse exact bytes; changed inputs and corrupted cache re-sign")
