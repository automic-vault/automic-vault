#!/usr/bin/env python3
"""Reuse a verified signature only when the unsigned input and signing inputs match."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def fingerprint(path, quarantine=None):
    digest = hashlib.sha256()
    paths = [path, *sorted(path.rglob("*"))] if path.is_dir() else [path]
    for item in paths:
        mode = item.lstat().st_mode
        if item.is_symlink():
            content = os.readlink(item).encode()
        elif stat.S_ISREG(mode):
            content = item.read_bytes()
        elif stat.S_ISDIR(mode):
            content = b""
        else:
            raise ValueError(f"Unsupported signing input: {item}")
        record = [str(item.relative_to(path)), mode, hashlib.sha256(content).hexdigest()]
        # Quarantine records copy time, not signed content. ditto still preserves it.
        attrs = subprocess.check_output(["/usr/bin/xattr", "-s", str(item)], text=True).splitlines()
        if quarantine is not None and "com.apple.quarantine" in attrs:
            quarantine[str(item.relative_to(path))] = subprocess.check_output(
                ["/usr/bin/xattr", "-psx", "com.apple.quarantine", str(item)]).decode()
        record.append([(key, subprocess.check_output(["/usr/bin/xattr", "-psx", key, str(item)]).decode())
                       for key in sorted(attrs) if key != "com.apple.quarantine"])
        digest.update(json.dumps(record).encode() + b"\n")
    return digest.hexdigest()


def sign(cache_root, args, target):
    identity = args[args.index("--sign") + 1]
    if identity != "-" and not re.fullmatch(r"[A-Fa-f0-9]{40}", identity):
        raise ValueError("Signing requires a certificate fingerprint, not a mutable name")
    verify = ["/usr/bin/codesign", "--verify", "--strict"]
    if identity != "-":
        verify += ["-R", f'=certificate leaf = H"{identity}"']
    quarantine = {}
    inputs = [fingerprint(target, quarantine), args, fingerprint(Path(__file__)),
              fingerprint(Path("/usr/bin/codesign"))]
    if "--entitlements" in args:
        inputs.append(fingerprint(Path(args[args.index("--entitlements") + 1])))
    input_hash = hashlib.sha256(json.dumps(inputs).encode()).hexdigest()
    cache = cache_root / target.name
    artifact = cache / target.name
    try:
        state = json.loads((cache / "state.json").read_text())
        reusable = (state["input"] == input_hash and state["output"] == fingerprint(artifact)
                    and subprocess.run([*verify, str(artifact)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    except (OSError, ValueError, KeyError):
        reusable = False
    if reusable:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        subprocess.run(["/usr/bin/ditto", str(artifact), str(target)], check=True)
        # Reusing signed bytes must not discard the current input's quarantine.
        for name, value in quarantine.items():
            item = target if name == "." else target / name
            subprocess.run(["/usr/bin/xattr", "-wsx", "com.apple.quarantine", value, str(item)], check=True)
        print(f"Reused signature: {target.name}", flush=True)
        return

    subprocess.run(["/usr/bin/codesign", *args, str(target)], check=True)
    subprocess.run([*verify, str(target)], check=True)
    cache_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache_root) as tmp:
        entry = Path(tmp) / "entry"
        entry.mkdir()
        subprocess.run(["/usr/bin/ditto", str(target), str(entry / target.name)], check=True)
        (entry / "state.json").write_text(json.dumps({"input": input_hash, "output": fingerprint(entry / target.name)}))
        if cache.exists():
            shutil.rmtree(cache)
        entry.rename(cache)


if __name__ == "__main__":
    if sys.argv[1] == "--fingerprint":
        print(hashlib.sha256(json.dumps([fingerprint(Path(p)) for p in sys.argv[2:]]).encode()).hexdigest())
    else:
        sign(Path(sys.argv[1]), sys.argv[2:-1], Path(sys.argv[-1]))
