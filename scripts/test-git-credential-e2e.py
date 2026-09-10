#!/usr/bin/env python3
"""Signed, live Vault/GitHub test. Creates and deletes one private test repository.

Requires the built app and av to be installed, /opt/av/git installed, and a
Vault-managed GitHub credential authorized to create/push/delete that repository.
Normal policy and Approval remain in force. Never reads or prints a raw token.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="create, exercise, and delete a private GitHub test repository")
    parser.add_argument("--av", default="/usr/local/bin/av")
    parser.add_argument("--gh", default="/opt/homebrew/bin/gh")
    parser.add_argument("--app", default="/Applications/Automic Vault.app/Contents/MacOS/AutomicVaultMenubar")
    options = parser.parse_args()
    if not options.run:
        parser.error("pass --run to perform the live remote test")
    git = "/opt/av/git/bin/git"
    gh = "/opt/av/git/bin/gh"
    secret_pattern = re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|Authorization: Basic )")

    def run(argv, *, cwd, data=None, env=None, ok=True):
        result = subprocess.run(argv, cwd=cwd, input=data, env=env, capture_output=True, timeout=180)
        # Failure output can be the evidence of a leak: never print it.
        assert not secret_pattern.search(result.stdout + result.stderr), "credential-shaped output detected (not displayed)"
        if ok and result.returncode:
            raise AssertionError(f"{Path(argv[0]).name} {argv[1]} failed (exit {result.returncode}; output withheld)")
        return result

    with tempfile.TemporaryDirectory(prefix="av-git-e2e-") as directory:
        root = Path(directory)
        clean = {"PATH": "/opt/av/git/bin:/usr/bin:/bin", "HOME": "/opt/av/git/empty",
                 "GH_CONFIG_DIR": "/opt/av/git/empty", "GIT_TERMINAL_PROMPT": "0"}
        request = b"protocol=https\nhost=github.com\npath=automic-vault/automic-vault.git\n\n"
        direct = run([gh, "auth", "git-credential", "get"], cwd=root, data=request, env=clean, ok=False)
        assert direct.returncode and direct.stdout == b"", "direct protected helper was not denied"
        print("PASS: direct signed provider receives no credential", flush=True)

        def api(endpoint, method="GET", body=None):
            argv = [options.gh, "api", endpoint, "--method", method]
            if body is not None:
                argv += ["--input", "-"]
            result = run(argv, cwd=root, data=None if body is None else json.dumps(body).encode())
            return json.loads(result.stdout) if result.stdout else None

        owner = api("user")["login"]
        name = "av-git-e2e-" + uuid.uuid4().hex[:16]
        repository = None
        try:
            created = api("user/repos", "POST", {"name": name, "private": True, "auto_init": True})
            repository = created["full_name"]
            assert repository == f"{owner}/{name}" and created["private"] is True
            print(f"Created private fixture: https://github.com/{repository}", flush=True)
            if created["default_branch"] != "main":
                commit = api(f"repos/{repository}/commits/{created['default_branch']}")["sha"]
                api(f"repos/{repository}/git/refs", "POST", {"ref": "refs/heads/main", "sha": commit})
                api(f"repos/{repository}", "PATCH", {"default_branch": "main"})
            url = f"https://github.com/{repository}.git"
            clone = root / "clone"
            run([options.av, "git", "clone", url, str(clone)], cwd=root)
            assert (clone / "README.md").is_file()
            print("PASS: authenticated clone", flush=True)

            # These controls must not enter the registered network Git's config.
            sink = root / "credential-store"
            helper = "/usr/bin/git credential-store --file=" + shlex.quote(str(sink))
            for key, value in [("credential.helper", helper), (f"http.{url}.sslVerify", "false"),
                               (f"http.{url}.proxy", "http://127.0.0.1:1")]:
                run([git, "config", key, value], cwd=clone)
            trace = root / "trace"
            hostile = dict(os.environ, GIT_TRACE_CURL=str(trace), GIT_TRACE_REDACT="0",
                           GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="credential.helper", GIT_CONFIG_VALUE_0=helper,
                           GIT_SSL_NO_VERIFY="true", GIT_EXEC_PATH=str(root), HTTPS_PROXY="http://127.0.0.1:1")
            run([options.av, "git", "fetch", url], cwd=clone, env=hostile)
            assert not sink.exists() and not trace.exists()
            print("PASS: authenticated fetch ignores hostile config/environment", flush=True)

            api(f"repos/{repository}/contents/e2e.txt", "PUT", {
                "message": "E2E remote update", "branch": "main",
                "content": base64.b64encode(b"remote update\n").decode(),
            })
            run([options.av, "git", "pull", url], cwd=clone)
            assert (clone / "e2e.txt").read_text() == "remote update\n"
            print("PASS: authenticated fast-forward pull", flush=True)

            (clone / "e2e.txt").write_text("local update\n")
            run([git, "-c", "user.name=AV E2E", "-c", "user.email=e2e@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-am", "E2E local update"], cwd=clone)
            run([options.av, "git", "push", url], cwd=clone)
            local = run([git, "rev-parse", "HEAD"], cwd=clone).stdout.decode().strip()
            assert api(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == local
            assert not sink.exists() and not trace.exists()
            print("PASS: authenticated non-force push; remote ref matches", flush=True)

            # After unregister, a signed provider beneath unrelated software has
            # no operation authority, even with a syntactically valid nonce.
            replay = run([gh, "auth", "git-credential", "get"], cwd=root, data=request,
                         env=dict(clean, AV_GIT_NONCE="a" * 64), ok=False)
            assert replay.returncode and replay.stdout == b""
            print("PASS: unrelated signed provider with a nonce is denied", flush=True)

            records = json.loads(run([options.app, "--self-check-git-records", url], cwd=root).stdout)
            operations = set()
            for record in records:
                words = shlex.split(record["command"])
                if record["decision"] == "Approved" and words[:2] == ["av", "git"]:
                    assert record["keys"] == ["GH_TOKEN_GITHUB_COM"]
                    assert record["callerPath"] == gh and record["target"] == gh
                    operations.add(words[2])
            assert operations == {"clone", "fetch", "pull", "push"}, "missing real authorization records"
            print("PASS: all four operations have persisted Vault authorization records", flush=True)
        finally:
            if repository:
                try:
                    api(f"repos/{repository}", "DELETE")
                    print("Deleted private test fixture", flush=True)
                except Exception:
                    print(f"Cleanup required: https://github.com/{repository}", flush=True)
                    raise
    print("RESULT: signed live integration checks passed; not a proof against every native-code defect")


if __name__ == "__main__":
    main()
