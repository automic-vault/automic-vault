#!/usr/bin/env python3
"""Signed, live Vault/GitHub test against a disposable private repository.

Requires the built app and av to be installed, /opt/av/git installed, and a
Vault-managed GitHub credential authorized to push the selected repository.
Without --repository, creates a fixture; --keep-repository retains it for reuse.
Normal policy and Approval remain in force. Never reads or prints a raw token.
"""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="create, exercise, and delete a private GitHub test repository")
    parser.add_argument("--repository", help="existing disposable private OWNER/NAME; never deleted")
    parser.add_argument("--keep-repository", action="store_true", help="retain a newly created fixture for reuse")
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
        direct = run([gh, "auth", "git-credential", "get"], cwd="/opt/av/git", data=request, env=clean, ok=False)
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
            if options.repository:
                assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", options.repository), "invalid fixture repository"
                created = api(f"repos/{options.repository}")
            else:
                created = api("user/repos", "POST", {"name": name, "private": True, "auto_init": True})
            repository = created["full_name"]
            assert repository == (options.repository or f"{owner}/{name}") and created["private"] is True
            print(f"Private fixture: https://github.com/{repository}", flush=True)
            if created["default_branch"] != "main":
                commit = api(f"repos/{repository}/commits/{created['default_branch']}")["sha"]
                api(f"repos/{repository}/git/refs", "POST", {"ref": "refs/heads/main", "sha": commit})
                api(f"repos/{repository}", "PATCH", {"default_branch": "main"})
            url = f"https://github.com/{repository}.git"
            baseline = json.loads(run([options.app, "--self-check-git-records", url], cwd=root, ok=False).stdout)
            previous_records = {record["id"] for record in baseline}
            unregistered_env = dict(clean, GIT_DIR="/opt/av/git/repository", GIT_EXEC_PATH="/opt/av/git/bin",
                                    GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", AV_GIT_NONCE="a" * 64)
            unregistered = run([git, "-c", "credential.helper=!exec /opt/av/git/bin/gh auth git-credential",
                                "ls-remote", "--", url], cwd="/opt/av/git", env=unregistered_env, ok=False)
            assert unregistered.returncode and unregistered.stdout == b"", "unregistered signed Git chain gained authority"
            print("PASS: signed Git/HTTPS/gh chain without registration is denied", flush=True)
            clone = root / "clone"
            run([options.av, "git", "clone", url, str(clone)], cwd=root)
            assert (clone / ".git/HEAD").is_file()
            print("PASS: authenticated clone", flush=True)

            # Copy the actual nonce and invocation while the registered av is
            # stopped, so a sibling attempts reuse before unregister can occur.
            source = Path(__file__).resolve().parents[1] / "src/menu-helper/Sources/CProcessInfo"
            observer = root / "observer.dylib"
            run(["/usr/bin/clang", "-dynamiclib", "-I", str(source / "include"),
                 str(source / "CProcessInfo.c"), "-lbsm", "-o", str(observer)], cwd=root)
            process_info = ctypes.CDLL(str(observer))
            process_info.av_process_environment_value.restype = ctypes.c_bool
            process_info.av_process_arguments_data.restype = ctypes.c_ssize_t
            proc = ctypes.CDLL("/usr/lib/libproc.dylib")
            active = subprocess.Popen([options.av, "git", "fetch", url], cwd=clone,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stopped = False
            replay_args = replay_env = None
            try:
                deadline = time.monotonic() + 30
                while active.poll() is None and time.monotonic() < deadline:
                    children = (ctypes.c_int * 256)()
                    proc.proc_listchildpids(active.pid, children, ctypes.sizeof(children))
                    for child in children:
                        if child <= 0:
                            continue
                        nonce = ctypes.create_string_buffer(65)
                        if not process_info.av_process_environment_value(child, b"AV_GIT_NONCE", nonce, len(nonce)):
                            continue
                        assert re.fullmatch(rb"[0-9a-f]{64}", nonce.value)
                        arguments = ctypes.create_string_buffer(65536)
                        count = process_info.av_process_arguments_data(child, arguments, len(arguments))
                        if count <= 0:
                            continue
                        candidate = [os.fsdecode(arg) for arg in arguments.raw[:count].split(b"\0")[:-1]]
                        if not candidate or candidate[0] != git:
                            continue
                        os.kill(active.pid, signal.SIGSTOP)
                        _, status = os.waitpid(active.pid, os.WUNTRACED)
                        assert os.WIFSTOPPED(status), "registered av exited before the replay test"
                        stopped = True
                        replay_args = candidate
                        replay_env = dict(clean, AV_GIT_NONCE=nonce.value.decode(),
                                          XDG_CONFIG_HOME="/opt/av/git/empty", GIT_CONFIG_NOSYSTEM="1",
                                          GIT_CONFIG_GLOBAL="/dev/null", GIT_EXEC_PATH="/opt/av/git/bin",
                                          GIT_DIR="/opt/av/git/repository", GIT_PAGER="cat", LC_ALL="C",
                                          GIT_OBJECT_DIRECTORY=str((clone / ".git/objects").resolve()))
                        break
                    if stopped:
                        break
                    time.sleep(0.001)
                assert stopped, "did not capture an active registration"
                replay = run(replay_args, cwd="/opt/av/git", env=replay_env, ok=False)
                assert replay.returncode and replay.stdout == b"", "sibling reused an active registration"
            finally:
                if stopped:
                    os.kill(active.pid, signal.SIGCONT)
                try:
                    out, err = active.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    active.kill()
                    active.communicate()
                    raise
            assert active.returncode == 0 and not secret_pattern.search(out + err)
            replay = run(replay_args, cwd="/opt/av/git", env=replay_env, ok=False)
            assert replay.returncode and replay.stdout == b"", "sibling reused an expired registration"
            print("PASS: copied live and expired nonces cannot authorize a sibling signed chain", flush=True)

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

            fixture_file = "av-e2e-" + uuid.uuid4().hex + ".txt"
            api(f"repos/{repository}/contents/{fixture_file}", "PUT", {
                "message": "E2E remote update", "branch": "main",
                "content": base64.b64encode(b"remote update\n").decode(),
            })
            run([options.av, "git", "pull", url], cwd=clone)
            assert (clone / fixture_file).read_text() == "remote update\n"
            print("PASS: authenticated fast-forward pull", flush=True)

            (clone / fixture_file).write_text("local update\n")
            run([git, "-c", "user.name=AV E2E", "-c", "user.email=e2e@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-am", "E2E local update"], cwd=clone)
            run([options.av, "git", "push", url], cwd=clone)
            local = run([git, "rev-parse", "HEAD"], cwd=clone).stdout.decode().strip()
            assert api(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == local
            assert not sink.exists() and not trace.exists()
            print("PASS: authenticated non-force push; remote ref matches", flush=True)

            # After unregister, a signed provider beneath unrelated software has
            # no operation authority, even with a syntactically valid nonce.
            replay = run([gh, "auth", "git-credential", "get"], cwd="/opt/av/git", data=request,
                         env=dict(clean, AV_GIT_NONCE="a" * 64), ok=False)
            assert replay.returncode and replay.stdout == b""
            print("PASS: unrelated signed provider with a nonce is denied", flush=True)

            records = json.loads(run([options.app, "--self-check-git-records", url], cwd=root).stdout)
            operations = set()
            for record in records:
                if record["id"] in previous_records:
                    continue
                words = shlex.split(record["command"].replace("\\\n", ""))
                if record["decision"] == "Approved" and words[:2] == ["av", "git"]:
                    assert record["keys"] == ["GH_TOKEN_GITHUB_COM"]
                    assert record["callerPath"] == gh and record["target"] == gh
                    operations.add(words[2])
            assert operations == {"clone", "fetch", "pull", "push"}, "missing real authorization records"
            print("PASS: all four operations have persisted Vault authorization records", flush=True)
        finally:
            if repository and not options.repository and not options.keep_repository:
                try:
                    api(f"repos/{repository}", "DELETE")
                    print("Deleted private test fixture", flush=True)
                except Exception:
                    print(f"Cleanup required: https://github.com/{repository}", flush=True)
                    raise
            elif repository:
                print(f"Retained private fixture: https://github.com/{repository}", flush=True)
    print("RESULT: signed live integration checks passed; not a proof against every native-code defect")


if __name__ == "__main__":
    main()
