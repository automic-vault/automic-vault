#!/usr/bin/env python3
"""Adversarial Git credential experiment for issue #319; never uses real Secrets.

Run on macOS: python3 scripts/check-git-credential-confinement.py
Add --remote-helper to probe configuration routing and raw-helper session attacks.
Uses Apple Git, a dummy provider, and two ephemeral loopback TLS identities.
PASS means an expected observation held, including expected counterexamples.
This is not a production wrapper or a test of AV's XPC/Launcher boundary.
"""
import base64
import hashlib
import http.server
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit


def run(argv, *, cwd, env, data=None, ok=True):
    result = subprocess.run(argv, cwd=cwd, env=env, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if ok and result.returncode:
        raise AssertionError(f"command failed: {argv[0]} {argv[1:3]}: "
                             + result.stderr.decode(errors="replace").replace(TOKEN, "<DUMMY>"))
    return result


TOKEN = "AV319_DUMMY_NOT_A_CREDENTIAL"
AUTH = "Basic " + base64.b64encode(f"probe:{TOKEN}".encode()).decode()


def remote_helper_probe(git, exec_path, root, env, url, common, pin, server, Server, Backend, calls):
    """Exercise the actual Apple HTTPS helper, not a mock authorization engine."""
    def local(*args):
        return run([str(git), *args], cwd=root, env=env).stdout.strip()

    protected = root / "fixed.git"
    local("init", "--bare", "--template=", str(protected))
    transport_env = dict(env, HOME=str(root / "empty"), XDG_CONFIG_HOME=str(root / "empty"),
                         GIT_DIR=str(protected), GIT_OBJECT_DIRECTORY=str(root / "seed/.git/objects"),
                         GIT_EXEC_PATH=str(exec_path))
    (root / "empty").mkdir()
    transport = [str(git), *common, "-c", f"http.pinnedPubkey={pin}",
                 "remote-https", url, url]

    def exchange(commands):
        return run(transport, cwd=root, env=transport_env, data=commands.encode())

    def clean(result):
        assert TOKEN.encode() not in result.stdout + result.stderr
        assert AUTH.encode() not in result.stdout + result.stderr

    # The routing helper is deliberately mutable and has no Vault authority.
    # Its sole job is to relay bytes to the actual, isolated Apple transport.
    helper = root / "git-remote-avprobe"
    helper.write_text(f"#!{sys.executable}\nimport os, sys\n"
                      f"command = {transport!r}\n"
                      f"assert sys.argv[2] == {url!r}\n"
                      f"os.execve(command[0], command, {transport_env!r})\n")
    helper.chmod(0o700)
    routing = dict(env, PATH=f"{root}:{env['PATH']}")
    client = root / "client"
    local("init", "--template=", str(client))
    local("-C", str(client), "remote", "add", "origin", url)
    prefix = url.rsplit("/", 1)[0] + "/"
    local("-C", str(client), "config", f"url.avprobe::{prefix}.insteadOf", prefix)
    leak = root / "outer-credential-store"
    trace = root / "outer-curl-trace"
    local("-C", str(client), "config", "credential.helper", f"store --file={leak}")
    local("-C", str(client), "config", f"http.{url}.sslVerify", "false")
    local("-C", str(client), "config", f"http.{url}.proxy", "http://127.0.0.1:1")
    result = run([str(git), "ls-remote", "origin"], cwd=client,
                 env=dict(routing, GIT_TRACE_CURL=str(trace), GIT_TRACE_REDACT="0"))
    clean(result)
    assert b"refs/heads/main" in result.stdout and server.authenticated > 0
    assert local("-C", str(client), "config", "--get", "remote.origin.url").decode() == url
    assert not leak.exists() and not trace.exists()
    print("PASS: ordinary git ls-remote origin authenticates through configuration-selected isolated transport")
    print("PASS: unchanged origin; outer helper/TLS/proxy configuration and tracing receive no dummy credential")

    # A longer rewrite can bypass our helper. This must remove protected
    # credential access, never grant it. There are no ambient credentials here.
    before = calls.read_text().count("get\n")
    result = run([str(git), "-c", f"url.https://127.0.0.1:1/.insteadOf={url}",
                  "ls-remote", url], cwd=client, env=routing, ok=False)
    assert result.returncode and calls.read_text().count("get\n") == before
    print("PASS: bypassing URL routing cannot reach this dummy credential provider")

    # Simulate trusting an initial read label and then forwarding all later
    # stdin to the same credential-bearing transport. No new provider lookup
    # is needed for an actual remote write.
    oid = local("-C", str(root / "seed"), "rev-parse", "HEAD").decode()
    before = calls.read_text().count("get\n")
    result = exchange(f"list\npush {oid}:refs/heads/read-session-write\n\n\n")
    clean(result)
    assert local("--git-dir=" + str(root / "remote.git"), "rev-parse",
                 "refs/heads/read-session-write").decode() == oid
    assert calls.read_text().count("get\n") == before + 1
    print("COUNTEREXAMPLE: a read-authenticated raw-helper session creates a remote branch with one credential lookup")

    # Broad helper verbs must be rejected or separately bounded by an adapter. The native
    # helper accepts `get URL PATH`, which can target a different TLS origin.
    sink = Server(("127.0.0.1", 0), Backend)
    worker = threading.Thread(target=sink.serve_forever, daemon=True)
    worker.start()
    try:
        other = f"https://localhost:{sink.server_port}/remote.git/info/refs?service=git-upload-pack"
        before = calls.read_text().count("get\n")
        result = exchange(f"list\nget {other} {root / 'download'}\n\n")
        clean(result)
        assert sink.authenticated > 0
        assert calls.read_text().count("get\n") == before + 1
        print("COUNTEREXAMPLE: raw-helper get sends the cached dummy credential to another TLS origin")
    finally:
        sink.shutdown()
        sink.server_close()
        worker.join(timeout=5)
    print("RESULT: configuration routing works; an unrestricted remote-HTTPS relay violates operation and destination bounds")
    print("No real Secrets or Vault authorization used; this is not a bypass of the existing registered av git route")


def main():
    if sys.platform != "darwin":
        raise SystemExit("This experiment requires macOS and Apple Git")
    git = Path(subprocess.check_output(["/usr/bin/xcrun", "--find", "git"], text=True).strip())
    exec_path = Path(subprocess.check_output([str(git), "--exec-path"], text=True).strip())
    for binary, identifier in [(git, "com.apple.git"),
                               (exec_path / "git-remote-https", "com.apple.git-remote-http"),
                               (exec_path / "git-credential-store", "com.apple.git")]:
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                        f'-R=anchor apple and identifier "{identifier}"', str(binary)], check=True)
    print(subprocess.check_output([str(git), "--version"], text=True).strip())
    print("PASS: on-disk Apple identities for Git, HTTPS transport, and storage helper")

    with tempfile.TemporaryDirectory(prefix="av-git-confinement-") as temporary:
        root = Path(temporary)
        env = {"PATH": f"{exec_path}:/usr/bin:/bin", "HOME": str(root),
               "XDG_CONFIG_HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
               "GIT_AUTHOR_NAME": "Probe", "GIT_AUTHOR_EMAIL": "probe@example.invalid",
               "GIT_COMMITTER_NAME": "Probe", "GIT_COMMITTER_EMAIL": "probe@example.invalid"}
        def gitrun(*args, cwd=root, **kwargs):
            return run([str(git), *args], cwd=cwd, env=env, **kwargs)

        def certificate(name):
            cert, key, config = [root / (name + suffix) for suffix in (".pem", ".key", ".cnf")]
            config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
                              "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n"
                              "basicConstraints=critical,CA:TRUE\n")
            run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-config", str(config), "-out", str(cert), "-keyout", str(key)],
                cwd=root, env=env)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            return cert, context

        cert, trusted_context = certificate("trusted")
        untrusted_cert, untrusted_context = certificate("untrusted")
        public_key = run(["/usr/bin/openssl", "x509", "-pubkey", "-noout", "-in", str(cert)],
                         cwd=root, env=env).stdout
        der = run(["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
                  cwd=root, env=env, data=public_key).stdout
        pin = "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode()
        gitrun("init", "--bare", "--initial-branch=main", "remote.git")
        gitrun("--git-dir=" + str(root / "remote.git"), "config", "http.receivepack", "true")
        gitrun("init", "--initial-branch=main", "seed")
        seed = root / "seed"
        (seed / "file").write_text("initial\n")
        gitrun("add", "file", cwd=seed)
        gitrun("commit", "-m", "initial", cwd=seed)
        gitrun("push", str(root / "remote.git"), "HEAD:refs/heads/main", cwd=seed)

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            context = trusted_context
            requests = 0
            authenticated = 0
            rejected_auth = 0
            redirect = None
            def get_request(self):
                connection, address = super().get_request()
                try:
                    return self.context.wrap_socket(connection, server_side=True), address
                except Exception:
                    connection.close()
                    raise

        class Backend(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.serve()
            def do_POST(self):
                self.serve()
            def serve(self):
                self.server.requests += 1
                authorization = self.headers.get("Authorization")
                if authorization != AUTH:
                    if authorization:
                        self.server.rejected_auth += 1
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="probe"')
                    self.end_headers()
                    return
                self.server.authenticated += 1
                if self.server.redirect:
                    self.send_response(302)
                    self.send_header("Location", self.server.redirect)
                    self.end_headers()
                    return
                path = urlsplit(self.path)
                if path.path not in ("/remote.git/info/refs", "/remote.git/git-upload-pack",
                                     "/remote.git/git-receive-pack"):
                    self.send_error(404)
                    return
                backend_env = dict(env, GIT_PROJECT_ROOT=str(root), GIT_HTTP_EXPORT_ALL="1",
                                   PATH_INFO=path.path, QUERY_STRING=path.query,
                                   REQUEST_METHOD=self.command, REMOTE_USER="probe",
                                   CONTENT_TYPE=self.headers.get("Content-Type", ""),
                                   CONTENT_LENGTH=self.headers.get("Content-Length", "0"),
                                   GIT_PROTOCOL=self.headers.get("Git-Protocol", ""))
                data = self.rfile.read(int(backend_env["CONTENT_LENGTH"]))
                result = run([str(exec_path / "git-http-backend")], cwd=root,
                             env=backend_env, data=data)
                headers, body = result.stdout.split(b"\r\n\r\n", 1)
                fields = [line.decode().split(": ", 1) for line in headers.split(b"\r\n")]
                status = next((int(v.split()[0]) for k, v in fields if k == "Status"), 200)
                self.send_response(status)
                for key, value in fields:
                    if key != "Status":
                        self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        server = Server(("127.0.0.1", 0), Backend)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"https://localhost:{server.server_port}/remote.git"
        calls = root / "provider-calls"
        provider = root / "dummy-provider"
        # Test double only: its source is mutable, it has no signing/XPC authority,
        # and its literal password is deliberately public. It models gh's stdout.
        provider.write_text(f"#!{sys.executable}\nimport pathlib, sys\n"
                            "if sys.argv[1:] != ['get']: sys.exit(0)\n"
                            "fields = dict(line.rstrip('\\n').split('=', 1) for line in sys.stdin if '=' in line)\n"
                            f"if fields.get('protocol') != 'https' or fields.get('host') != 'localhost:{server.server_port}' or fields.get('path') not in (None, 'remote.git'): sys.exit(1)\n"
                            f"with pathlib.Path({str(calls)!r}).open('a') as f: f.write('get\\n')\n"
                            f"print('username=probe\\npassword={TOKEN}\\n')\n")
        provider.chmod(0o700)
        helper = shlex.quote(str(provider))
        common = ["-c", "credential.helper=", "-c", "credential.helper=" + helper,
                  "-c", "core.hooksPath=/dev/null", "-c", "http.sslVerify=true",
                  "-c", "http.sslCAInfo=" + str(cert), "-c", "http.followRedirects=false",
                  "-c", "http.proxy=", "-c", "credential.useHttpPath=true",
                  "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]

        def confined(operation, repo=None, *, exact_tls=False, pinned_transport=False, ok=True):
            if operation not in ("clone", "fetch", "pull", "push"):
                raise ValueError("outside the candidate's positive operation catalog")
            args = list(common)
            if exact_tls or pinned_transport:
                scope = url + "/" if pinned_transport else url
                args += ["-c", f"http.{scope}.sslVerify=true", "-c", f"http.{scope}.sslCAInfo={cert}"]
            if pinned_transport:
                args += ["-c", f"http.{scope}.pinnedPubkey={pin}",
                         "-c", f"http.{scope}.followRedirects=false",
                         "-c", f"http.{scope}.proxy="]
            if operation == "clone":
                args += ["clone", "--template=", "--no-recurse-submodules", "--", url, str(repo)]
            elif operation == "fetch":
                args += ["fetch", "--no-recurse-submodules", "--", url, "refs/heads/main"]
            elif operation == "pull":
                args += ["pull", "--ff-only", "--no-recurse-submodules", "--", url, "refs/heads/main"]
            else:
                args += ["push", "--no-verify", "--", url, "HEAD:refs/heads/main"]
            # Model a native launcher's environment allowlist. This Python
            # function is a test candidate, not a protected launcher.
            return run([str(git), *args], cwd=root if operation == "clone" else repo,
                       env=dict(env), ok=ok)

        def check_clean_output(result):
            for value in (TOKEN.encode(), AUTH.encode()):
                assert value not in result.stdout + result.stderr, "credential appeared in output"

        try:
            if sys.argv[1:] == ["--remote-helper"]:
                remote_helper_probe(git, exec_path, root, env, url, common, pin,
                                    server, Server, Backend, calls)
                return
            clone = root / "clone"
            for operation in ("clone", "fetch"):
                before = server.authenticated
                result = confined(operation, clone)
                assert server.authenticated > before, "success without authenticating is not a valid test"
                check_clean_output(result)
            (seed / "file").write_text("remote update\n")
            gitrun("commit", "-am", "remote update", cwd=seed)
            gitrun("push", str(root / "remote.git"), "HEAD:refs/heads/main", cwd=seed)
            check_clean_output(confined("pull", clone))
            assert (clone / "file").read_text() == "remote update\n"
            (clone / "file").write_text("local update\n")
            gitrun("commit", "-am", "local update", cwd=clone)
            check_clean_output(confined("push", clone))
            assert gitrun("rev-parse", "HEAD", cwd=clone).stdout == gitrun(
                "--git-dir=" + str(root / "remote.git"), "rev-parse", "refs/heads/main").stdout
            print("PASS: authenticated clone/fetch/pull/push, checked file/ref changes and clean output")

            leak = root / "stored"
            store = shlex.quote(str(exec_path / "git-credential-store")) + " --file=" + shlex.quote(str(leak))
            gitrun("config", "--add", "credential.helper", helper, cwd=clone)
            gitrun("config", "--add", "credential.helper", store, cwd=clone)
            gitrun("-c", "http.sslCAInfo=" + str(cert), "ls-remote", url, cwd=clone)
            assert TOKEN in leak.read_text(), "negative control did not expose dummy credential"
            leak.unlink()
            check_clean_output(confined("fetch", clone))
            assert not leak.exists(), "fixed helper list did not block storage"
            print("PASS: storage attack reproduces without reset; candidate blocks it")

            trace = root / "trace"
            hostile = {
                "GIT_TRACE_CURL": str(trace), "GIT_TRACE_REDACT": "0",
                "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper",
                "GIT_CONFIG_VALUE_0": store, "GIT_SSL_NO_VERIFY": "true",
                "GIT_EXEC_PATH": str(root), "HTTPS_PROXY": "http://127.0.0.1:1"}
            previous = dict(os.environ)
            try:
                os.environ.update(hostile)
                check_clean_output(confined("fetch", clone))
            finally:
                os.environ.clear()
                os.environ.update(previous)
            assert not trace.exists() and not leak.exists()
            print("PASS: candidate does not forward hostile ambient environment")
            for operation in ("credential", "ls-remote", "-c", "unknown"):
                try:
                    confined(operation, clone)
                except ValueError:
                    continue
                raise AssertionError("unsupported operation reached Git")
            print("PASS: candidate rejects commands outside its four fixed operation forms")

            server.context = untrusted_context
            before = server.authenticated
            result = confined("fetch", clone, ok=False)
            assert result.returncode and server.authenticated == before
            print("PASS: untrusted TLS certificate blocks credentials with clean TLS configuration")

            gitrun("config", f"http.{url}.sslVerify", "false", cwd=clone)
            before = server.authenticated
            result = confined("fetch", clone)
            assert server.authenticated > before
            print("COUNTEREXAMPLE: URL-scoped sslVerify=false overrides command-line http.sslVerify=true; untrusted server receives dummy credential")

            before = server.authenticated
            result = confined("fetch", clone, exact_tls=True, ok=False)
            assert result.returncode and server.authenticated == before
            print("PASS: exact-URL TLS override blocks that specific counterexample")

            gitrun("config", f"http.{url}/.sslVerify", "false", cwd=clone)
            before = server.authenticated
            result = confined("fetch", clone, exact_tls=True, ok=False)
            assert result.returncode and server.authenticated == before
            print("PASS: trailing-slash spelling does not bypass the exact-URL TLS override")
            before = server.authenticated
            result = confined("fetch", clone, pinned_transport=True, ok=False)
            assert result.returncode and server.authenticated == before
            print("PASS: transport-normalized URL scope also rejects the untrusted certificate")
            gitrun("config", "--unset", f"http.{url}/.sslVerify", cwd=clone)

            ca_directory = root / "attacker-ca"
            ca_directory.mkdir()
            cert_hash = run(["/usr/bin/openssl", "x509", "-hash", "-noout", "-in", str(untrusted_cert)],
                            cwd=root, env=env).stdout.decode().strip()
            (ca_directory / (cert_hash + ".0")).symlink_to(untrusted_cert)
            gitrun("config", f"http.{url}/.sslCAPath", str(ca_directory), cwd=clone)
            before = server.authenticated
            result = confined("fetch", clone, pinned_transport=True, ok=False)
            assert result.returncode and server.authenticated == before
            print("PASS: additional CA-directory configuration does not bypass pinned transport")
            gitrun("config", "--unset", f"http.{url}/.sslCAPath", cwd=clone)

            # Deterministic schedule for a same-user race, not a probabilistic
            # stress test: another process writes after inspection, before use.
            gitrun("config", "--unset", f"http.{url}.sslVerify", cwd=clone)
            config = clone / ".git/config"
            checked = config.read_bytes()
            assert b"sslVerify" not in checked
            run([sys.executable, "-c", "import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                 "p.write_text(p.read_text()+sys.argv[2])", str(config),
                 f'\n[http "{url}"]\n sslVerify = false\n'], cwd=root, env=env)
            assert config.read_bytes() != checked and root.stat().st_mode & 0o777 == 0o700
            before = server.authenticated
            confined("fetch", clone)
            assert server.authenticated > before
            print("COUNTEREXAMPLE: same-user config replacement after inspection succeeds inside a mode-0700 temporary directory")

            # CA files owned by the user can also change. This is a fixture for
            # a mutable trust input, not a claim about the system trust store.
            original_certificate = cert.read_bytes()
            cert.write_bytes(untrusted_cert.read_bytes())
            before = server.authenticated
            confined("fetch", clone, exact_tls=True)
            assert server.authenticated > before
            print("COUNTEREXAMPLE: exact-URL TLS verification still trusts a substituted user-owned CA file")
            before = server.authenticated
            result = confined("fetch", clone, pinned_transport=True, ok=False)
            assert result.returncode and server.authenticated == before
            assert b"public key" in result.stderr.lower(), "expected a public-key pin rejection"
            print("PASS: in-argument server public-key pin rejects the substituted TLS identity")
            cert.write_bytes(original_certificate)
            server.context = trusted_context

            pinned = root / "pinned-clone"
            check_clean_output(confined("clone", pinned, pinned_transport=True))
            gitrun("config", "--add", f"credential.{url}.helper", store, cwd=pinned)
            gitrun("config", f"http.{url}.sslVerify", "false", cwd=pinned)
            gitrun("config", f"http.{url}.pinnedPubkey", "sha256//" + "A" * 44, cwd=pinned)
            check_clean_output(confined("fetch", pinned, pinned_transport=True))
            # Bring the local seed up to the previous authenticated push first.
            gitrun("fetch", str(root / "remote.git"), "main", cwd=seed)
            gitrun("reset", "--hard", "FETCH_HEAD", cwd=seed)
            (seed / "file").write_text("pinned remote update\n")
            gitrun("commit", "-am", "pinned remote update", cwd=seed)
            gitrun("push", str(root / "remote.git"), "HEAD:refs/heads/main", cwd=seed)
            check_clean_output(confined("pull", pinned, pinned_transport=True))
            assert (pinned / "file").read_text() == "pinned remote update\n"
            (pinned / "file").write_text("pinned local update\n")
            gitrun("commit", "-am", "pinned local update", cwd=pinned)
            check_clean_output(confined("push", pinned, pinned_transport=True))
            assert gitrun("rev-parse", "HEAD", cwd=pinned).stdout == gitrun(
                "--git-dir=" + str(root / "remote.git"), "rev-parse", "refs/heads/main").stdout
            assert not leak.exists()
            print("PASS: pinned candidate completes clone/fetch/pull/push with hostile scoped helper/TLS settings")

            sink = Server(("127.0.0.1", 0), Backend)
            sink_worker = threading.Thread(target=sink.serve_forever, daemon=True)
            sink_worker.start()
            try:
                server.redirect = f"https://localhost:{sink.server_port}/remote.git/info/refs?service=git-upload-pack"
                gitrun("config", f"http.{url}.followRedirects", "true", cwd=pinned)
                result = confined("fetch", pinned, pinned_transport=True, ok=False)
                assert result.returncode and sink.requests == 0
                check_clean_output(result)
                print("PASS: scoped redirect setting cannot make pinned candidate contact another origin")
                server.redirect = None
                # Remote rewriting happens before the protected helper. A scope
                # mismatch must deny disclosure even if the destination has a
                # valid certificate. The dummy provider checks the exact port.
                gitrun("config", f"url.https://localhost:{sink.server_port}/.insteadOf",
                       f"https://localhost:{server.server_port}/", cwd=pinned)
                result = confined("fetch", pinned, pinned_transport=True, ok=False)
                assert result.returncode and sink.requests > 0 and sink.authenticated == 0
                check_clean_output(result)
                print("PASS: rewritten origin receives no credential; authentication fails")
            finally:
                server.redirect = None
                sink.shutdown()
                sink.server_close()
                sink_worker.join(timeout=5)
            print("RESULT: tested transport controls hold; production identity/registration boundary NOT demonstrated")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    main()
