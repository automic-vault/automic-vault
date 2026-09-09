#!/usr/bin/env python3
"""Check the reviewed uv keyring protocol with isolated dummy credentials.

Usage: python3 scripts/check-uv-keyring.py /path/to/official/uv
This does not install AV or exercise the signed XPC authorization boundary.
"""
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

uv = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="av-uv-keyring-") as temporary:
    root = Path(temporary)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    calls = root / "calls.jsonl"
    helper = root / "keyring"
    helper.write_text(f"#!{sys.executable}\n" + "import json, os, sys\n"
                      + f"with open({str(calls)!r}, 'a') as f: f.write(json.dumps([sys.argv[1:], os.getppid()]) + '\\n')\n"
                      + "print('probe-user\\nprobe-password' if sys.argv[-2:] == ['--mode', 'creds'] else 'probe-password')\n")
    helper.chmod(0o700)

    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404 if self.headers.get("Authorization") else 401)
            self.send_header("WWW-Authenticate", 'Basic realm="probe"')
            self.end_headers()
        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    env = {"HOME": str(root), "PATH": f"{root}:/usr/bin:/bin", "UV_NO_CONFIG": "true",
           "UV_CREDENTIALS_DIR": str(root / "credentials"), "UV_CACHE_DIR": str(root / "cache"),
           "UV_KEYRING_PROVIDER": "subprocess", "UV_PYTHON_DOWNLOADS": "never", "UV_HTTP_RETRIES": "0"}
    url = f"https://localhost:{server.server_port}/simple/"

    def run(args, input=""):
        process = subprocess.Popen([str(uv), *args], env=env, cwd=root, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input, timeout=30)
        return process.pid, process.returncode, stdout, stderr

    try:
        base = ["pip", "compile", "--python", sys.executable, "--allow-insecure-host", "localhost", "-"]
        pid, _, _, _ = run(base + ["--index-url", url.replace("https://", "https://probe-user@")], "av-dummy-nonexistent==1\n")
        records = [json.loads(line) for line in calls.read_text().splitlines()]
        assert any(args == ["get", url, "probe-user"] and parent == pid for args, parent in records), records
        calls.unlink()
        config = root / "uv.toml"
        config.write_text(f'[[index]]\nname = "probe"\nurl = "{url}"\nauthenticate = "always"\n')
        pid, _, _, _ = run(["--config-file", str(config), *base], "av-dummy-nonexistent==1\n")
        records = [json.loads(line) for line in calls.read_text().splitlines()]
        assert any(args == ["get", url, "--mode", "creds"] and parent == pid for args, parent in records), records
        calls.unlink()
        _, code, _, _ = run(["auth", "token", url, "--username", "probe-user"])
        assert code != 0 and not calls.exists(), "auth token unexpectedly called keyring"
        _, code, _, _ = run(["auth", "login", url, "--username", "probe-user", "--password", "probe-password"])
        assert code == 0, "dummy credential fixture could not be written"
        import tomllib
        stored = tomllib.loads((root / "credentials/credentials.toml").read_text())
        assert stored == {"credential": [{"service": f"https://localhost:{server.server_port}/", "username": "probe-user", "scheme": "basic", "password": "probe-password"}]}, stored
        print("PASS: password and creds protocols, direct uv parent, auth-token exclusion, plaintext schema")
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
