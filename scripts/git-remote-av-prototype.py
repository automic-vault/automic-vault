#!/usr/bin/env python3
"""Remote-helper experiment. Fixture authorization only; NEVER use real credentials.

Invoked by check-git-credential-confinement.py --adapter. Not installed by AV.
The signed Gate Client, live identity binding, and Vault records are not implemented here.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


def main():
    if len(sys.argv) != 4:
        raise ValueError("this helper requires an explicit loopback test fixture")
    fixture = json.loads(Path(sys.argv[1]).read_text())
    endpoint = urlsplit(fixture["url"])
    if (endpoint.scheme != "https" or endpoint.hostname != "localhost" or not endpoint.port
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.path != "/remote.git" or endpoint.query or endpoint.fragment):
        raise ValueError("prototype is restricted to the loopback test server")
    if sys.argv[3] != fixture["url"]:
        raise ValueError("unrecognized destination")
    git = fixture["git"]
    local_env = dict(fixture["environment"])
    if "GIT_DIR" in os.environ:
        local_env["GIT_DIR"] = os.environ["GIT_DIR"]
    options = {}

    def local(*args):
        return subprocess.run([git, *args], env=local_env, capture_output=True,
                              check=True, timeout=20).stdout.decode().strip()

    def reference(value):
        if (not value.startswith("refs/heads/") or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
                or subprocess.run([git, "check-ref-format", value], env=local_env,
                                  capture_output=True, timeout=20).returncode):
            raise ValueError("unsupported branch ref")
        return value

    def oid(value):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("expected a fixed SHA-1 object ID")
        return value

    def line():
        value = sys.stdin.buffer.readline(8193)
        if len(value) > 8192 or (value and not value.endswith(b"\n")) or b"\0" in value or b"\r" in value:
            raise ValueError("malformed helper input")
        return None if not value else value[:-1].decode("utf-8", errors="strict")

    def batch(first, prefix):
        values = [first]
        while (value := line()) != "":
            if value is None or not value.startswith(prefix) or len(values) >= 4096:
                raise ValueError("incomplete, mixed, or oversized batch")
            values.append(value)
        return values

    def network(kind, commands, details):
        # Fixture-only authorization. A production Gate Client must submit this
        # complete plan to Vault and bind it to the real original operation.
        if kind == "write" and fixture["authority"] != "write":
            raise ValueError("fixture read authority cannot authorize a write")
        plan = {"kind": kind, "url": fixture["url"], "options": dict(options), **details}
        environment = dict(fixture["environment"], GIT_DIR=fixture["repository"],
                           HOME=fixture["empty"], XDG_CONFIG_HOME=fixture["empty"])
        if commands[0].startswith(("fetch ", "push ")):
            if local("rev-parse", "--show-object-format") != "sha1" or local("rev-parse", "--is-shallow-repository") != "false":
                raise ValueError("prototype requires a full SHA-1 repository")
            objects = str(Path(local("rev-parse", "--git-path", "objects")).resolve())
            environment["GIT_OBJECT_DIRECTORY"] = objects
            plan["objects"] = objects
        # Construct all input before starting the credential-bearing process.
        # Never retain that process between protocol requests.
        settings = [f"option {key} {value}" for key, value in options.items()]
        payload = ("\n".join(settings + commands) + "\n\n").encode()
        with Path(fixture["plans"]).open("a") as log:
            log.write(json.dumps(plan, sort_keys=True) + "\n")
        # We advertise fetch/push, not an opaque stateless-connect session.
        # Protocol v0 supplies the explicit ref list those capabilities need.
        result = subprocess.run([git, *fixture["config"], "-c", "protocol.version=0",
                                 "remote-https", fixture["url"], fixture["url"]],
                                cwd=fixture["empty"], env=environment, input=payload,
                                capture_output=True, timeout=120)
        if result.returncode:
            raise ValueError("constrained HTTPS request failed (output withheld)")
        response = result.stdout
        for _ in settings:
            status, separator, response = response.partition(b"\n")
            if not separator or status != b"ok":
                raise ValueError("transport did not accept a required option")
        # No credential redaction here: tests must detect any actual disclosure.
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()

    while (value := line()) not in (None, ""):
        if value == "capabilities":
            print("fetch\npush\noption\n\n", end="", flush=True)
        elif value.startswith("option "):
            key, _, setting = value[7:].partition(" ")
            if key in ("progress", "cloning", "followtags", "check-connectivity", "dry-run") and setting in ("true", "false"):
                options[key] = setting
            elif key == "verbosity" and re.fullmatch(r"[0-3]", setting):
                options[key] = setting
            else:
                # Refuse unknown safety semantics instead of letting Git warn
                # about unsupported options and continue with weaker behavior.
                raise ValueError("unsupported option: " + key)
            print("ok", flush=True)
        elif value in ("list", "list for-push"):
            network("write" if value == "list for-push" else "read", [value], {"operation": value})
        elif value.startswith("fetch "):
            requests = []
            for entry in batch(value, "fetch "):
                fields = entry.split(" ")
                if len(fields) != 3:
                    raise ValueError("malformed fetch")
                _, object_id, ref = fields
                if ref != "HEAD":
                    reference(ref)
                requests.append((oid(object_id), ref))
            network("read", [f"fetch {object_id} {ref}" for object_id, ref in requests] + [""],
                    {"operation": "fetch", "fetch": requests})
        elif value.startswith("push "):
            requests = []
            for entry in batch(value, "push "):
                source, separator, destination = entry[5:].partition(":")
                if not separator or not source or source.startswith("+"):
                    raise ValueError("force, deletion, or malformed push is unsupported")
                if source != "HEAD" and not re.fullmatch(r"[0-9a-f]{40}", source):
                    reference(source)
                # Resolve once, before authorization; the network child gets
                # only this OID and never resolves the mutable source ref again.
                object_id = oid(local("rev-parse", "--verify", "--end-of-options", source + "^{commit}"))
                requests.append((object_id, reference(destination)))
            network("write", [f"push {object_id}:{ref}" for object_id, ref in requests] + [""],
                    {"operation": "push", "updates": requests})
        else:
            raise ValueError("unsupported helper command")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"av prototype: {error}", file=sys.stderr)
        sys.exit(1)
