#!/usr/bin/env python3
"""Exercise the built Compose image with disposable containers and a volume.

Run `docker compose build` first. No existing Compose project or local database
is used. The generated test project, volume and certificates are removed on exit.
"""

import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlencode
import uuid


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    project = "certificate-smoke-" + uuid.uuid4().hex[:12]
    environment = {**os.environ, "CERTIFICATI_PORT": str(port)}
    compose = ["docker", "compose", "--project-name", project,
               "--file", str(ROOT / "docker-compose.yml")]

    def command(args, *, binary=False, timeout=120):
        result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True,
                                text=not binary, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"Command failed: {args}\n{result.stdout!s}\n{result.stderr!s}")
        return result.stdout

    def request(method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def state():
        status, body = request("GET", "/api/state")
        require(status == 200, "State API unavailable")
        return json.loads(body)

    def form(method, path, values, token):
        status, body = request(method, path, urlencode(values).encode(), {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"http://127.0.0.1:{port}", "X-CSRF-Token": token,
        })
        require(status == 200, f"Form rejected: {path}: {body!r}")
        return json.loads(body)

    def start():
        command(compose + ["up", "--detach", "--no-build", "--wait", "--wait-timeout", "90"])

    try:
        print("Starting isolated Compose project and checking its health...", flush=True)
        start()
        container = command(compose + ["ps", "--quiet", "certificate-manager"]).strip()
        info = json.loads(command(["docker", "inspect", container]))[0]
        require(info["Config"]["User"] == "10001:10001", "Container must run as the application user")
        require(info["HostConfig"]["ReadonlyRootfs"], "Root filesystem must be read-only")
        require("ALL" in info["HostConfig"]["CapDrop"], "Capabilities must be dropped")
        require(any(item.startswith("no-new-privileges") for item in info["HostConfig"]["SecurityOpt"]),
                "Privilege escalation must be disabled")
        bindings = info["HostConfig"]["PortBindings"]
        require(bindings == {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]},
                "HTTP must be published only on loopback, with matching ports")
        require(info["State"]["Health"]["Status"] == "healthy", "Healthcheck did not succeed")
        require(any(mount["Type"] == "volume" and mount["Destination"] == "/data"
                    for mount in info["Mounts"]), "Persistent data volume missing")
        for route in ("/", "/certificati", "/servizi", "/importa", "/verifica",
                      "/promemoria", "/email", "/workflow?lang=ja"):
            require(request("GET", route)[0] == 200, f"Web page unavailable: {route}")
        require(request("GET", "/api/state", headers={"Host": "untrusted.example.test"})[0] == 403,
                "Host protection was weakened")
        require(request("POST", "/api/check", b"")[0] == 403, "CSRF protection was weakened")
        initial = state()
        require(initial["certificates"] == [], "Test project must start with a fresh registry")
        token = initial["csrf_token"]
        require(request("POST", "/api/check", b"", {
            "Origin": "http://untrusted.example.test", "X-CSRF-Token": token,
        })[0] == 403, "Origin protection was weakened")

        with tempfile.TemporaryDirectory(prefix="certificate-container-") as directory:
            certificate = Path(directory) / "certificate.pem"
            command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-days", "120", "-subj", "/CN=container.example.test",
                     "-addext", "basicConstraints=critical,CA:FALSE",
                     "-keyout", str(Path(directory) / "test-only.key"), "-out", str(certificate)])
            status, _ = request("POST", "/api/certificates", certificate.read_bytes(), {
                "Content-Type": "application/octet-stream", "X-Filename": "container-test.pem",
                "X-CSRF-Token": token,
            })
            require(status == 200, "Certificate upload failed in read-only container")
        certificate_id = state()["certificates"][0]["id"]
        form("PUT", f"/api/certificates/{certificate_id}/contacts", [
            ("role", "business"), ("name", "Container test"), ("email", "test@example.test"),
        ], token)
        profile = dict(enabled=0, host="smtp.example.test", port=587, security="starttls",
                       from_email="sender@example.test", username="test-user",
                       password="generated-test-only-password", clear_password=0)
        form("PUT", "/api/smtp/settings", profile, token)
        key_stat = command(compose + ["exec", "-T", "certificate-manager", "stat",
                                      "--format=%u:%g %a", "/data/certificati.db.smtp.key"]).strip()
        require(key_stat == "10001:10001 600", "SMTP key ownership or mode is incorrect")

        # A closed container-local port exercises the forked monitor without an
        # external HTTPS peer or any outbound SMTP delivery.
        form("POST", "/api/monitors", dict(certificate_id=certificate_id,
             target="https://127.0.0.1:1", interval_minutes=1, enabled=1), token)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current = state()
            if current["monitors"] and current["monitors"][0]["last_status"] == "unreachable":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Background monitor did not finish inside the container")
        print("HTTP, security checks, upload, monitor and encrypted SMTP storage passed.", flush=True)

        command(compose + ["down", "--remove-orphans"])
        archive = command(compose + ["run", "-T", "--rm", "--no-deps", "--entrypoint", "/bin/sh",
                                    "certificate-manager", "-c", "tar -C /data -czf - ."], binary=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as backup:
            names = {item.name.removeprefix("./"): item for item in backup.getmembers()}
            require("certificati.db" in names, "Volume backup omitted the database")
            require("certificati.db.smtp.key" in names, "Volume backup omitted the SMTP key")
            require(names["certificati.db.smtp.key"].mode == 0o600, "Backup lost key permissions")

        start()
        restored = state()
        require(restored["certificates"][0]["id"] == certificate_id, "Recreation lost the registry")
        require(restored["certificates"][0]["contacts"][0]["email"] == "test@example.test",
                "Recreation lost contacts")
        require(len(restored["monitors"]) == 1, "Recreation lost monitoring settings")
        require(restored["smtp"]["password_set"] and not restored["smtp"]["enabled"],
                "Recreation lost or enabled SMTP settings")
        form("PUT", "/api/smtp/settings", {**profile, "password": ""}, restored["csrf_token"])
        print("Volume recreation, complete backup and SMTP key reuse passed.", flush=True)
    finally:
        # This UUID-scoped project contains only synthetic disposable data.
        command(compose + ["down", "--volumes", "--remove-orphans"])
    print("Container smoke test passed; disposable project removed.", flush=True)


if __name__ == "__main__":
    main()
