#!/usr/bin/env python3
"""HTTP bind configuration and request protections, using isolated databases."""

import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CERTIFICATI_BIN", ROOT / "certificati")).resolve()
TEST_ENV = {key: value for key, value in os.environ.items() if not key.startswith("CERTIFICATI_SMTP_")}


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="certificati-network-")
        self.db = Path(self.workspace.name) / "test.db"
        self.server = None
        self.log = None

    def tearDown(self):
        self.stop_server()
        self.workspace.cleanup()

    def stop_server(self):
        if self.server is not None:
            if self.server.poll() is None:
                self.server.terminate()
                try:
                    self.server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.server.kill()
                    self.server.wait(timeout=5)
            self.server = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def start_server(self, options):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            self.port = candidate.getsockname()[1]
        args = [str(value).replace("{port}", str(self.port)) for value in options]
        self.log = tempfile.TemporaryFile()
        self.server = subprocess.Popen(
            [str(BINARY), "--db", str(self.db), "serve", *args],
            stdout=self.log, stderr=subprocess.STDOUT, env=TEST_ENV,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail("Server exited: " + self.log.read().decode(errors="replace"))
            try:
                status, _, body = self.http("GET", "/api/state")
                if status == 200:
                    self.token = json.loads(body)["csrf_token"]
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.fail("HTTP server did not start within 10 seconds")

    def http(self, method, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        try:
            connection.request(method, path, body=b"" if method == "POST" else None, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_default_bind_remains_loopback(self):
        self.start_server(["--port", "{port}"])
        self.log.seek(0)
        output = self.log.read().decode(errors="replace")
        self.assertIn(f"Listener HTTP: 127.0.0.1:{self.port}", output)
        status, _, body = self.http("GET", "/workflow?lang=it")
        self.assertEqual(status, 200, body)

    def test_explicit_bind_and_port_accept_both_orders(self):
        for bind_address in ("127.0.0.1", "0.0.0.0"):
            for options in (["--bind", bind_address, "--port", "{port}"],
                            ["--port", "{port}", "--bind", bind_address]):
                with self.subTest(options=options):
                    self.start_server(options)
                    self.log.seek(0)
                    self.assertIn(f"Listener HTTP: {bind_address}:{self.port}", self.log.read().decode())
                    self.assertTrue(self.db.is_file())
                    self.stop_server()

    def test_invalid_options_are_rejected_before_database_creation(self):
        invalid = [
            ["--bind"], ["--port"], ["--bind", ""], ["--bind", "localhost"],
            ["--bind", "::1"], ["--bind", "192.0.2.1"], ["--bind", "127.0.0.2"],
            ["--bind", "0"], ["--bind", "127.000.000.001"],
            ["--bind", "0.0.0.0", "--bind", "127.0.0.1"],
            ["--bind", "127.0.0.1", "--bind", "127.0.0.1"],
            ["--port", "49152", "--port", "49153"],
            ["--port", "0"], ["--port", "65536"], ["--port", "-1"],
            ["--port", "+8080"], ["--port", "8080x"], ["--port", ""],
            ["--port", "999999999999999999999999"],
            ["--bind", "0.0.0.0", "--port", "invalid"],
            ["--port", "49152", "--bind"], ["--bind", "0.0.0.0", "extra"],
            ["--interval", "60"], ["--unknown", "value"],
        ]
        for options in invalid:
            with self.subTest(options=options):
                result = subprocess.run(
                    [str(BINARY), "--db", str(self.db), "serve", *options],
                    capture_output=True, text=True, env=TEST_ENV, timeout=5,
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.db.exists(), "Invalid arguments must not create an archive")

    def test_all_interface_bind_keeps_host_origin_and_csrf_checks(self):
        self.start_server(["--bind", "0.0.0.0", "--port", "{port}"])
        for host in (f"0.0.0.0:{self.port}", f"example.test:{self.port}",
                     "127.0.0.1:1", "localhost:1"):
            with self.subTest(host=host):
                status, _, body = self.http("GET", "/api/state", {"Host": host})
                self.assertEqual(status, 403, body)
        for origin in ("http://example.test", "null", f"https://127.0.0.1:{self.port}",
                       "http://127.0.0.1:1"):
            with self.subTest(origin=origin):
                status, _, body = self.http("POST", "/api/check", {
                    "Origin": origin, "X-CSRF-Token": self.token,
                })
                self.assertEqual(status, 403, body)
        for token in ("", "invalid", "0" * len(self.token)):
            with self.subTest(token=token):
                status, _, body = self.http("POST", "/api/check", {"X-CSRF-Token": token})
                self.assertEqual(status, 403, body)
        for host in ("127.0.0.1", "localhost"):
            status, _, body = self.http("POST", "/api/check", {
                "Host": f"{host}:{self.port}", "Origin": f"http://{host}:{self.port}",
                "X-CSRF-Token": self.token,
            })
            self.assertEqual(status, 200, body)
            self.assertTrue(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
