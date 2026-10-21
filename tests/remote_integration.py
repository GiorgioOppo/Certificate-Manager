#!/usr/bin/env python3
"""Local TLS acquisition tests; no public hosts or external email services."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CERTIFICATI_BIN", ROOT / "certificati")).resolve()
OPENSSL = os.environ.get("OPENSSL", "openssl")


def command(*arguments):
    result = subprocess.run(
        [str(argument) for argument in arguments], capture_output=True, text=True, timeout=30
    )
    if result.returncode:
        raise AssertionError(f"Comando fallito: {arguments}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def fingerprint(pem):
    first = pem.split("-----END CERTIFICATE-----", 1)[0] + "-----END CERTIFICATE-----\n"
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(first)).hexdigest()


def normalized_fingerprint(value):
    return value.replace(":", "").lower()


class LocalServer:
    """TLS peer which records decrypted bytes, or a deliberately plain TCP peer."""

    def __init__(self, certificate=None, key=None, ipv6=False):
        self.context = None
        self.connections = 0
        self.received = []
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        if certificate:
            self.replace_certificate(certificate, key)
        self.listener = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("::1" if ipv6 else "127.0.0.1", 0))
            self.listener.listen(8)
            self.listener.settimeout(0.2)
        except BaseException:
            self.listener.close()
            raise
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def replace_certificate(self, certificate, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(key))
        with self.lock:
            self.context = context

    def run(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.connections += 1
                context = self.context
            try:
                client.settimeout(2)
                if context is None:
                    client.sendall(b"This endpoint speaks plain TCP, not TLS.\r\n")
                    continue
                with context.wrap_socket(client, server_side=True) as secured:
                    # The client must inspect the handshake without issuing an HTTP request.
                    data = secured.recv(4096)
                    if data:
                        with self.lock:
                            self.received.append(data)
            except (OSError, ssl.SSLError):
                pass
            finally:
                client.close()

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=4)
        if self.thread.is_alive():
            raise AssertionError("Il server TLS di prova non si è arrestato.")


class RemoteAcquisitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise RuntimeError(f"Eseguibile mancante: {BINARY}; eseguire make.")
        cls.fixtures = tempfile.TemporaryDirectory(prefix="certificati-remote-fixtures-")
        directory = cls.fixture_dir = Path(cls.fixtures.name)
        cls.root = directory / "root.pem"
        cls.root_key = directory / "root.key"
        cls.intermediate = directory / "intermediate.pem"
        cls.intermediate_key = directory / "intermediate.key"
        command(
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-days", "3650", "-set_serial", "1", "-subj", "/CN=Remote Test Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", cls.root_key, "-out", cls.root,
        )
        command(
            OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-subj", "/CN=Remote Test Intermediate CA", "-keyout", cls.intermediate_key,
            "-out", directory / "intermediate.csr",
        )
        extensions = directory / "intermediate.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid:always\n"
        )
        command(
            OPENSSL, "x509", "-req", "-in", directory / "intermediate.csr",
            "-CA", cls.root, "-CAkey", cls.root_key, "-set_serial", "2", "-days", "3650",
            "-sha256", "-extfile", extensions, "-out", cls.intermediate,
        )
        leaf_extensions = directory / "leaf.ext"
        leaf_extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        )
        cls.certificates = {}
        for name, serial in (("first", "10"), ("second", "11"), ("expired", "12")):
            certificate, key, request = directory / f"{name}.pem", directory / f"{name}.key", directory / f"{name}.csr"
            command(
                OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", "/CN=localhost", "-keyout", key, "-out", request,
            )
            if name != "expired":
                command(
                    OPENSSL, "x509", "-req", "-in", request, "-CA", cls.intermediate,
                    "-CAkey", cls.intermediate_key, "-set_serial", serial, "-days", "120",
                    "-sha256", "-extfile", leaf_extensions, "-out", certificate,
                )
            else:
                (directory / "index.txt").write_text("")
                (directory / "serial").write_text("12\n")
                config = directory / "ca.cnf"
                config.write_text(
                    f"[ca]\ndefault_ca=local_ca\n[local_ca]\ndatabase={directory / 'index.txt'}\n"
                    f"new_certs_dir={directory}\nserial={directory / 'serial'}\n"
                    f"certificate={cls.intermediate}\nprivate_key={cls.intermediate_key}\n"
                    "default_md=sha256\ndefault_days=30\npolicy=subject_policy\n"
                    "x509_extensions=server_cert\n[subject_policy]\ncommonName=supplied\n"
                    "[server_cert]\nbasicConstraints=critical,CA:FALSE\n"
                    "keyUsage=critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
                    "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                )
                command(
                    OPENSSL, "ca", "-batch", "-config", config, "-in", request,
                    "-out", certificate, "-notext", "-startdate", "20200101000000Z",
                    "-enddate", "20200102000000Z",
                )
            chain = directory / f"{name}-chain.pem"
            chain.write_bytes(certificate.read_bytes() + cls.intermediate.read_bytes())
            cls.certificates[name] = (certificate, key, chain)

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="certificati-remote-test-")
        self.db = Path(self.workspace.name) / "remote.db"
        self.application = None
        self.application_log = None
        self.servers = []

    def tearDown(self):
        if self.application:
            self.application.terminate()
            try:
                self.application.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.application.kill()
                self.application.wait(timeout=5)
        if self.application_log:
            self.application_log.close()
        for server in self.servers:
            server.close()
        self.workspace.cleanup()

    def peer(self, name="first", ipv6=False, plaintext=False):
        if plaintext:
            server = LocalServer()
        else:
            _, key, chain = self.certificates[name]
            server = LocalServer(chain, key, ipv6=ipv6)
        self.servers.append(server)
        return server

    def start_application(self, trusted=True):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            self.port = candidate.getsockname()[1]
        environment = {key: value for key, value in os.environ.items() if not key.startswith("CERTIFICATI_SMTP_")}
        environment.pop("CERTIFICATI_TLS_CA_FILE", None)
        if trusted:
            environment["CERTIFICATI_TLS_CA_FILE"] = str(self.root)
        self.application_log = tempfile.TemporaryFile()
        self.application = subprocess.Popen(
            [str(BINARY), "--db", str(self.db), "serve", "--port", str(self.port)],
            env=environment, stdout=self.application_log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.application.poll() is not None:
                self.application_log.seek(0)
                self.fail("Server applicativo terminato: " + self.application_log.read().decode(errors="replace"))
            try:
                status, _, data = self.http("GET", "/api/state")
                if status == 200:
                    self.token = json.loads(data)["csrf_token"]
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.fail("Il server applicativo non risponde entro 10 secondi.")

    def http(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def form(self, path, values, method="POST", csrf=True):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if csrf:
            headers["X-CSRF-Token"] = self.token
        return self.http(method, path, urlencode(values).encode(), headers)

    def check(self, target, certificate_id=None):
        values = {"target": target}
        if certificate_id is not None:
            values["certificate_id"] = certificate_id
        status, _, body = self.form("/api/remote/check", values)
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        for key in ("ok", "target", "host", "address", "port", "checked_at", "dns_ok", "tcp_ok",
                    "tls_ok", "chain_trusted", "hostname_valid", "time_valid", "verified",
                    "verification_error", "tls_version", "comparison", "expected_certificate_id",
                    "certificate", "presented_chain", "token", "download_url"):
            self.assertIn(key, data)
        return data

    def state(self):
        status, _, body = self.http("GET", "/api/state")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def test_trusted_snapshot_import_download_and_comparison(self):
        peer = self.peer()
        self.start_application()
        target = f"https://localhost:{peer.port}/ignored/path?query=ignored"
        checked = self.check(target)
        for stage in ("dns_ok", "tcp_ok", "tls_ok", "chain_trusted", "hostname_valid", "time_valid", "verified"):
            self.assertTrue(checked[stage], (stage, checked))
        self.assertEqual(checked["host"], "localhost")
        self.assertEqual(checked["port"], peer.port)
        self.assertTrue(checked["address"])
        self.assertTrue(checked["tls_version"].startswith("TLS"))
        self.assertEqual(checked["comparison"], "unknown")
        self.assertTrue(checked["token"] and checked["download_url"])
        first_pem = self.certificates["first"][0].read_text()
        self.assertEqual(normalized_fingerprint(checked["certificate"]["fingerprint"]), fingerprint(first_pem))
        self.assertEqual(len(checked["presented_chain"]), 2)
        self.assertEqual(self.state()["certificates"], [])
        # Changing the live server must not change a previously captured download or import.
        _, second_key, second_chain = self.certificates["second"]
        peer.replace_certificate(second_chain, second_key)
        connections = peer.connections
        status, headers, download = self.http("GET", checked["download_url"])
        self.assertEqual(status, 200, download)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        self.assertEqual(download.decode(), self.certificates["first"][2].read_text())
        self.assertEqual(download.count(b"-----BEGIN CERTIFICATE-----"), 2)
        self.assertNotIn(b"PRIVATE KEY", download)
        self.assertNotIn(self.root.read_bytes().strip(), download)
        self.assertEqual(peer.connections, connections)
        status, _, body = self.form("/api/remote/import", {"token": checked["token"]})
        self.assertEqual(status, 200, body)
        imported = json.loads(body)
        self.assertTrue(imported["ok"])
        self.assertGreater(imported["imported"], 0)
        certificate_id = imported["certificate_id"]
        row = next(row for row in self.state()["certificates"] if row["id"] == certificate_id)
        self.assertEqual(normalized_fingerprint(row["fingerprint"]), fingerprint(first_pem))
        # Import uses the captured snapshot; a separately scheduled monitor may
        # now handshake with the live endpoint without changing this baseline.
        status, _, body = self.form(f"/api/certificates/{certificate_id}/contacts", [
            ("role", "business"), ("name", "Referente locale"), ("email", "reference@example.test")
        ], method="PUT")
        self.assertEqual(status, 200, body)
        status, _, body = self.form("/api/remote/import", {"token": checked["token"]})
        self.assertEqual(status, 200, body)
        duplicate = json.loads(body)
        self.assertEqual(duplicate["certificate_id"], certificate_id)
        self.assertEqual(duplicate["imported"], 0)
        self.assertGreater(duplicate["duplicates"], 0)
        row = next(row for row in self.state()["certificates"] if row["id"] == certificate_id)
        self.assertEqual(row["contacts"][0]["email"], "reference@example.test")
        changed = self.check(f"localhost:{peer.port}", certificate_id)
        self.assertEqual(changed["comparison"], "changed")
        self.assertEqual(changed["expected_certificate_id"], certificate_id)
        self.assertEqual(normalized_fingerprint(changed["certificate"]["fingerprint"]),
                         fingerprint(self.certificates["second"][0].read_text()))
        _, first_key, first_chain = self.certificates["first"]
        peer.replace_certificate(first_chain, first_key)
        same = self.check(f"localhost:{peer.port}", certificate_id)
        self.assertEqual(same["comparison"], "same")
        self.assertEqual(peer.received, [])

    def test_untrusted_certificate_still_available(self):
        peer = self.peer()
        self.start_application(trusted=False)
        checked = self.check(f"localhost:{peer.port}")
        self.assertTrue(checked["dns_ok"] and checked["tcp_ok"] and checked["tls_ok"])
        self.assertFalse(checked["chain_trusted"])
        self.assertTrue(checked["hostname_valid"] and checked["time_valid"])
        self.assertFalse(checked["verified"])
        self.assertTrue(checked["verification_error"])
        self.assertIsNotNone(checked["certificate"])
        self.assertTrue(checked["token"] and checked["download_url"])
        self.assertEqual(self.state()["certificates"], [])
        self.assertEqual(peer.received, [])

    def test_hostname_mismatch_is_separate_from_trust(self):
        peer = self.peer()
        self.start_application()
        checked = self.check(f"127.0.0.1:{peer.port}")
        self.assertTrue(checked["tls_ok"] and checked["chain_trusted"] and checked["time_valid"])
        self.assertFalse(checked["hostname_valid"])
        self.assertFalse(checked["verified"])
        self.assertIsNotNone(checked["certificate"])
        self.assertTrue(checked["verification_error"])
        self.assertEqual(peer.received, [])

    def test_expired_certificate_is_retrieved_for_diagnosis(self):
        peer = self.peer("expired")
        self.start_application()
        checked = self.check(f"localhost:{peer.port}")
        self.assertTrue(checked["dns_ok"] and checked["tcp_ok"] and checked["tls_ok"])
        self.assertFalse(checked["time_valid"])
        self.assertFalse(checked["verified"])
        self.assertIsNotNone(checked["certificate"])
        self.assertTrue(checked["verification_error"])
        self.assertEqual(peer.received, [])

    def test_tcp_failure_and_plaintext_tls_failure(self):
        plain = self.peer(plaintext=True)
        self.start_application()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed:
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
        unreachable = self.check(f"127.0.0.1:{closed_port}")
        self.assertTrue(unreachable["dns_ok"])
        self.assertFalse(unreachable["tcp_ok"] or unreachable["tls_ok"])
        self.assertIsNone(unreachable["certificate"])
        self.assertFalse(unreachable["token"] or unreachable["download_url"])
        plaintext = self.check(f"127.0.0.1:{plain.port}")
        self.assertTrue(plaintext["dns_ok"] and plaintext["tcp_ok"])
        self.assertFalse(plaintext["tls_ok"])
        self.assertIsNone(plaintext["certificate"])
        self.assertEqual(self.state()["certificates"], [])

    def test_invalid_input_csrf_and_snapshot_tokens(self):
        peer = self.peer()
        self.start_application()
        status, _, body = self.form("/api/remote/check", {"target": f"localhost:{peer.port}"}, csrf=False)
        self.assertEqual(status, 403, body)
        self.assertEqual(peer.connections, 0)
        for target in ("http://localhost", "ftp://localhost", "https://user:password@localhost",
                       "*.example.test", "https://*.example.test", "localhost:0", "localhost:65536",
                       "localhost:notaport", "https://", "localhost\r\nInjected: yes"):
            with self.subTest(target=target):
                status, _, body = self.form("/api/remote/check", {"target": target})
                self.assertEqual(status, 400, body)
        status, _, body = self.form("/api/remote/import", {"token": "unknown-snapshot-token"})
        self.assertIn(status, (400, 404), body)
        checked = self.check(f"localhost:{peer.port}")
        status, _, body = self.http("GET", checked["download_url"].replace(checked["token"], "unknown-token"))
        self.assertIn(status, (400, 404), body)
        self.assertEqual(self.state()["certificates"], [])

    def test_csrf_rejection_preserves_response_with_delayed_body(self):
        peer = self.peer()
        self.start_application()
        body = urlencode({"target": f"localhost:{peer.port}"}).encode()
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
                try:
                    connection.putrequest("POST", "/api/remote/check")
                    connection.putheader("Content-Type", "application/x-www-form-urlencoded")
                    connection.putheader("Content-Length", str(len(body)))
                    connection.endheaders()
                    # Rejection precedes the request body: closing an unread socket
                    # must not reset the connection and truncate the HTTP 403 JSON.
                    time.sleep(0.03)
                    connection.send(body)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 403)
                    error = json.loads(response.read())
                    self.assertTrue(error.get("error"), error)
                finally:
                    connection.close()
        self.assertEqual(peer.connections, 0)
        self.assertEqual(self.state()["certificates"], [])

    def test_bracketed_ipv6_if_available(self):
        try:
            peer = self.peer(ipv6=True)
        except OSError as error:
            self.skipTest(f"Loopback IPv6 non disponibile: {error}")
        self.start_application()
        checked = self.check(f"https://[::1]:{peer.port}/ignored")
        self.assertTrue(checked["dns_ok"] and checked["tcp_ok"] and checked["tls_ok"])
        self.assertFalse(checked["hostname_valid"])
        self.assertFalse(checked["verified"])
        self.assertIsNotNone(checked["certificate"])
        self.assertEqual(peer.received, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
