#!/usr/bin/env python3
"""Integration tests: generated certificates, isolated SQLite DBs, local HTTP."""

import datetime
from email import policy
from email.parser import BytesParser
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote, urlencode


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CERTIFICATI_BIN", ROOT / "certificati")).resolve()
OPENSSL = os.environ.get("OPENSSL", "openssl")
TEST_ENV = {key: value for key, value in os.environ.items() if not key.startswith("CERTIFICATI_SMTP_")}


def command(*args):
    result = subprocess.run(
        [str(arg) for arg in args], capture_output=True, text=True, timeout=20
    )
    if result.returncode:
        raise AssertionError(f"Comando fallito: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def remove_workflow_v6(connection):
    """Remove v6+ additions before reconstructing an actual historical schema."""
    # Triggers on legacy tables reference workflow_audit. Remove them first so
    # historical table rebuilds and inserts are valid without the v6 audit log.
    triggers = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'audit_%'"
    ).fetchall()
    for (name,) in triggers:
        connection.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
    for table in ("inventory_rows", "inventory_batches", "inventory_commits", "event_claims",
                  "monitor_options", "renewal_closure_reports", "policy_templates", "workflow_audit",
                  "mail_template_variants", "mail_templates", "mail_template_settings"):
        connection.execute(f"DROP TABLE IF EXISTS {table}")


class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise RuntimeError(f"Eseguibile mancante: {BINARY}; eseguire make prima dei test.")
        if not shutil.which(OPENSSL):
            raise RuntimeError("openssl non disponibile nel PATH.")
        cls.fixtures = tempfile.TemporaryDirectory(prefix="certificati-fixtures-")
        cls.fixture_dir = Path(cls.fixtures.name)
        cls.pem = cls.fixture_dir / "example.pem"
        cls.key = cls.fixture_dir / "example.key"
        cls.soon = cls.fixture_dir / "soon.pem"
        cls.der = cls.fixture_dir / "example.der"
        cls.bundle = cls.fixture_dir / "bundle.pem"
        cls.malformed = cls.fixture_dir / "malformed.pem"
        for name, certificate, key, days in [
            ("example.test", cls.pem, cls.key, "120"),
            ("soon.test", cls.soon, cls.fixture_dir / "soon.key", "2"),
        ]:
            command(
                OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", days, "-set_serial", "12345" if days == "120" else "67890",
                "-subj", f"/C=IT/O=Certificati Test/CN={name}",
                "-addext", f"subjectAltName=DNS:{name},DNS:www.{name},IP:127.0.0.1",
                "-keyout", key, "-out", certificate,
            )
        command(OPENSSL, "x509", "-in", cls.pem, "-outform", "DER", "-out", cls.der)
        cls.bundle.write_bytes(cls.pem.read_bytes() + cls.soon.read_bytes())
        cls.malformed.write_bytes(
            cls.pem.read_bytes() + b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
        )
        cls.root_ca = cls.fixture_dir / "root-ca.pem"
        root_key = cls.fixture_dir / "root-ca.key"
        command(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", "/CN=Unit Test Root CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", root_key, "-out", cls.root_ca)
        cls.intermediate = cls.fixture_dir / "intermediate.pem"
        intermediate_key = cls.fixture_dir / "intermediate.key"
        intermediate_csr = cls.fixture_dir / "intermediate.csr"
        command(OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=Unit Test Intermediate CA", "-keyout", intermediate_key, "-out", intermediate_csr)
        extensions = cls.fixture_dir / "intermediate.ext"
        extensions.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        command(OPENSSL, "x509", "-req", "-in", intermediate_csr, "-CA", cls.root_ca,
                "-CAkey", root_key, "-set_serial", "100", "-days", "730", "-extfile", extensions, "-out", cls.intermediate)
        cls.leaf_old = cls.fixture_dir / "leaf-old.pem"
        cls.leaf_new = cls.fixture_dir / "leaf-new.pem"
        for filename, certificate, days, serial, domain in [
            ("old", cls.leaf_old, "10", "200", "service.example.test"),
            ("new", cls.leaf_new, "120", "201", "service.example.test"),
        ]:
            key = cls.fixture_dir / (filename + ".key")
            csr = cls.fixture_dir / (filename + ".csr")
            command(OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={domain}",
                    "-keyout", key, "-out", csr)
            extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                  "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                                  f"subjectAltName=DNS:{domain},DNS:www.{domain}\n")
            command(OPENSSL, "x509", "-req", "-in", csr, "-CA", cls.intermediate, "-CAkey", intermediate_key,
                    "-set_serial", serial, "-days", days, "-extfile", extensions, "-out", certificate)
        cls.old_chain = cls.leaf_old.read_bytes() + cls.intermediate.read_bytes() + cls.root_ca.read_bytes()
        cls.new_chain = cls.leaf_new.read_bytes() + cls.intermediate.read_bytes() + cls.root_ca.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="certificati-test-")
        self.db = Path(self.workspace.name) / "test.db"
        self.server = None
        self.server_log = None

    def tearDown(self):
        self.stop_server()
        self.workspace.cleanup()

    def cli(self, *args, success=True):
        result = subprocess.run(
            [str(BINARY), "--db", str(self.db), *map(str, args)],
            capture_output=True, text=True, timeout=15,
            env=TEST_ENV,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def rows(self, sql):
        with sqlite3.connect(self.db) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql)]

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            self.port = candidate.getsockname()[1]
        self.server_log = tempfile.TemporaryFile()
        self.server = subprocess.Popen(
            [str(BINARY), "--db", str(self.db), "serve", "--port", str(self.port)],
            stdout=self.server_log, stderr=subprocess.STDOUT,
            env=TEST_ENV,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.server_log.seek(0)
                self.fail("Server terminato: " + self.server_log.read().decode(errors="replace"))
            try:
                status, _, body = self.http("GET", "/api/state")
                if status == 200:
                    self.token = json.loads(body)["csrf_token"]
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.fail("Il server locale non si è avviato entro 10 secondi.")

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
        if self.server_log is not None:
            self.server_log.close()
            self.server_log = None

    def http(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def state(self):
        status, _, body = self.http("GET", "/api/state")
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertIn("certificates", state)
        self.assertIn("notifications", state)
        return state

    def upload(self, content, filename="certificato.pem"):
        return self.http("POST", "/api/certificates", body=content, headers={
            "Content-Type": "application/octet-stream",
            "X-Filename": quote(filename, safe=""),
            "X-CSRF-Token": self.token,
        })

    def mutate(self, method, path, body=b"", content_type="application/octet-stream"):
        return self.http(method, path, body, {"X-CSRF-Token": self.token, "Content-Type": content_type})

    def save_contacts(self, certificate_id, contacts):
        pairs = []
        for role, name, email in contacts:
            pairs.extend([("role", role), ("name", name), ("email", email)])
        return self.mutate("PUT", f"/api/certificates/{certificate_id}/contacts", urlencode(pairs).encode(),
                           "application/x-www-form-urlencoded")

    def test_chain_contacts_renewal_and_email_queue_without_smtp(self):
        self.start_server()
        status, _, body = self.upload(self.old_chain, "catena.pem")
        self.assertEqual(status, 200, body)
        state = self.state()
        old = next(cert for cert in state["certificates"] if not cert["is_ca"])
        self.assertEqual(old["chain_status"], "complete")
        self.assertIn("Unit Test Root CA", old["root_ca"])
        self.assertIn("Unit Test Intermediate CA", old["intermediate_ca"])
        self.assertTrue(old["pem_available"])
        self.assertNotIn("pem", old)
        contacts = [("business", "Responsabile Uno", "owner@example.test"),
                    ("business", "Responsabile Due", "owner2@example.test"),
                    ("technical", "Tecnico Uno", "tech@example.test"),
                    ("technical", "Tecnico Due", "tech2@example.test")]
        status, _, body = self.save_contacts(old["id"], contacts)
        self.assertEqual(status, 200, body)
        state = self.state()
        old = next(cert for cert in state["certificates"] if cert["id"] == old["id"])
        self.assertEqual(len(old["contacts"]), 4)
        expiry = [item for item in state["outbox"] if item["kind"] == "expiry"]
        self.assertEqual(len(expiry), 2)
        self.assertTrue(all(item["status"] == "pending" and item["threshold"] == 15 for item in expiry))
        self.assertFalse(state["delivery"]["configured"])
        status, _, body = self.save_contacts(old["id"], [("business", "Invalid", "bad\r\nBcc: victim@test.invalid")])
        self.assertEqual(status, 400, body)
        self.assertEqual(len(next(c for c in self.state()["certificates"] if c["id"] == old["id"])["contacts"]), 4)
        status, _, body = self.save_contacts(old["id"], contacts + [("business", "Duplicate", "OWNER@example.test")])
        self.assertEqual(status, 400, body)
        status, _, body = self.http("PUT", f"/api/certificates/{old['id']}/contacts", b"", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403, body)
        # Invalid renewals leave the active certificate and all contacts untouched.
        status, _, body = self.mutate("POST", f"/api/certificates/{old['id']}/renew", self.old_chain)
        self.assertEqual(status, 400, body)
        self.assertEqual(len(self.state()["certificates"]), 3)
        status, _, body = self.mutate("POST", f"/api/certificates/{old['id']}/renew", self.new_chain)
        self.assertEqual(status, 200, body)
        renewal = json.loads(body)
        self.assertEqual(renewal["queued"], 2)
        state = self.state()
        new = next(c for c in state["certificates"] if c["id"] == renewal["certificate_id"])
        previous = next(c for c in state["certificates"] if c["id"] == old["id"])
        # Signing the renewal does not retire the still-installed certificate.
        self.assertEqual(previous["archived"], 0)
        self.assertIsNone(previous["superseded_by"])
        self.assertEqual(new["archived"], 0)
        self.assertEqual(new["contacts"], old["contacts"])
        self.assertEqual(len(state["outbox"]), 4)
        self.assertEqual(state["delivery"]["pending"], 4)
        certificate_messages = [item for item in state["outbox"] if item["kind"] == "certificate"]
        previous_reminders = [item for item in state["outbox"] if item["kind"] == "expiry"]
        self.assertEqual(len(certificate_messages), 2)
        self.assertEqual(len(previous_reminders), 2)
        self.assertTrue(all(item["certificate_id"] == old["id"] for item in previous_reminders))
        self.assertTrue(all(item["status"] == "pending" for item in state["outbox"]))
        for item in certificate_messages:
            self.assertNotIn("attachment_pem", item)
            status, headers, content = self.http("GET", f"/api/outbox/{item['id']}/message")
            self.assertEqual(status, 200, content)
            self.assertIn("attachment", headers["Content-Disposition"])
            message = BytesParser(policy=policy.default).parsebytes(content)
            self.assertIn(item["recipient_email"], str(message["To"]))
            attachments = list(message.iter_attachments())
            self.assertEqual(len(attachments), 1)
            pem = attachments[0].get_payload(decode=True)
            self.assertIn(self.leaf_new.read_bytes().strip(), pem)
            self.assertEqual(pem.count(b"-----BEGIN CERTIFICATE-----"), 3)
            self.assertNotIn(b"PRIVATE KEY", pem)
        status, headers, content = self.http("GET", f"/api/certificates/{new['id']}/download")
        self.assertEqual(status, 200)
        self.assertEqual(content.count(b"-----BEGIN CERTIFICATE-----"), 3)
        status, _, body = self.mutate("POST", f"/api/certificates/{new['id']}/distribute")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["queued"], 0)
        status, _, body = self.mutate("POST", "/api/delivery/process")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["sent"], 0)
        self.assertFalse(json.loads(body)["configured"])
        self.assertTrue(all(item["status"] == "pending" for item in self.state()["outbox"]))
        # Changing recipients removes queued messages for people no longer assigned.
        status, _, body = self.save_contacts(new["id"], contacts[:3])
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.state()["outbox"]), 3)
        self.stop_server()
        self.start_server()
        self.assertEqual(len(next(c for c in self.state()["certificates"] if c["id"] == new["id"])["contacts"]), 3)
        self.assertEqual(self.state()["delivery"]["pending"], 3)

    def test_missing_chain_and_legacy_database_upgrade(self):
        self.cli("import", self.leaf_old)
        original = self.rows("SELECT * FROM certificates")[0]
        # Rebuild a genuine v1 archive, containing the original row and reminder history.
        self.db.unlink()
        columns = [key for key in original if key not in {"pem", "archived", "superseded_by"}]
        text_columns = {"fingerprint", "common_name", "subject", "issuer", "serial", "sans", "key_algorithm", "signature_algorithm", "source"}
        definitions = ["id INTEGER PRIMARY KEY AUTOINCREMENT"] + [
            key + (" TEXT NOT NULL" if key in text_columns else " INTEGER NOT NULL") + (" UNIQUE" if key == "fingerprint" else "")
            for key in columns if key != "id"]
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE certificates(" + ",".join(definitions) + ")")
            connection.execute("CREATE TABLE notifications(certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,"
                               "threshold INTEGER NOT NULL,sent_at INTEGER NOT NULL,PRIMARY KEY(certificate_id,threshold))")
            connection.execute("INSERT INTO certificates(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")",
                               [original[key] for key in columns])
            connection.execute("INSERT INTO notifications VALUES(?,?,?)", (original["id"], 15, int(time.time())))
            connection.execute("PRAGMA user_version=1")
        self.start_server()
        state = self.state()
        self.assertEqual(len(state["certificates"]), 1)
        legacy = state["certificates"][0]
        self.assertEqual(legacy["id"], original["id"])
        self.assertEqual(legacy["chain_status"], "legacy")
        self.assertFalse(legacy["pem_available"])
        self.assertEqual(len(state["notifications"]), 1)
        self.assertEqual(self.rows("PRAGMA user_version")[0]["user_version"], 8)
        status, _, body = self.upload(self.leaf_old.read_bytes())
        self.assertEqual(status, 200, body)
        cert = self.state()["certificates"][0]
        self.assertTrue(cert["pem_available"])
        self.assertEqual(cert["chain_status"], "incomplete")
        self.assertEqual(cert["root_ca"], "")
        self.assertEqual(cert["intermediate_ca"], "")
        self.assertEqual(len(self.state()["notifications"]), 1)

    def test_v2_database_upgrade_preserves_contacts_history_and_queue(self):
        self.start_server()
        status, _, body = self.upload(self.old_chain, "precedente.pem")
        self.assertEqual(status, 200, body)
        certificate = next(cert for cert in self.state()["certificates"] if not cert["is_ca"])
        status, _, body = self.save_contacts(certificate["id"], [
            ("business", "Referente conservato", "owner@example.test"),
            ("technical", "Tecnico conservato", "tech@example.test"),
        ])
        self.assertEqual(status, 200, body)
        self.stop_server()
        tables = ("certificates", "contacts", "notifications", "outbox")
        previous = {table: self.rows(f"SELECT * FROM {table} ORDER BY rowid") for table in tables}
        self.assertTrue(all(previous[table] for table in tables))
        # Historical messages have no template metadata; migration adds empty
        # markers without rebuilding their subject or body.
        for row in previous["outbox"]:
            row.update(template_alert="", template_audience="", template_copy=0, template_language="")
        # Remove later additions to recreate a populated, genuine v2 schema.
        with sqlite3.connect(self.db) as connection:
            remove_workflow_v6(connection)
            for table in ("renewal_endpoints", "renewal_jobs", "reminder_policies", "monitor_recipients",
                          "certificate_groups", "directory_assignments", "directory_memberships",
                          "directory_groups", "directory_people"):
                connection.execute(f"DROP TABLE {table}")
            # Rebuild the original tables rather than using DROP COLUMN, which
            # would require SQLite 3.35 even though the application supports 3.24.
            connection.execute("ALTER TABLE outbox RENAME TO outbox_v5_fixture")
            connection.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                               "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                               "kind TEXT NOT NULL CHECK(kind IN('expiry','certificate')),"
                               "recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL,"
                               "threshold INTEGER NOT NULL DEFAULT -1,subject TEXT NOT NULL,body TEXT NOT NULL,"
                               "attachment_pem TEXT NOT NULL DEFAULT '',"
                               "status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','failed')),"
                               "attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',"
                               "created_at INTEGER NOT NULL,sent_at INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0,"
                               "UNIQUE(certificate_id,kind,recipient_email,threshold))")
            columns = [key for key in previous["outbox"][0] if key not in {"event_id", "template_alert", "template_audience", "template_copy", "template_language"}]
            column_list = ",".join(columns)
            connection.execute(f"INSERT INTO outbox({column_list}) SELECT {column_list} FROM outbox_v5_fixture")
            connection.execute("DROP TABLE outbox_v5_fixture")
            connection.execute("ALTER TABLE notifications RENAME TO notifications_v5_fixture")
            connection.execute("CREATE TABLE notifications (certificate_id INTEGER NOT NULL "
                               "REFERENCES certificates(id) ON DELETE CASCADE,"
                               "threshold INTEGER NOT NULL CHECK(threshold IN(45,30,15,2,0)),"
                               "sent_at INTEGER NOT NULL,PRIMARY KEY(certificate_id,threshold))")
            connection.execute("INSERT INTO notifications SELECT * FROM notifications_v5_fixture")
            connection.execute("DROP TABLE notifications_v5_fixture")
            connection.execute("DROP TABLE smtp_settings")
            connection.execute("DROP TABLE monitor_events")
            connection.execute("DROP TABLE monitors")
            connection.execute("PRAGMA user_version=2")
        self.start_server()
        state = self.state()
        self.assertEqual(self.rows("PRAGMA user_version")[0]["user_version"], 8)
        self.assertEqual(state["monitors"], [])
        self.assertEqual(state["monitor_events"], [])
        for table in tables:
            self.assertEqual(self.rows(f"SELECT * FROM {table} ORDER BY rowid"), previous[table], table)

    def test_cli_metadata_dedup_persistence_and_remove(self):
        self.cli("import", self.pem)
        records = self.rows("SELECT * FROM certificates")
        self.assertEqual(len(records), 1)
        cert = records[0]
        self.assertEqual(cert["common_name"], "example.test")
        self.assertIn("Certificati Test", cert["issuer"])
        self.assertIn("DNS:example.test", cert["sans"])
        self.assertIn("DNS:www.example.test", cert["sans"])
        self.assertIn("127.0.0.1", cert["sans"])
        self.assertEqual(cert["key_bits"], 2048)
        self.assertTrue(cert["serial"] and cert["signature_algorithm"])
        expected_fingerprint = command(
            OPENSSL, "x509", "-in", self.pem, "-noout", "-fingerprint", "-sha256"
        ).split("=", 1)[1].strip().replace(":", "").lower()
        self.assertEqual(cert["fingerprint"].replace(":", "").lower(), expected_fingerprint)
        start = datetime.datetime.fromtimestamp(cert["not_before"], datetime.timezone.utc)
        end = datetime.datetime.fromtimestamp(cert["not_after"], datetime.timezone.utc)
        self.assertEqual(end - start, datetime.timedelta(days=120))
        self.assertLessEqual(start.timestamp(), time.time() + 2)
        self.cli("import", self.der)
        records = self.rows("SELECT * FROM certificates")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["id"], cert["id"])
        self.assertEqual(records[0]["added_at"], cert["added_at"])
        self.assertIn("example.test", self.cli("list").stdout)
        self.assertIn("example.test", self.cli("show", cert["id"]).stdout)
        self.cli("remove", cert["id"])
        self.assertEqual(self.rows("SELECT * FROM certificates"), [])
        self.cli("show", cert["id"], success=False)

    def test_cli_show_nullable_renewal_link(self):
        self.cli("import", self.leaf_old, self.leaf_new)
        records = self.rows("SELECT id FROM certificates ORDER BY not_after")
        old_id, new_id = (record["id"] for record in records)

        def replacement_value():
            details = self.cli("show", old_id).stdout
            return next(line.split(maxsplit=1)[1] for line in details.splitlines()
                        if line.startswith("superseded_by "))

        self.assertEqual(replacement_value(), "—")
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE certificates SET archived=1,superseded_by=? WHERE id=?",
                               (new_id, old_id))
        self.assertEqual(replacement_value(), str(new_id))
        self.cli("remove", new_id)
        self.assertEqual(replacement_value(), "—")

    def test_cli_bundle_atomicity_and_reminder_history(self):
        self.cli("import", self.malformed, success=False)
        self.assertEqual(self.rows("SELECT * FROM certificates"), [])
        self.cli("import", self.bundle)
        self.assertEqual(len(self.rows("SELECT * FROM certificates")), 2)
        self.cli("check")
        notifications = self.rows("SELECT * FROM notifications")
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["threshold"], 2)
        self.cli("check")
        self.cli("import", self.bundle)
        self.cli("check")
        self.assertEqual(self.rows("SELECT * FROM notifications"), notifications)
        self.cli("remove", notifications[0]["certificate_id"])
        self.assertEqual(self.rows("SELECT * FROM notifications"), [])

    def test_cli_rejects_private_keys_and_invalid_der(self):
        mixed = Path(self.workspace.name) / "mixed.pem"
        mixed.write_bytes(self.pem.read_bytes() + self.key.read_bytes())
        self.cli("import", mixed, success=False)
        self.cli("import", self.key, success=False)
        invalid_der = Path(self.workspace.name) / "invalid.der"
        invalid_der.write_bytes(self.der.read_bytes() + b"unexpected trailing data")
        self.cli("import", invalid_der, success=False)
        self.assertEqual(self.rows("SELECT * FROM certificates"), [])

    def test_http_import_csrf_host_persistence_and_remove(self):
        self.start_server()
        self.assertGreaterEqual(len(self.token), 32)
        status, headers, html = self.http("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertTrue(html)
        for token in (None, "invalid-token"):
            headers = {} if token is None else {"X-CSRF-Token": token}
            status, _, _ = self.http("POST", "/api/check", body=b"", headers=headers)
            self.assertEqual(status, 403)
        for host in ("attacker.example", f"127.0.0.1.attacker.example:{self.port}"):
            status, _, _ = self.http("GET", "/api/state", headers={"Host": host})
            self.assertIn(status, (400, 403))
        status, _, _ = self.upload(self.malformed.read_bytes())
        self.assertGreaterEqual(status, 400)
        self.assertEqual(self.state()["certificates"], [])
        filename = "catena certificati è.pem"
        status, _, body = self.upload(self.bundle.read_bytes(), filename)
        self.assertIn(status, (200, 201), body)
        records = self.state()["certificates"]
        self.assertEqual(len(records), 2)
        self.assertEqual({cert["common_name"] for cert in records}, {"example.test", "soon.test"})
        self.assertTrue(all(cert["source"] == filename for cert in records))
        self.assertTrue(all("days_remaining" in cert and "status" in cert for cert in records))
        primary = next(cert for cert in records if cert["common_name"] == "example.test")
        status, _, body = self.upload(self.der.read_bytes(), "example.der")
        self.assertIn(status, (200, 201), body)
        self.assertEqual(len(self.state()["certificates"]), 2)
        self.assertEqual(
            next(cert for cert in self.state()["certificates"] if cert["common_name"] == "example.test")["id"],
            primary["id"],
        )
        status, _, body = self.http("POST", "/api/check", body=b"", headers={"X-CSRF-Token": self.token})
        self.assertEqual(status, 200, body)
        notifications = self.state()["notifications"]
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["threshold"], 2)
        self.stop_server()
        self.start_server()
        self.assertEqual(len(self.state()["certificates"]), 2)
        self.assertEqual(self.state()["notifications"], notifications)
        soon_id = notifications[0]["certificate_id"]
        status, _, body = self.http("DELETE", f"/api/certificates/{soon_id}", headers={"X-CSRF-Token": self.token})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.state()["certificates"]), 1)
        self.assertEqual(self.state()["notifications"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
