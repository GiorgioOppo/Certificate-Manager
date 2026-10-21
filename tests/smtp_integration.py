#!/usr/bin/env python3
"""SMTP UI configuration, isolated persistence and secret handling; no external mail."""
import json
import http.client
from pathlib import Path
import socket
import sqlite3
import stat
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from urllib.parse import urlencode

import integration as core


@contextmanager
def database(path):
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


class SmtpSettingsTests(unittest.TestCase):
    setUp = core.ApplicationTests.setUp
    tearDown = core.ApplicationTests.tearDown
    start_server = core.ApplicationTests.start_server
    stop_server = core.ApplicationTests.stop_server
    state = core.ApplicationTests.state

    def rows(self, sql):
        with database(self.db) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql)]

    def http(self, method, path, body=None, headers=None):
        # SMTP connection checks have their own bounded 10-second timeout.
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def start(self):
        self.start_server()

    def form(self, path, values, method="PUT", csrf=True):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if csrf:
            headers["X-CSRF-Token"] = self.token
        body = urlencode(values).encode()
        return self.http(method, path, body, headers)

    def profile(self, **updates):
        values = dict(enabled=0, host="smtp.example.test", port=587, security="starttls",
                      from_email="sender@example.test", username="smtp-user", password="test-only-password-742!",
                      clear_password=0)
        values.update(updates)
        return values

    def save(self, values):
        status, _, body = self.form("/api/smtp/settings", values)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["ok"])
        return body

    def key_path(self):
        return Path(str(self.db) + ".smtp.key")

    def test_save_retain_replace_clear_and_persist_without_exposing_secrets(self):
        self.start()
        self.assertEqual(self.state()["smtp"]["source"], "none")
        values = self.profile()
        secret = values["password"]
        response = self.save(values)
        state = self.state()
        smtp = state["smtp"]
        self.assertEqual(smtp["source"], "database")
        self.assertTrue(smtp["exists"] and smtp["password_set"])
        self.assertFalse(smtp["enabled"] or smtp["configured"] or state["delivery"]["configured"])
        self.assertEqual(smtp["host"], values["host"])
        self.assertEqual(smtp["from_email"], values["from_email"])
        self.assertNotIn("password", smtp)
        self.assertNotIn(secret, json.dumps(state))
        self.assertNotIn(secret.encode(), response)
        self.assertNotIn(secret.encode(), self.db.read_bytes())
        self.assertEqual(stat.S_IMODE(self.key_path().stat().st_mode), 0o600)
        self.assertEqual(len(self.key_path().read_bytes()), 32)
        with database(self.db) as connection:
            encrypted = connection.execute("SELECT password_cipher FROM smtp_settings").fetchone()[0]
        self.assertIsInstance(encrypted, bytes)
        self.assertNotIn(secret.encode(), encrypted)
        self.stop_server()
        self.start()
        self.assertTrue(self.state()["smtp"]["password_set"])
        # Blank means retain only the same endpoint and account; sender can change.
        self.save({**values, "password": "", "from_email": "renewals@example.test"})
        status, _, body = self.form("/api/smtp/settings", {**values, "host": "other.example.test", "password": ""})
        self.assertEqual(status, 400, body)
        self.assertEqual(self.state()["smtp"]["host"], values["host"])
        self.save({**values, "host": "other.example.test", "password": "replacement-test-only-93!"})
        self.assertTrue(self.state()["smtp"]["password_set"])
        self.save({**values, "host": "other.example.test", "password": "", "username": "", "clear_password": 1})
        state = self.state()
        self.assertFalse(state["smtp"]["password_set"])
        self.assertEqual(state["smtp"]["username"], "")
        self.assertEqual(state["outbox"], [])
        self.assertFalse(state["smtp"]["enabled"])

    def test_validation_csrf_and_connection_test_do_not_save_or_send(self):
        self.start()
        values = self.profile()
        status, _, body = self.form("/api/smtp/settings", values, csrf=False)
        self.assertEqual(status, 403, body)
        status, _, body = self.form("/api/smtp/test", values, method="POST", csrf=False)
        self.assertEqual(status, 403, body)
        for changes in ({"host": "smtp://example.test"}, {"host": "host/path"}, {"host": "user@host"},
                        {"host": "host\r\nInjected"}, {"port": 0}, {"port": 65536},
                        {"security": "none"}, {"from_email": "sender@example.test\r\nBcc: bad@example.test"},
                        {"username": "", "password": "orphan-secret"}, {"clear_password": 1}):
            with self.subTest(changes=changes):
                status, _, body = self.form("/api/smtp/settings", {**values, **changes})
                self.assertEqual(status, 400, body)
                self.assertNotIn(values["password"].encode(), body)
        self.assertEqual(self.state()["smtp"]["source"], "none")
        self.assertFalse(self.key_path().exists())
        # Keep a local port reserved without listening: the connection fails promptly.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            draft = self.profile(host="127.0.0.1", port=reserved.getsockname()[1], username="", password="")
            status, _, body = self.form("/api/smtp/test", draft, method="POST")
        self.assertEqual(status, 502, body)
        self.assertIn("error", json.loads(body))
        state = self.state()
        self.assertEqual(state["smtp"]["source"], "none")
        self.assertEqual(state["outbox"], [])
        self.assertFalse(self.key_path().exists())

    def test_database_disable_overrides_environment_configuration(self):
        environment = {"CERTIFICATI_SMTP_URL": "smtps://localhost:465", "CERTIFICATI_SMTP_FROM": "env@example.test",
                       "CERTIFICATI_SMTP_USERNAME": "env-user", "CERTIFICATI_SMTP_PASSWORD": "env-test-only-962"}
        with patch.dict(core.TEST_ENV, environment):
            self.start()
        state = self.state()
        self.assertEqual(state["smtp"]["source"], "environment")
        self.assertTrue(state["delivery"]["configured"])
        self.assertNotIn(environment["CERTIFICATI_SMTP_PASSWORD"], json.dumps(state))
        values = self.profile(enabled=0, host="localhost", port=465, security="tls", from_email="env@example.test",
                              username="env-user", password="")
        self.save(values)
        self.stop_server()
        with patch.dict(core.TEST_ENV, environment):
            self.start()
        state = self.state()
        self.assertEqual(state["smtp"]["source"], "database")
        self.assertTrue(state["smtp"]["password_set"])
        self.assertFalse(state["smtp"]["enabled"] or state["delivery"]["configured"])

    def test_missing_key_and_corrupted_ciphertext_fail_without_replacing_configuration(self):
        self.start()
        values = self.profile()
        self.save(values)
        self.stop_server()
        key = self.key_path().read_bytes()
        self.key_path().unlink()
        self.start()
        self.assertTrue(self.state()["smtp"]["password_set"])
        status, _, body = self.form("/api/delivery/process", {}, method="POST")
        self.assertEqual(status, 200, body)  # A paused profile never needs its secret.
        status, _, body = self.form("/api/smtp/settings", {**values, "password": ""})
        self.assertEqual(status, 400, body)
        self.assertFalse(self.key_path().exists(), "La chiave mancante non deve essere rigenerata per decifrare.")
        self.stop_server()
        self.key_path().write_bytes(key)
        self.key_path().chmod(0o600)
        with database(self.db) as connection:
            encrypted = connection.execute("SELECT password_cipher FROM smtp_settings").fetchone()[0]
            corrupt = bytearray(encrypted)
            corrupt[-1] ^= 1
            connection.execute("UPDATE smtp_settings SET password_cipher=?", (bytes(corrupt),))
        self.start()
        status, _, body = self.form("/api/smtp/settings", {**values, "password": ""})
        self.assertEqual(status, 400, body)
        self.assertNotIn(values["password"].encode(), body)
        with database(self.db) as connection:
            self.assertEqual(connection.execute("SELECT password_cipher FROM smtp_settings").fetchone()[0], bytes(corrupt))

    def test_schema_v3_upgrade_preserves_monitoring_and_certificate_records(self):
        self.start()
        self.stop_server()
        now = 1800000000
        with database(self.db) as connection:
            connection.execute("INSERT INTO certificates(fingerprint,common_name,subject,issuer,serial,sans,key_algorithm,"
                               "key_bits,signature_algorithm,is_ca,not_before,not_after,source,added_at) "
                               "VALUES('fixture-sha','service.example.test','','','1','','RSA',2048,'sha256',0,0,2500000000,'fixture',?)", (now,))
            connection.execute("INSERT INTO contacts VALUES(1,'business','Owner','owner@example.test')")
            connection.execute("INSERT INTO notifications VALUES(1,15,?)", (now,))
            connection.execute("INSERT INTO monitors(certificate_id,target,enabled,created_at,updated_at) "
                               "VALUES(1,'https://service.example.test:443',0,?,?)", (now, now))
            connection.execute("INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,created_at) "
                               "VALUES(1,'unreachable','Historical event','fixture-sha',?)", (now,))
            connection.execute("DROP TABLE smtp_settings")
            connection.execute("PRAGMA user_version=3")
        tables = ("certificates", "contacts", "notifications", "outbox", "monitors", "monitor_events")
        before = {table: self.rows(f"SELECT * FROM {table} ORDER BY rowid") for table in tables}
        self.start()
        self.assertEqual(self.rows("PRAGMA user_version")[0]["user_version"], 4)
        self.assertEqual(self.state()["smtp"]["source"], "none")
        for table in tables:
            self.assertEqual(self.rows(f"SELECT * FROM {table} ORDER BY rowid"), before[table], table)


if __name__ == "__main__":
    unittest.main(verbosity=2)
