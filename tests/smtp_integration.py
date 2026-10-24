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


def legacy_layout(connection, version):
    """Recreate empty v3/v4 tables using their historical DDL (SQLite >=3.24)."""
    assert version in (3, 4)
    core.remove_workflow_v6(connection)
    for table in ("directory_assignments", "certificate_groups", "directory_memberships",
                  "directory_groups", "directory_people", "renewal_endpoints", "renewal_jobs",
                  "reminder_policies", "monitor_recipients"):
        connection.execute(f"DROP TABLE {table}")
    if version == 3:
        connection.execute("DROP TABLE smtp_settings")
    for table in ("outbox", "monitor_events", "monitors", "notifications"):
        connection.execute(f"DROP TABLE {table}")
    connection.execute("CREATE TABLE monitors (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                       "target TEXT NOT NULL,interval_seconds INTEGER NOT NULL DEFAULT 900 "
                       "CHECK(interval_seconds BETWEEN 60 AND 86400),enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
                       "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),next_check_at INTEGER NOT NULL DEFAULT 0,"
                       "last_checked_at INTEGER,last_status TEXT NOT NULL DEFAULT 'pending' CHECK(last_status IN"
                       "('pending','ok','unreachable','tls_error','changed','verification_error','error')),"
                       "last_error TEXT NOT NULL DEFAULT '',last_fingerprint TEXT NOT NULL DEFAULT '',"
                       "last_address TEXT NOT NULL DEFAULT '',dns_ok INTEGER NOT NULL DEFAULT 0,"
                       "tcp_ok INTEGER NOT NULL DEFAULT 0,tls_ok INTEGER NOT NULL DEFAULT 0,"
                       "verified INTEGER NOT NULL DEFAULT 0,claim_until INTEGER NOT NULL DEFAULT 0,"
                       "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(certificate_id,target))")
    connection.execute("CREATE INDEX monitors_due ON monitors(enabled,next_check_at,claim_until)")
    connection.execute("CREATE TABLE monitor_events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,"
                       "kind TEXT NOT NULL CHECK(kind IN"
                       "('unreachable','tls_error','changed','verification_error','error','recovered')),"
                       "message TEXT NOT NULL,expected_fingerprint TEXT NOT NULL,"
                       "observed_fingerprint TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,acknowledged_at INTEGER)")
    connection.execute("CREATE INDEX monitor_events_recent ON monitor_events(created_at,id)")
    connection.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                       "kind TEXT NOT NULL CHECK(kind IN('expiry','certificate')),"
                       "recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL,threshold INTEGER NOT NULL DEFAULT -1,"
                       "subject TEXT NOT NULL,body TEXT NOT NULL,attachment_pem TEXT NOT NULL DEFAULT '',"
                       "status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','failed')),"
                       "attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,"
                       "sent_at INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0,UNIQUE(certificate_id,kind,recipient_email,threshold))")
    connection.execute("CREATE TABLE notifications(certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                       "threshold INTEGER NOT NULL CHECK(threshold IN(45,30,15,2,0)),sent_at INTEGER NOT NULL,"
                       "PRIMARY KEY(certificate_id,threshold))")
    connection.execute(f"PRAGMA user_version={version}")


def legacy_records(connection, now):
    connection.execute("INSERT INTO certificates(fingerprint,common_name,subject,issuer,serial,sans,key_algorithm,"
                       "key_bits,signature_algorithm,is_ca,not_before,not_after,source,added_at) "
                       "VALUES('fixture-sha','service.example.test','','','1','','RSA',2048,'sha256',0,0,2500000000,'fixture',?)", (now,))
    connection.execute("INSERT INTO contacts VALUES(1,'business','Owner','owner@example.test')")
    connection.execute("INSERT INTO contacts VALUES(1,'technical','Operations','ops@example.test')")
    connection.execute("INSERT INTO notifications VALUES(1,15,?)", (now,))
    connection.execute("INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,"
                       "status,attempts,created_at,sent_at) VALUES(1,'expiry','Owner','owner@example.test',15,"
                       "'Historical reminder','Original text','sent',1,?,?)", (now, now))
    connection.execute("INSERT INTO monitors(certificate_id,target,enabled,created_at,updated_at) "
                       "VALUES(1,'https://service.example.test:443',0,?,?)", (now, now))
    connection.execute("INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,created_at) "
                       "VALUES(1,'unreachable','Historical event','fixture-sha',?)", (now,))


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
            # Rebuild the historical schema, removing both v5 and v6 additions.
            legacy_layout(connection, 3)
            legacy_records(connection, now)
        tables = ("certificates", "contacts", "notifications", "outbox", "monitors", "monitor_events")
        columns = {table: [row["name"] for row in self.rows(f"PRAGMA table_info({table})")] for table in tables}
        before = {table: self.rows(f"SELECT * FROM {table} ORDER BY rowid") for table in tables}
        self.start()
        self.assertEqual(self.rows("PRAGMA user_version")[0]["user_version"], 7)
        self.assertEqual(self.state()["smtp"]["source"], "none")
        for table in tables:
            legacy_columns = ",".join(columns[table])
            self.assertEqual(self.rows(f"SELECT {legacy_columns} FROM {table} ORDER BY rowid"), before[table], table)
        self.assertEqual(self.rows("SELECT email_alerts FROM monitors"), [{"email_alerts": 0}])
        self.assertEqual(self.rows("SELECT event_id FROM outbox"), [{"event_id": None}])
        self.assertEqual(self.state()["monitor_mail"], [])


    def test_schema_v4_upgrade_preserves_smtp_secret_queue_and_monitoring(self):
        self.start()
        profile = self.profile()
        self.save(profile)  # Paused configuration: no SMTP connection or email.
        self.stop_server()
        key_before = self.key_path().read_bytes()
        mode_before = stat.S_IMODE(self.key_path().stat().st_mode)
        with database(self.db) as connection:
            legacy_layout(connection, 4)
            legacy_records(connection, 1800000000)
            connection.execute("INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,"
                               "attachment_pem,status,attempts,last_error,created_at,next_attempt) "
                               "VALUES(1,'certificate','Operations','ops@example.test',-1,'Public certificate','Original body',"
                               "'Public fixture','failed',2,'Historical SMTP failure',1800000000,2500000000)")
        tables = ("certificates", "contacts", "notifications", "outbox", "monitors", "monitor_events", "smtp_settings")
        columns = {table: [row["name"] for row in self.rows(f"PRAGMA table_info({table})")] for table in tables}
        before = {table: self.rows(f"SELECT * FROM {table} ORDER BY rowid") for table in tables}
        self.start()
        self.assertEqual(self.rows("PRAGMA user_version")[0]["user_version"], 7)
        for table in tables:
            self.assertEqual(self.rows(f"SELECT {','.join(columns[table])} FROM {table} ORDER BY rowid"), before[table], table)
        self.assertEqual(self.key_path().read_bytes(), key_before)
        self.assertEqual(stat.S_IMODE(self.key_path().stat().st_mode), mode_before)
        self.assertEqual(self.rows("SELECT email_alerts FROM monitors"), [{"email_alerts": 0}])
        self.assertEqual(self.rows("SELECT event_id FROM outbox ORDER BY id"), [{"event_id": None}, {"event_id": None}])
        self.assertEqual(self.rows("PRAGMA foreign_key_check"), [])
        smtp = self.state()["smtp"]
        self.assertEqual(smtp["source"], "database")
        self.assertTrue(smtp["password_set"])
        self.assertFalse(smtp["enabled"])
        # Retaining the secret requires successfully decrypting the migrated blob.
        self.save({**profile, "password": ""})
        self.assertEqual(self.key_path().read_bytes(), key_before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
