#!/usr/bin/env python3
"""Persistent monitor tests using local TLS peers, temporary DBs and no SMTP."""

import json
from pathlib import Path
import socket
import sqlite3
import threading
import time
import unittest

import remote_integration as remote


class StallServer:
    """Accept TCP and hold it open without replying to the TLS ClientHello."""

    def __init__(self):
        self.stop = threading.Event()
        self.accepted = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted.set()
            self.stop.wait(20)
            client.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise AssertionError("Il peer TLS bloccato non si è arrestato.")


class MonitorIntegrationTests(unittest.TestCase):
    # Reuse only fixture/helper functions, without inheriting the remote tests.
    setUp = remote.RemoteAcquisitionTests.setUp
    tearDown = remote.RemoteAcquisitionTests.tearDown
    peer = remote.RemoteAcquisitionTests.peer
    start_application = remote.RemoteAcquisitionTests.start_application
    http = remote.RemoteAcquisitionTests.http
    form = remote.RemoteAcquisitionTests.form
    state = remote.RemoteAcquisitionTests.state
    check = remote.RemoteAcquisitionTests.check

    @classmethod
    def setUpClass(cls):
        source = remote.RemoteAcquisitionTests
        source.setUpClass()
        cls.root, cls.certificates = source.root, source.certificates
        directory = source.fixture_dir
        cls.renewed = directory / "renewed.pem"
        cls.renewed_chain = directory / "renewed-chain.pem"
        cls.renewed_key = directory / "second.key"
        remote.command(
            remote.OPENSSL, "x509", "-req", "-in", directory / "second.csr",
            "-CA", source.intermediate, "-CAkey", source.intermediate_key,
            "-set_serial", "99", "-days", "365", "-sha256", "-extfile", directory / "leaf.ext",
            "-out", cls.renewed,
        )
        cls.renewed_chain.write_bytes(cls.renewed.read_bytes() + source.intermediate.read_bytes())

    @classmethod
    def tearDownClass(cls):
        remote.RemoteAcquisitionTests.tearDownClass()

    def wait(self, predicate, timeout=7):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.state()
            if predicate(last):
                return last
            time.sleep(0.1)
        self.fail(f"Stato atteso non raggiunto entro {timeout}s: {last}")

    def monitor(self, monitor_id, state=None):
        state = self.state() if state is None else state
        return next(item for item in state["monitors"] if item["id"] == monitor_id)

    def upload_baseline(self):
        chain = self.certificates["first"][2].read_bytes()
        status, _, body = self.http("POST", "/api/certificates", chain, {
            "Content-Type": "application/octet-stream", "X-Filename": "baseline.pem",
            "X-CSRF-Token": self.token,
        })
        self.assertEqual(status, 200, body)
        state = self.state()
        self.assertEqual(state["monitors"], [])
        return next(cert for cert in state["certificates"] if not cert["is_ca"])

    def create_monitor(self, certificate_id, target, enabled=1, interval=None):
        fields = {"certificate_id": certificate_id, "target": target, "enabled": enabled}
        if interval is not None:
            fields["interval_minutes"] = interval
        status, _, body = self.form("/api/monitors", fields)
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertTrue(result["ok"])
        return result["monitor_id"]

    def edit_monitor(self, monitor_id, **changes):
        current = self.monitor(monitor_id)
        fields = {
            "certificate_id": current["certificate_id"], "target": current["target"],
            "enabled": current["enabled"], "interval_minutes": current["interval_seconds"] // 60,
        }
        fields.update(changes)
        status, _, body = self.form(f"/api/monitors/{monitor_id}", fields, method="PUT")
        self.assertEqual(status, 200, body)
        return self.monitor(monitor_id)

    def force_check(self, monitor_id, expected):
        old = self.monitor(monitor_id)
        checked = old["last_checked_at"] or 0
        # Avoid comparing two integer timestamps from the same clock second.
        while int(time.time()) <= checked:
            time.sleep(0.03)
        status, _, body = self.form(f"/api/monitors/{monitor_id}/check", {})
        self.assertEqual(status, 200, body)
        state = self.wait(lambda state: (
            self.monitor(monitor_id, state)["last_status"] == expected
            and (self.monitor(monitor_id, state)["last_checked_at"] or 0) > checked
            and not self.monitor(monitor_id, state)["claim_until"]
        ))
        return state

    def stop_application(self):
        self.application.terminate()
        self.application.wait(timeout=5)
        self.application = None
        self.application_log.close()
        self.application_log = None

    def test_change_recovery_unreachable_dedup_ack_and_persistence(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        monitor_id = self.create_monitor(certificate["id"], f"https://LOCALHOST:{peer.port}/ignored?query=1")
        state = self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok")
        monitor = self.monitor(monitor_id, state)
        self.assertEqual(monitor["target"], f"https://localhost:{peer.port}")
        self.assertEqual(monitor["interval_seconds"], 900)
        self.assertTrue(monitor["enabled"] and monitor["verified"])
        self.assertTrue(monitor["dns_ok"] and monitor["tcp_ok"] and monitor["tls_ok"])
        self.assertEqual(remote.normalized_fingerprint(monitor["last_fingerprint"]),
                         remote.normalized_fingerprint(certificate["fingerprint"]))
        self.assertEqual(state["monitor_events"], [])
        _, key, chain = self.certificates["second"]
        peer.replace_certificate(chain, key)
        state = self.force_check(monitor_id, "changed")
        events = state["monitor_events"]
        self.assertEqual([event["kind"] for event in events], ["changed"])
        self.assertNotEqual(events[0]["expected_fingerprint"], events[0]["observed_fingerprint"])
        state = self.force_check(monitor_id, "changed")
        self.assertEqual(len(state["monitor_events"]), 1)
        peer.replace_certificate(self.renewed_chain, self.renewed_key)
        state = self.force_check(monitor_id, "changed")
        changed_events = [event for event in state["monitor_events"] if event["kind"] == "changed"]
        self.assertEqual(len(changed_events), 2)
        self.assertEqual(len({event["observed_fingerprint"] for event in changed_events}), 2)
        _, key, chain = self.certificates["first"]
        peer.replace_certificate(chain, key)
        state = self.force_check(monitor_id, "ok")
        self.assertEqual({event["kind"] for event in state["monitor_events"]}, {"changed", "recovered"})
        peer.close()
        self.servers.remove(peer)
        state = self.force_check(monitor_id, "unreachable")
        event_count = len(state["monitor_events"])
        self.assertEqual(event_count, 4)
        self.assertEqual(len([event for event in state["monitor_events"] if event["kind"] == "unreachable"]), 1)
        state = self.force_check(monitor_id, "unreachable")
        self.assertEqual(len(state["monitor_events"]), event_count)
        event_id = next(event["id"] for event in state["monitor_events"] if event["kind"] == "unreachable")
        status, _, body = self.form(f"/api/monitor-events/{event_id}/ack", {})
        self.assertEqual(status, 200, body)
        self.assertTrue(next(event for event in self.state()["monitor_events"] if event["id"] == event_id)["acknowledged_at"])
        self.edit_monitor(monitor_id, enabled=0)
        status, _, body = self.form(f"/api/monitors/{monitor_id}/check", {})
        self.assertEqual(status, 400, body)
        self.stop_application()
        self.start_application()
        state = self.state()
        self.assertFalse(self.monitor(monitor_id, state)["enabled"])
        self.assertEqual(len(state["monitor_events"]), event_count)
        self.assertTrue(next(event for event in state["monitor_events"] if event["id"] == event_id)["acknowledged_at"])
        self.assertFalse(state["delivery"]["configured"])
        self.assertEqual(state["outbox"], [])

    def test_tls_and_certificate_verification_failures_are_distinct(self):
        peer = self.peer()
        plaintext = self.peer(plaintext=True)
        self.start_application()
        certificate = self.upload_baseline()
        # The expected certificate is served, but its SAN only permits localhost.
        monitor_id = self.create_monitor(certificate["id"], f"127.0.0.1:{peer.port}")
        state = self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "verification_error"
                          and not self.monitor(monitor_id, state)["claim_until"])
        monitor = self.monitor(monitor_id, state)
        self.assertTrue(monitor["dns_ok"] and monitor["tcp_ok"] and monitor["tls_ok"])
        self.assertFalse(monitor["verified"])
        self.assertEqual([event["kind"] for event in state["monitor_events"]], ["verification_error"])
        state = self.force_check(monitor_id, "verification_error")
        self.assertEqual(len(state["monitor_events"]), 1)
        self.edit_monitor(monitor_id, target=f"127.0.0.1:{plaintext.port}")
        state = self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "tls_error"
                          and not self.monitor(monitor_id, state)["claim_until"])
        monitor = self.monitor(monitor_id, state)
        self.assertTrue(monitor["dns_ok"] and monitor["tcp_ok"])
        self.assertFalse(monitor["tls_ok"] or monitor["verified"])
        self.assertEqual({event["kind"] for event in state["monitor_events"]}, {"verification_error", "tls_error"})
        state = self.force_check(monitor_id, "tls_error")
        self.assertEqual(len(state["monitor_events"]), 2)

    def test_automatic_due_check_without_manual_post(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        monitor_id = self.create_monitor(certificate["id"], f"localhost:{peer.port}")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok"
                  and not self.monitor(monitor_id, state)["claim_until"])
        previous_connections = peer.connections
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE monitors SET next_check_at=? WHERE id=?", (int(time.time()) - 1, monitor_id))
        self.wait(lambda state: peer.connections > previous_connections
                  and self.monitor(monitor_id, state)["last_status"] == "ok"
                  and not self.monitor(monitor_id, state)["claim_until"])
        self.assertEqual(self.state()["monitor_events"], [])
        self.assertEqual(peer.received, [])

    def test_remote_import_starts_monitor_and_preserves_paused_duplicate(self):
        peer = self.peer()
        self.start_application()
        checked = self.check(f"localhost:{peer.port}")
        status, _, body = self.form("/api/remote/import", {"token": checked["token"]})
        self.assertEqual(status, 200, body)
        certificate_id = json.loads(body)["certificate_id"]
        state = self.state()
        self.assertEqual(len(state["monitors"]), 1)
        monitor = state["monitors"][0]
        self.assertEqual(monitor["certificate_id"], certificate_id)
        self.assertEqual(monitor["interval_seconds"], 900)
        self.assertTrue(monitor["enabled"])
        paused = self.edit_monitor(monitor["id"], enabled=0)
        status, _, body = self.form("/api/remote/import", {"token": checked["token"]})
        self.assertEqual(status, 200, body)
        state = self.state()
        self.assertEqual(len(state["monitors"]), 1)
        self.assertFalse(state["monitors"][0]["enabled"])
        self.assertEqual(state["monitors"][0]["revision"], paused["revision"])

    def test_validation_csrf_and_delete(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        values = {"certificate_id": certificate["id"], "target": f"localhost:{peer.port}", "enabled": 0}
        status, _, body = self.form("/api/monitors", values, csrf=False)
        self.assertEqual(status, 403, body)
        for changes in ({"target": "http://localhost"}, {"target": "*.example.test"},
                        {"target": "https://user:password@localhost"}, {"target": "localhost:65536"},
                        {"interval_minutes": 0}, {"interval_minutes": 1441}, {"interval_minutes": "1.5"}):
            with self.subTest(changes=changes):
                status, _, body = self.form("/api/monitors", {**values, **changes})
                self.assertEqual(status, 400, body)
        monitor_id = self.create_monitor(certificate["id"], values["target"], enabled=0, interval=1)
        self.assertEqual(self.monitor(monitor_id)["interval_seconds"], 60)
        status, _, body = self.form("/api/monitors", {**values, "target": f"https://LOCALHOST:{peer.port}/ignored"})
        self.assertEqual(status, 400, body)
        self.assertEqual(len(self.state()["monitors"]), 1)
        ca_id = next(cert["id"] for cert in self.state()["certificates"] if cert["is_ca"])
        status, _, body = self.form("/api/monitors", {**values, "certificate_id": ca_id})
        self.assertEqual(status, 400, body)
        status, _, body = self.form(f"/api/monitors/{monitor_id}", {}, method="DELETE")
        self.assertEqual(status, 200, body)
        self.assertEqual(self.state()["monitors"], [])
        self.assertEqual(peer.connections, 0)

    def test_tls_stall_keeps_ui_responsive_and_ignores_stale_result(self):
        self.start_application()
        certificate = self.upload_baseline()
        stalled = StallServer()
        self.servers.append(stalled)
        monitor_id = self.create_monitor(certificate["id"], f"127.0.0.1:{stalled.port}")
        self.assertTrue(stalled.accepted.wait(timeout=6), "Il monitor non ha avviato il collegamento TCP.")
        started = time.monotonic()
        state = self.state()
        self.assertLess(time.monotonic() - started, 2, "L'acquisizione TLS blocca l'interfaccia web.")
        old_revision = self.monitor(monitor_id, state)["revision"]
        paused = self.edit_monitor(monitor_id, enabled=0)
        self.assertGreater(paused["revision"], old_revision)
        stalled.close()
        self.servers.remove(stalled)
        # Closing the peer completes the old child after the configuration edit.
        time.sleep(2.2)
        state = self.state()
        current = self.monitor(monitor_id, state)
        self.assertFalse(current["enabled"])
        self.assertEqual(current["revision"], paused["revision"])
        self.assertEqual(current["last_status"], paused["last_status"])
        self.assertEqual(current["last_checked_at"], paused["last_checked_at"])
        self.assertEqual(state["monitor_events"], [])

    def test_renewal_keeps_previous_until_verified_deployment(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        monitor_id = self.create_monitor(certificate["id"], f"localhost:{peer.port}")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok")
        revision = self.monitor(monitor_id)["revision"]
        status, _, body = self.http("POST", f"/api/certificates/{certificate['id']}/renew", self.renewed_chain.read_bytes(), {
            "Content-Type": "application/octet-stream", "X-Filename": "renewed.pem", "X-CSRF-Token": self.token,
        })
        self.assertEqual(status, 200, body)
        new_id = json.loads(body)["certificate_id"]
        state = self.state()
        job = next(item for item in state["renewal_jobs"] if item["new_certificate_id"] == new_id)
        current = self.monitor(monitor_id)
        self.assertEqual(current["certificate_id"], certificate["id"])
        self.assertEqual(current["revision"], revision)
        self.assertEqual(remote.normalized_fingerprint(current["expected_fingerprint"]),
                         remote.normalized_fingerprint(certificate["fingerprint"]))
        self.assertFalse(next(cert for cert in state["certificates"] if cert["id"] == certificate["id"])["archived"])
        # Signing a replacement does not install it or invalidate the old peer.
        state = self.force_check(monitor_id, "ok")
        self.assertEqual(state["monitor_events"], [])
        # The authorization covers only the explicitly linked new fingerprint.
        _, unknown_key, unknown_chain = self.certificates["second"]
        peer.replace_certificate(unknown_chain, unknown_key)
        self.force_check(monitor_id, "changed")
        peer.replace_certificate(self.renewed_chain, self.renewed_key)
        state = self.force_check(monitor_id, "ok")
        self.assertIn("recovered", {event["kind"] for event in state["monitor_events"]})
        self.assertEqual(self.monitor(monitor_id, state)["certificate_id"], certificate["id"])
        # A fresh installation request is required before closing the renewal.
        status, _, body = self.form(f"/api/renewal-jobs/{job['id']}/complete", {})
        self.assertEqual(status, 400, body)
        status, _, body = self.form(f"/api/renewal-jobs/{job['id']}/check-install", {"monitor_id": monitor_id})
        self.assertEqual(status, 200, body)
        self.wait(lambda state: any(endpoint["job_id"] == job["id"] and endpoint["verified_at"]
                                    for endpoint in state["renewal_endpoints"]))
        status, _, body = self.form(f"/api/renewal-jobs/{job['id']}/complete", {})
        self.assertEqual(status, 200, body)
        state = self.state()
        current = self.monitor(monitor_id, state)
        self.assertEqual(current["certificate_id"], new_id)
        self.assertGreater(current["revision"], revision)
        self.assertEqual(remote.normalized_fingerprint(current["expected_fingerprint"]),
                         remote.fingerprint(self.renewed.read_text()))
        self.assertTrue(next(cert for cert in state["certificates"] if cert["id"] == certificate["id"])["archived"])

    def test_configurable_email_alerts_queue_only_new_faults_and_recoveries(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        monitor_id = self.create_monitor(certificate["id"], f"localhost:{peer.port}")
        state = self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok")
        self.assertFalse(self.monitor(monitor_id, state)["email_alerts"])
        # Existing installations do not suddenly start sending notifications.
        _, other_key, other_chain = self.certificates["second"]
        peer.replace_certificate(other_chain, other_key)
        self.force_check(monitor_id, "changed")
        self.assertEqual(self.state()["outbox"], [])
        self.edit_monitor(monitor_id, email_alerts=1,
                          email_recipients="owner@example.test; tech@example.test\nOWNER@example.test")
        state = self.state()
        self.assertEqual({row["email"].lower() for row in state["monitor_mail"] if row["monitor_id"] == monitor_id},
                         {"owner@example.test", "tech@example.test"})
        # Enabling alerts does not replay historical faults.
        self.assertEqual(state["outbox"], [])
        _, original_key, original_chain = self.certificates["first"]
        peer.replace_certificate(original_chain, original_key)
        state = self.force_check(monitor_id, "ok")
        alerts = [item for item in state["outbox"] if item["kind"] == "monitor"]
        self.assertEqual(len(alerts), 2)
        self.assertEqual(len({item["event_id"] for item in alerts}), 1)
        peer.replace_certificate(other_chain, other_key)
        state = self.force_check(monitor_id, "changed")
        alerts = [item for item in state["outbox"] if item["kind"] == "monitor"]
        self.assertEqual(len(alerts), 4)
        self.assertEqual(len({item["event_id"] for item in alerts}), 2)
        state = self.force_check(monitor_id, "changed")
        self.assertEqual(len([item for item in state["outbox"] if item["kind"] == "monitor"]), 4)
        self.assertFalse(state["delivery"]["configured"])
        self.assertTrue(all(item["status"] == "pending" and item["attempts"] == 0 for item in state["outbox"]))
        # Editing certificate contacts cannot delete independent monitor mail.
        status, _, body = self.form(f"/api/certificates/{certificate['id']}/contacts", {
            "role": "technical", "name": "Another technician", "email": "another@example.test",
        }, method="PUT")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.state()["outbox"]), 4)
        self.edit_monitor(monitor_id, email_alerts=0, email_recipients="owner@example.test;tech@example.test")
        status, _, body = self.form("/api/delivery/process", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.state()["outbox"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
