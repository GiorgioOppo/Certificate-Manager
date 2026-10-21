#!/usr/bin/env python3
"""Overlapping renewals and fresh per-endpoint deployment verification."""

import json
import sqlite3
import time
import unittest
from urllib.parse import urlencode

import monitor_integration as monitoring
import remote_integration as remote


class LifecycleIntegrationTests(unittest.TestCase):
    # Share local TLS fixtures and HTTP helpers without inheriting their tests.
    setUp = monitoring.MonitorIntegrationTests.setUp
    tearDown = monitoring.MonitorIntegrationTests.tearDown
    peer = monitoring.MonitorIntegrationTests.peer
    start_application = monitoring.MonitorIntegrationTests.start_application
    http = monitoring.MonitorIntegrationTests.http
    form = monitoring.MonitorIntegrationTests.form
    state = monitoring.MonitorIntegrationTests.state
    wait = monitoring.MonitorIntegrationTests.wait
    monitor = monitoring.MonitorIntegrationTests.monitor
    create_monitor = monitoring.MonitorIntegrationTests.create_monitor
    edit_monitor = monitoring.MonitorIntegrationTests.edit_monitor
    force_check = monitoring.MonitorIntegrationTests.force_check
    upload_baseline = monitoring.MonitorIntegrationTests.upload_baseline

    @classmethod
    def setUpClass(cls):
        monitoring.MonitorIntegrationTests.setUpClass()
        source = monitoring.MonitorIntegrationTests
        cls.root, cls.certificates = source.root, source.certificates
        cls.renewed, cls.renewed_chain, cls.renewed_key = source.renewed, source.renewed_chain, source.renewed_key
        fixture = remote.RemoteAcquisitionTests
        cls.third = fixture.fixture_dir / "third.pem"
        cls.third_chain = fixture.fixture_dir / "third-chain.pem"
        remote.command(remote.OPENSSL, "x509", "-req", "-in", fixture.fixture_dir / "second.csr",
                       "-CA", fixture.intermediate, "-CAkey", fixture.intermediate_key,
                       "-set_serial", "101", "-days", "730", "-sha256",
                       "-extfile", fixture.fixture_dir / "leaf.ext", "-out", cls.third)
        cls.third_chain.write_bytes(cls.third.read_bytes() + fixture.intermediate.read_bytes())

    @classmethod
    def tearDownClass(cls):
        monitoring.MonitorIntegrationTests.tearDownClass()

    def renew(self, old_id, chain=None):
        status, _, body = self.http("POST", f"/api/certificates/{old_id}/renew",
                                   (chain or self.renewed_chain).read_bytes(), {
                                       "Content-Type": "application/octet-stream", "X-CSRF-Token": self.token,
                                   })
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        state = self.state()
        job = next(item for item in state["renewal_jobs"]
                   if item["old_certificate_id"] == old_id and item["new_certificate_id"] == result["certificate_id"])
        return result["certificate_id"], job["id"]

    def action(self, job_id, action, fields=None, expected=200):
        status, _, body = self.form(f"/api/renewal-jobs/{job_id}/{action}", fields or {})
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def certificate(self, cert_id, state=None):
        return next(item for item in (state or self.state())["certificates"] if item["id"] == cert_id)

    def test_multiple_valid_renewals_leave_previous_contacts_monitors_and_reminders_active(self):
        peer = self.peer()
        self.start_application()
        old = self.upload_baseline()
        monitor_id = self.create_monitor(old["id"], f"localhost:{peer.port}")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok")
        data = urlencode([("role", "business"), ("name", "Owner"), ("email", "owner@example.test"),
                          ("role", "technical"), ("name", "Operator"), ("email", "operator@example.test")]).encode()
        status, _, body = self.http("PUT", f"/api/certificates/{old['id']}/contacts", data, {
            "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": self.token,
        })
        self.assertEqual(status, 200, body)
        # Existing reminders must survive signing a replacement.
        with sqlite3.connect(self.db) as db:
            now = int(time.time())
            db.execute("INSERT OR IGNORE INTO notifications(certificate_id,threshold,sent_at) VALUES(?,45,?)", (old["id"], now))
            db.execute("INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,created_at) VALUES(?,'expiry','Owner','owner@example.test',45,'Existing reminder','Pending reminder',?)", (old["id"], now))
        new_id, job_id = self.renew(old["id"])
        third_id, third_job = self.renew(old["id"], self.third_chain)
        self.assertNotEqual(job_id, third_job)
        state = self.state()
        self.assertEqual(len([cert for cert in state["certificates"] if not cert["is_ca"]]), 3)
        for cert_id in (old["id"], new_id, third_id):
            cert = self.certificate(cert_id, state)
            self.assertFalse(cert["archived"])
            self.assertIsNone(cert["superseded_by"])
            self.assertEqual(len(cert["contacts"]), 2)
        self.assertEqual(self.certificate(new_id, state)["operational_status"], "ready")
        self.assertEqual(self.monitor(monitor_id, state)["certificate_id"], old["id"])
        self.assertTrue(any(item["certificate_id"] == old["id"] and item["kind"] == "expiry" for item in state["outbox"]))
        self.assertEqual(len([item for item in state["outbox"] if item["kind"] == "certificate"]), 2)
        peer.replace_certificate(self.renewed_chain, self.renewed_key)
        state = self.force_check(monitor_id, "ok")
        self.assertFalse(any(event["kind"] == "changed" for event in state["monitor_events"]))
        self.assertEqual(self.monitor(monitor_id, state)["certificate_id"], old["id"])
        self.action(job_id, "complete", expected=400)  # An automatic match is not an explicit installation verification.

    def test_completion_requires_fresh_tls_verified_new_certificate_on_every_endpoint(self):
        first, second = self.peer(), self.peer()
        self.start_application()
        old = self.upload_baseline()
        ids = [self.create_monitor(old["id"], f"localhost:{peer.port}") for peer in (first, second)]
        self.wait(lambda state: all(self.monitor(mid, state)["last_status"] == "ok" for mid in ids))
        new_id, job_id = self.renew(old["id"])
        self.action(job_id, "complete", expected=400)
        first.replace_certificate(self.renewed_chain, self.renewed_key)
        self.action(job_id, "check-install")
        self.wait(lambda state: any(e["job_id"] == job_id and e["monitor_id"] == ids[0] and e["verified_at"] for e in state["renewal_endpoints"]))
        self.action(job_id, "complete", expected=400)
        self.assertFalse(self.certificate(old["id"])["archived"])
        second.replace_certificate(self.renewed_chain, self.renewed_key)
        self.action(job_id, "check-install", {"monitor_id": ids[1]})
        self.wait(lambda state: all(e["verified_at"] for e in state["renewal_endpoints"] if e["job_id"] == job_id))
        # A once-successful verification that has aged out cannot close the renewal.
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE renewal_endpoints SET verified_at=? WHERE job_id=?", (int(time.time()) - 1800, job_id))
        self.action(job_id, "complete", expected=400)
        self.action(job_id, "check-install")
        self.wait(lambda state: all(e["verified_at"] for e in state["renewal_endpoints"] if e["job_id"] == job_id))
        self.action(job_id, "complete")
        state = self.state()
        self.assertTrue(self.certificate(old["id"], state)["archived"])
        self.assertEqual(self.certificate(old["id"], state)["superseded_by"], new_id)
        self.assertTrue(all(self.monitor(mid, state)["certificate_id"] == new_id for mid in ids))
        self.assertEqual(next(j for j in state["renewal_jobs"] if j["id"] == job_id)["status"], "verified")

    def test_zero_endpoints_requires_explicit_retirement_and_plan_is_reused(self):
        self.start_application()
        old = self.upload_baseline()
        now = int(time.time())
        fields = {"old_certificate_id": old["id"], "status": "awaiting_ca", "requested_at": now,
                  "planned_renewal_at": now + 86400, "planned_install_at": now + 172800,
                  "responsible": "Operator", "notes": "Retire the old offline certificate after manual inventory review."}
        status, _, body = self.form("/api/renewal-jobs", fields)
        self.assertEqual(status, 200, body)
        plan_id = json.loads(body)["job_id"]
        new_id, job_id = self.renew(old["id"])
        self.assertEqual(job_id, plan_id)
        self.action(job_id, "complete", expected=400)
        self.action(job_id, "check-install", expected=400)
        self.assertFalse(self.certificate(old["id"])["archived"])
        self.action(job_id, "retire")
        state = self.state()
        self.assertTrue(self.certificate(old["id"], state)["archived"])
        job = next(j for j in state["renewal_jobs"] if j["id"] == job_id)
        self.assertEqual(job["status"], "retired")
        self.assertEqual(job["planned_install_at"], fields["planned_install_at"])
        self.assertEqual(job["new_certificate_id"], new_id)

    def test_approved_certificate_without_trusted_tls_cannot_verify_installation(self):
        peer = self.peer()
        self.start_application(trusted=False)
        old = self.upload_baseline()
        monitor_id = self.create_monitor(old["id"], f"localhost:{peer.port}")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "verification_error")
        _, job_id = self.renew(old["id"])
        peer.replace_certificate(self.renewed_chain, self.renewed_key)
        self.action(job_id, "check-install")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "verification_error" and self.monitor(monitor_id, state)["last_checked_at"])
        state = self.state()
        self.assertFalse(next(e for e in state["renewal_endpoints"] if e["job_id"] == job_id)["verified_at"])
        self.action(job_id, "complete", expected=400)
        self.assertFalse(self.certificate(old["id"])["archived"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
