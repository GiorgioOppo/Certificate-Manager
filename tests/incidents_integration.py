#!/usr/bin/env python3
"""Incident claims, failure confirmation and maintenance on isolated localhost peers."""
import json
import time
import unittest
import monitor_integration as monitors
import remote_integration as remote


class IncidentIntegrationTests(unittest.TestCase):
    setUp = monitors.MonitorIntegrationTests.setUp
    tearDown = monitors.MonitorIntegrationTests.tearDown
    peer = monitors.MonitorIntegrationTests.peer
    start_application = monitors.MonitorIntegrationTests.start_application
    http = monitors.MonitorIntegrationTests.http
    form = monitors.MonitorIntegrationTests.form
    state = monitors.MonitorIntegrationTests.state
    check = monitors.MonitorIntegrationTests.check
    wait = monitors.MonitorIntegrationTests.wait
    monitor = monitors.MonitorIntegrationTests.monitor
    upload_baseline = monitors.MonitorIntegrationTests.upload_baseline
    create_monitor = monitors.MonitorIntegrationTests.create_monitor
    edit_monitor = monitors.MonitorIntegrationTests.edit_monitor
    force_check = monitors.MonitorIntegrationTests.force_check

    @classmethod
    def setUpClass(cls):
        remote.RemoteAcquisitionTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        remote.RemoteAcquisitionTests.tearDownClass.__func__(cls)

    def incidents(self):
        status, _, body = self.http("GET", "/api/incidents/state")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def options(self, monitor_id, **values):
        fields = {"monitor_id": monitor_id, "failure_threshold": 3}
        fields.update(values)
        status, _, body = self.form("/api/incidents/monitor-options", fields)
        self.assertEqual(status, 200, body)

    def setup_monitor(self):
        peer = self.peer()
        self.start_application()
        certificate = self.upload_baseline()
        monitor_id = self.create_monitor(certificate["id"], f"https://localhost:{peer.port}")
        self.wait(lambda state: self.monitor(monitor_id, state)["last_status"] == "ok")
        self.edit_monitor(monitor_id, email_alerts=1, email_recipients="ops@example.test")
        return peer, monitor_id

    def test_confirmation_claim_does_not_recover_or_acknowledge(self):
        peer, monitor_id = self.setup_monitor()
        self.options(monitor_id)
        self.force_check(monitor_id, "ok")
        peer.close()
        self.servers.remove(peer)
        state = self.force_check(monitor_id, "unreachable")
        event = next(item for item in state["monitor_events"] if item["kind"] == "unreachable")
        self.assertEqual(state["outbox"], [])
        state = self.force_check(monitor_id, "unreachable")
        self.assertEqual(state["outbox"], [])
        state = self.force_check(monitor_id, "unreachable")
        self.assertEqual(len(state["outbox"]), 1)
        state = self.force_check(monitor_id, "unreachable")
        self.assertEqual(len(state["outbox"]), 1)
        status, _, body = self.form(f"/api/incidents/events/{event['id']}/claim", {
            "responsible": "Operatore Test", "notes": "Preso in carico\nVerifica rete",
            "due_at": int(time.time()) + 3600, "status": "resolved",
        })
        self.assertEqual(status, 200, body)
        state = self.state()
        self.assertEqual(self.monitor(monitor_id, state)["last_status"], "unreachable")
        self.assertFalse(next(item for item in state["monitor_events"] if item["id"] == event["id"])["acknowledged_at"])
        self.assertFalse(any(item["kind"] == "recovered" for item in state["monitor_events"]))
        claims = self.incidents()["claims"]
        self.assertEqual(claims[0]["responsible"], "Operatore Test")
        self.assertEqual(claims[0]["status"], "resolved")
        status, _, body = self.http("GET", f"/api/incidents/events/{event['id']}")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["events"][0]["last_status"], "unreachable")

    def test_maintenance_keeps_observations_and_alerts_once_after_expiry(self):
        peer, monitor_id = self.setup_monitor()
        end = int(time.time()) + 5
        self.options(monitor_id, failure_threshold=10, maintenance_start=int(time.time())-1,
                     maintenance_end=end, maintenance_reason="Aggiornamento di prova")
        _, key, chain = self.certificates["second"]
        peer.replace_certificate(chain, key)
        state = self.force_check(monitor_id, "changed")
        self.assertTrue(any(item["kind"] == "changed" for item in state["monitor_events"]))
        self.assertEqual(state["outbox"], [])
        # Expiry itself schedules the check despite the ordinary 15-minute interval.
        state = self.wait(lambda state: len(state["outbox"]) == 1 and
                          self.monitor(monitor_id, state)["last_checked_at"] >= end, timeout=9)
        self.assertEqual(self.monitor(monitor_id, state)["last_status"], "changed")
        self.assertFalse(self.incidents()["monitor_options"][0]["post_maintenance_check"])
        event_count = len(state["monitor_events"])
        state = self.force_check(monitor_id, "changed")
        self.assertEqual(len(state["outbox"]), 1)
        self.assertEqual(len(state["monitor_events"]), event_count)

    def test_foreign_fingerprint_is_immediate_and_options_validate(self):
        peer, monitor_id = self.setup_monitor()
        self.options(monitor_id, failure_threshold=10)
        _, key, chain = self.certificates["second"]
        peer.replace_certificate(chain, key)
        state = self.force_check(monitor_id, "changed")
        self.assertEqual(len(state["outbox"]), 1)
        # A pending anomaly email remains valid when a later recovery and a new
        # anomaly are queued while SMTP is paused.
        _, baseline_key, baseline_chain = self.certificates["first"]
        peer.replace_certificate(baseline_chain, baseline_key)
        state = self.force_check(monitor_id, "ok")
        self.assertEqual(len(state["outbox"]), 2)
        peer.replace_certificate(chain, key)
        state = self.force_check(monitor_id, "changed")
        self.assertEqual(len(state["outbox"]), 3)
        events = {event["id"]: event for event in state["monitor_events"]}
        self.assertEqual(sorted(events[item["event_id"]]["kind"] for item in state["outbox"]),
                         ["changed", "changed", "recovered"])
        self.assertEqual(len({item["event_id"] for item in state["outbox"]}), 3)
        for fields in ({"monitor_id": monitor_id, "failure_threshold": 11},
                       {"monitor_id": monitor_id, "failure_threshold": 2,
                        "maintenance_start": int(time.time())+20, "maintenance_end": int(time.time())+10}):
            status, _, body = self.form("/api/incidents/monitor-options", fields)
            self.assertEqual(status, 400, body)
        status, _, body = self.form("/api/incidents/events/999999/claim", {
            "responsible": "Test", "status": "open",
        })
        self.assertEqual(status, 400, body)


if __name__ == "__main__":
    unittest.main()
