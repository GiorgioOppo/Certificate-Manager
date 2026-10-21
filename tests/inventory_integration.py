#!/usr/bin/env python3
"""Durable inventory rows against isolated databases and local TLS peers only."""
import json
import sqlite3
import threading
import time
import unittest
from urllib.parse import urlencode

import remote_integration as remote


class InventoryIntegrationTests(unittest.TestCase):
    setUp = remote.RemoteAcquisitionTests.setUp
    tearDown = remote.RemoteAcquisitionTests.tearDown
    peer = remote.RemoteAcquisitionTests.peer
    start_application = remote.RemoteAcquisitionTests.start_application
    http = remote.RemoteAcquisitionTests.http
    form = remote.RemoteAcquisitionTests.form
    state = remote.RemoteAcquisitionTests.state

    @classmethod
    def setUpClass(cls):
        remote.RemoteAcquisitionTests.setUpClass()
        for name in ('root', 'root_key', 'intermediate', 'intermediate_key', 'certificates'):
            setattr(cls, name, getattr(remote.RemoteAcquisitionTests, name))

    @classmethod
    def tearDownClass(cls):
        remote.RemoteAcquisitionTests.tearDownClass()

    def api(self, path, data=(), expected=200):
        status, _, body = self.form('/api/inventory/' + path, data)
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def get_batch(self, batch_id):
        status, _, body = self.http('GET', f'/api/inventory/batches/{batch_id}')
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def wait_batch(self, batch_id, status):
        deadline = time.monotonic() + 30
        value = None
        while time.monotonic() < deadline:
            value = self.get_batch(batch_id)
            if value['status'] == status:
                return value
            time.sleep(0.15)
        self.fail(f'Lotto non arrivato a {status}: {value}')

    def target(self, peer):
        return f'https://localhost:{peer.port}'

    def input(self, peer, name='Owner', email='owner@example.test'):
        return [('target', self.target(peer)), ('role', 'business'), ('name', name), ('email', email),
                ('role', 'technical'), ('name', 'Technician'), ('email', 'tech@example.test')]

    def commit(self, inputs, planned, key='one', policy=None, expected=200):
        data = list(inputs) + [('expected_fingerprint', planned['plan']['certificate']['fingerprint']),
                               ('review_token', planned['review_token']), ('idempotency_key', key)]
        if policy:
            data.append(('name_policy', policy))
        return self.api('commit', data, expected=expected)

    def counts(self):
        tables = ('certificates', 'contacts', 'directory_people', 'directory_assignments',
                  'monitors', 'inventory_commits', 'outbox', 'workflow_audit')
        with sqlite3.connect(self.db) as db:
            # One read statement is also one consistent snapshot of the row's
            # atomic outcome while the server continues background scheduling.
            row = db.execute('SELECT ' + ','.join(f'(SELECT count(*) FROM {name})' for name in tables)).fetchall()[0]
            return dict(zip(tables, row))

    def test_plan_is_read_only_and_commit_is_complete_and_idempotent(self):
        peer = self.peer()
        self.start_application()
        before = self.counts()
        inputs = self.input(peer)
        plan = self.api('plan', inputs)
        self.assertEqual(self.counts(), before)
        self.assertTrue(plan['plan']['certificate']['new'])
        self.assertTrue(plan['plan']['monitor']['created'])
        self.assertEqual([row['action'] for row in plan['plan']['contacts']], ['added', 'added'])
        result = self.commit(inputs, plan)
        self.assertFalse(result['replayed'])
        counts = self.counts()
        self.assertEqual(counts['contacts'], 2)
        self.assertEqual(counts['directory_people'], 2)
        self.assertEqual(counts['directory_assignments'], 2)
        self.assertEqual(counts['monitors'], 1)
        self.assertEqual(counts['inventory_commits'], 1)
        self.assertEqual(counts['outbox'], 0)
        self.assertEqual(self.commit(inputs, plan)['certificate_id'], result['certificate_id'])
        self.assertEqual(self.counts(), counts)
        self.commit(self.input(peer, 'Changed'), plan, expected=409)

    def test_failure_rolls_back_certificate_people_contacts_monitor_and_receipt(self):
        peer = self.peer()
        self.start_application()
        inputs = self.input(peer)
        plan = self.api('plan', inputs)
        before = self.counts()
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TRIGGER inventory_test_failure BEFORE INSERT ON monitors BEGIN SELECT RAISE(ABORT,'forced monitor failure'); END")
        self.commit(inputs, plan, expected=400)
        self.assertEqual(self.counts(), before)
        with sqlite3.connect(self.db) as db:
            db.execute('DROP TRIGGER inventory_test_failure')
        self.commit(inputs, plan)
        self.assertEqual(self.counts()['contacts'], 2)

    def test_fresh_remote_fingerprint_and_database_review_are_required(self):
        peer = self.peer()
        self.start_application()
        inputs = self.input(peer)
        planned = self.api('plan', inputs)
        _, key, chain = self.certificates['second']
        peer.replace_certificate(chain, key)
        self.commit(inputs, planned, expected=400)
        self.assertEqual(self.counts()['certificates'], 0)
        planned = self.api('plan', inputs)
        status, _, body = self.form('/api/people', {'name': 'Externally added', 'email': 'owner@example.test'})
        self.assertEqual(status, 200, body)
        self.commit(inputs, planned, expected=409)
        self.assertEqual(self.counts()['certificates'], 0)

    def test_shared_name_conflicts_require_explicit_decision(self):
        first, second = self.peer(), self.peer('second')
        self.start_application()
        initial = self.input(first, 'Original Owner')
        self.commit(initial, self.api('plan', initial))
        inputs = self.input(second, 'New Owner')
        plan = self.api('plan', inputs)
        conflict = next(row for row in plan['plan']['contacts'] if row['email'] == 'owner@example.test')
        self.assertEqual(conflict['action'], 'conflict')
        self.assertEqual(conflict['existing_name'], 'Original Owner')
        self.assertEqual(conflict['affected_certificates'], 1)
        before = self.counts()
        self.commit(inputs, plan, key='conflict', expected=400)
        self.assertEqual(self.counts(), before)
        self.commit(inputs, plan, key='conflict', policy='update')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT DISTINCT name FROM contacts WHERE email='owner@example.test'").fetchall(), [('New Owner',)])
            self.assertEqual(db.execute("SELECT count(*) FROM certificates WHERE is_ca=0 AND common_name='localhost' AND archived=0").fetchone()[0], 2)

    def batch_input(self, peers):
        values = [('rows', str(len(peers))), ('name', 'Synthetic inventory')]
        for index, peer in enumerate(peers):
            for field, value in [('target', self.target(peer)), ('line', str(index + 2)),
                                 ('business_name', 'Owner'), ('business_email', 'owner@example.test'),
                                 ('technical_name', 'Technician'), ('technical_email', 'tech@example.test')]:
                values.append((f'row_{index}_{field}', value))
        return values

    def test_batch_processes_offline_after_browser_closes_and_shared_people_are_reused(self):
        first, second = self.peer(), self.peer('second')
        self.start_application()
        batch = self.api('batches', self.batch_input([first, second]))
        batch_id = batch['id']
        self.assertEqual(batch['status'], 'draft')
        self.assertEqual(self.counts()['certificates'], 0)
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        self.assertEqual([row['status'] for row in reviewed['rows']], ['ready', 'ready'])
        self.assertEqual(self.counts()['certificates'], 0)
        self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token']), ('name_policy', 'keep')])
        # No HTTP polling is needed for either TLS fetches or commits.
        time.sleep(4)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM inventory_rows WHERE batch_id=? AND status='imported'", (batch_id,)).fetchone()[0], 2)
        completed = self.wait_batch(batch_id, 'completed')
        self.assertEqual([row['status'] for row in completed['rows']], ['imported', 'imported'])
        counts = self.counts()
        self.assertEqual(counts['directory_people'], 2)
        self.assertEqual(counts['contacts'], 4)
        self.assertEqual(counts['monitors'], 2)
        self.assertEqual(counts['inventory_commits'], 2)
        self.assertEqual(counts['outbox'], 0)

    def test_selected_valid_rows_and_retry_preserve_completed_rows(self):
        good, broken = self.peer(), self.peer(plaintext=True)
        self.start_application()
        batch_id = self.api('batches', self.batch_input([good, broken]))['id']
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        self.assertEqual([row['status'] for row in reviewed['rows']], ['ready', 'error'])
        self.assertTrue(reviewed['rows'][1]['error'])
        self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token'])], expected=400)
        self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token']),
                                            ('row_id', reviewed['rows'][0]['id'])])
        partial = self.wait_batch(batch_id, 'review')
        self.assertEqual([row['status'] for row in partial['rows']], ['imported', 'error'])
        before_id = partial['rows'][0]['certificate_id']
        _, key, chain = self.certificates['second']
        broken.replace_certificate(chain, key)
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        self.assertEqual([row['status'] for row in reviewed['rows']], ['imported', 'ready'])
        self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token']),
                                            ('row_id', reviewed['rows'][1]['id'])])
        completed = self.wait_batch(batch_id, 'completed')
        self.assertEqual(completed['rows'][0]['certificate_id'], before_id)
        self.assertEqual(self.counts()['inventory_commits'], 2)

    def test_batch_persists_across_server_restart(self):
        first, second = self.peer(), self.peer('second')
        self.start_application()
        batch_id = self.api('batches', self.batch_input([first, second]))['id']
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        self.application.terminate()
        self.application.wait(timeout=6)
        self.application_log.close()
        self.start_application()
        restored = self.get_batch(batch_id)
        self.assertEqual(restored['review_token'], reviewed['review_token'])
        self.api(f'batches/{batch_id}/start', [('review_token', restored['review_token'])])
        self.wait_batch(batch_id, 'completed')
        self.assertEqual(self.counts()['inventory_commits'], 2)

    def test_batch_input_validation_is_atomic_and_csrf_is_enforced(self):
        peer = self.peer()
        self.start_application()
        values = self.batch_input([peer, peer])
        values = [(key, 'bad-email' if key == 'row_1_business_email' else value) for key, value in values]
        self.api('batches', values, expected=400)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM inventory_batches').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM inventory_rows').fetchone()[0], 0)
        status, _, _ = self.form('/api/inventory/plan', self.input(peer), csrf=False)
        self.assertEqual(status, 403)

    def test_raw_row_payload_preserves_pipe_names_and_pause_resumes_selection(self):
        peer = self.peer()
        self.start_application()
        payload = urlencode(self.input(peer, 'Owner | Operations'))
        batch = self.api('batches', [('rows', '1'), ('row_0_payload', payload), ('row_0_line', '27')])
        self.assertEqual(batch['rows'][0]['payload'], payload)
        batch_id = batch['id']
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        self.assertEqual(reviewed['rows'][0]['line'], 27)
        self.assertEqual(reviewed['rows'][0]['plan']['contacts'][0]['name'], 'Owner | Operations')
        self.api(f'batches/{batch_id}/pause')
        paused = self.get_batch(batch_id)
        self.assertEqual(paused['status'], 'paused')
        self.assertEqual(paused['rows'][0]['status'], 'ready')
        self.api(f'batches/{batch_id}/start', [('review_token', paused['review_token']),
                                            ('row_id', paused['rows'][0]['id'])])
        self.wait_batch(batch_id, 'completed')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT name FROM directory_people WHERE email='owner@example.test'").fetchall(), [('Owner | Operations',)])

    def test_batch_updates_same_shared_name_on_both_certificates(self):
        first, second = self.peer(), self.peer('second')
        self.start_application()
        status, _, body = self.form('/api/people', {'name': 'Original Owner', 'email': 'owner@example.test'})
        self.assertEqual(status, 200, body)
        batch_id = self.api('batches', self.batch_input([first, second]))['id']
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        for row in reviewed['rows']:
            owner = next(contact for contact in row['plan']['contacts'] if contact['email'] == 'owner@example.test')
            self.assertEqual(owner['action'], 'conflict')
            self.assertEqual(owner['existing_name'], 'Original Owner')
        self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token']), ('name_policy', 'update')])
        completed = self.wait_batch(batch_id, 'completed')
        self.assertEqual([row['status'] for row in completed['rows']], ['imported', 'imported'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT DISTINCT name FROM contacts WHERE email='owner@example.test'").fetchall(), [('Owner',)])
            self.assertEqual(db.execute("SELECT count(*) FROM contacts WHERE email='owner@example.test'").fetchall(), [(2,)])

    def test_unexpected_third_shared_name_requires_new_review(self):
        first, second = self.peer(), self.peer('second')
        self.start_application()
        status, _, body = self.form('/api/people', {'name': 'Original Owner', 'email': 'owner@example.test'})
        self.assertEqual(status, 200, body)
        person_id = json.loads(body)['id']
        batch_id = self.api('batches', self.batch_input([first, second]))['id']
        self.api(f'batches/{batch_id}/plan')
        reviewed = self.wait_batch(batch_id, 'review')
        entered, allow = threading.Event(), threading.Event()
        original = second.context

        class DelayedContext:
            def wrap_socket(self, *args, **kwargs):
                entered.set()
                allow.wait(6)
                return original.wrap_socket(*args, **kwargs)

        with second.lock:
            second.context = DelayedContext()
        try:
            self.api(f'batches/{batch_id}/start', [('review_token', reviewed['review_token']), ('name_policy', 'update')])
            self.assertTrue(entered.wait(8), 'Second row did not reach its fresh TLS check')
            status, _, body = self.form(f'/api/people/{person_id}', {'name': 'Unexpected Third Name', 'email': 'owner@example.test'}, method='PUT')
            self.assertEqual(status, 200, body)
        finally:
            allow.set()
        stopped = self.wait_batch(batch_id, 'review')
        self.assertEqual([row['status'] for row in stopped['rows']], ['imported', 'needs_review'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT name FROM directory_people WHERE id=?", (person_id,)).fetchall(), [('Unexpected Third Name',)])
            self.assertEqual(db.execute('SELECT count(*) FROM inventory_commits').fetchall(), [(1,)])

    def test_explicit_replan_refreshes_ready_rows_without_domain_writes(self):
        peer = self.peer()
        self.start_application()
        status, _, body = self.form('/api/people', {'name': 'Owner', 'email': 'owner@example.test'})
        self.assertEqual(status, 200, body)
        person_id = json.loads(body)['id']
        batch_id = self.api('batches', self.batch_input([peer]))['id']
        self.api(f'batches/{batch_id}/plan')
        first_plan = self.wait_batch(batch_id, 'review')
        _, key, chain = self.certificates['second']
        peer.replace_certificate(chain, key)
        status, _, body = self.form(f'/api/people/{person_id}', {'name': 'Renamed Owner', 'email': 'owner@example.test'}, method='PUT')
        self.assertEqual(status, 200, body)
        before = self.counts()
        self.api(f'batches/{batch_id}/plan')
        refreshed = self.wait_batch(batch_id, 'review')
        self.assertNotEqual(first_plan['rows'][0]['plan']['certificate']['fingerprint'], refreshed['rows'][0]['plan']['certificate']['fingerprint'])
        self.assertEqual(refreshed['rows'][0]['plan']['contacts'][0]['action'], 'conflict')
        self.assertEqual(refreshed['rows'][0]['plan']['contacts'][0]['existing_name'], 'Renamed Owner')
        self.assertEqual(self.counts(), before)
        status, _, body = self.http('GET', '/api/inventory/batches')
        self.assertEqual(status, 200, body)
        listing = next(batch for batch in json.loads(body)['batches'] if batch['id'] == batch_id)
        self.assertEqual(listing['ready_count'], 1)
        self.assertEqual(listing['checking_count'], 0)

    def test_plan_reconstructs_registered_root_and_is_read_only_including_audit(self):
        peer = self.peer()  # TLS presents leaf + intermediate, omitting the root.
        self.start_application()
        inputs = self.input(peer)
        incomplete = self.api('plan', inputs)['plan']['certificate']
        self.assertEqual(incomplete['root_ca'], '')
        self.assertEqual(incomplete['intermediate_ca'], 'CN=Remote Test Intermediate CA')
        self.assertFalse(incomplete['chain_complete'])
        status, _, body = self.http('POST', '/api/certificates', self.root.read_bytes() + self.intermediate.read_bytes(), {
            'Content-Type': 'application/octet-stream', 'X-Filename': 'synthetic-ca-chain.pem',
            'X-CSRF-Token': self.token,
        })
        self.assertEqual(status, 200, body)
        before = self.counts()
        planned = self.api('plan', inputs)['plan']['certificate']
        self.assertEqual(planned['root_ca'], 'CN=Remote Test Root CA')
        self.assertEqual(planned['intermediate_ca'], 'CN=Remote Test Intermediate CA')
        self.assertEqual(planned['chain_status'], 'complete')
        self.assertTrue(planned['chain_complete'])
        self.assertEqual(self.counts(), before)
        self.assertEqual(before['certificates'], 2)


if __name__ == '__main__':
    unittest.main()
