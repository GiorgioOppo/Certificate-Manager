#!/usr/bin/env python3
"""Guided import, shared directory and reminder rules against isolated SQLite DBs."""
import json
import sqlite3
import time
import unittest
from urllib.parse import urlencode

import integration as core


class WorkspaceIntegrationTests(unittest.TestCase):
    setUp = core.ApplicationTests.setUp
    tearDown = core.ApplicationTests.tearDown
    start_server = core.ApplicationTests.start_server
    stop_server = core.ApplicationTests.stop_server
    http = core.ApplicationTests.http
    state = core.ApplicationTests.state
    upload = core.ApplicationTests.upload
    mutate = core.ApplicationTests.mutate
    rows = core.ApplicationTests.rows
    save_contacts = core.ApplicationTests.save_contacts

    @classmethod
    def setUpClass(cls):
        core.ApplicationTests.setUpClass()
        for name in ('old_chain', 'new_chain', 'leaf_old', 'leaf_new', 'root_ca', 'intermediate', 'key'):
            setattr(cls, name, getattr(core.ApplicationTests, name))

    @classmethod
    def tearDownClass(cls):
        core.ApplicationTests.tearDownClass()

    def form(self, path, values=(), method='POST', expected=200):
        status, _, body = self.mutate(method, path, urlencode(values).encode(), 'application/x-www-form-urlencoded')
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def import_old(self):
        status, _, body = self.upload(self.old_chain)
        self.assertEqual(status, 200, body)
        return next(cert['id'] for cert in self.state()['certificates'] if not cert['is_ca'])

    def preview(self, content, expected=200):
        status, _, body = self.http('POST', '/api/import/preview', content, {
            'X-CSRF-Token': self.token, 'Content-Type': 'application/octet-stream', 'X-Filename': 'preview.pem',
        })
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def contacts(self, cert_id):
        return next(cert for cert in self.state()['certificates'] if cert['id'] == cert_id)['contacts']

    def person(self, name, email, groups=()):
        return self.form('/api/people', [('name', name), ('email', email)] + [('group_id', item) for item in groups])['id']

    def group(self, name, people=()):
        return self.form('/api/groups', [('name', name)] + [('person_id', item) for item in people])['id']

    def assign(self, cert_id, role, people=(), groups=(), expected=200):
        return self.form(f'/api/certificates/{cert_id}/assignments', [('role', role)] +
                         [('person_id', item) for item in people] + [('group_id', item) for item in groups], expected=expected)

    def test_preview_is_read_only_and_detects_chain_duplicates_and_renewals(self):
        self.start_server()
        before = self.state()
        partial = self.preview(self.leaf_new.read_bytes())['certificates'][0]
        self.assertFalse(partial['chain_complete'])
        self.assertEqual(partial['duplicate_id'], 0)
        self.assertEqual(partial['renewal_candidates'], [])
        complete = self.preview(self.new_chain)['certificates']
        self.assertEqual(len(complete), 3)
        self.assertTrue(next(item for item in complete if not item['is_ca'])['chain_complete'])
        after = self.state()
        for key in ('certificates', 'notifications', 'outbox', 'people', 'groups', 'monitors'):
            self.assertEqual(before[key], after[key], key)
        old_id = self.import_old()
        state = self.state()
        preview = self.preview(self.leaf_new.read_bytes())['certificates'][0]
        self.assertTrue(preview['chain_complete'])  # Existing CA chain participates in preview.
        self.assertIn(old_id, [candidate['id'] for candidate in preview['renewal_candidates']])
        duplicate = self.preview(self.old_chain)['certificates']
        self.assertTrue(all(item['duplicate_id'] for item in duplicate))
        self.assertTrue(all(not item['renewal_candidates'] for item in duplicate))
        for key in ('certificates', 'notifications', 'outbox', 'people', 'groups', 'monitors'):
            self.assertEqual(state[key], self.state()[key], key)
        self.preview(self.key.read_bytes(), expected=400)
        status, _, _ = self.http('POST', '/api/import/preview', self.old_chain, {'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 403)

    def test_directory_roles_groups_membership_and_email_propagate(self):
        self.start_server()
        cert_id = self.import_old()
        first = self.person('Owner', 'owner@example.test')
        second = self.person('Technician', 'tech@example.test')
        group = self.group('Operations', [first])
        self.assign(cert_id, 'business', groups=[group])
        self.assign(cert_id, 'technical', people=[first])
        self.assertEqual({(c['role'], c['email']) for c in self.contacts(cert_id)},
                         {('business', 'owner@example.test'), ('technical', 'owner@example.test')})
        self.form(f'/api/groups/{group}', [('name', 'Operations'), ('person_id', first), ('person_id', second)], method='PUT')
        self.assertEqual(len(self.contacts(cert_id)), 3)
        status, _, body = self.save_contacts(cert_id, [(c['role'], c['name'], c['email']) for c in self.contacts(cert_id)])
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.rows(f'SELECT * FROM certificate_groups WHERE certificate_id={cert_id}')), 1)
        # Historical delivery records keep their original address; pending records follow the person.
        with sqlite3.connect(self.db) as connection:
            connection.execute("INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,status,created_at,sent_at) VALUES(?,'expiry','Owner','owner@example.test',30,'Historical','Sent','sent',?,?)", (cert_id, int(time.time()), int(time.time())))
        self.form(f'/api/people/{first}', {'name': 'Renamed Owner', 'email': 'new-owner@example.test', 'group_id': group}, method='PUT')
        contacts = self.contacts(cert_id)
        self.assertEqual(len([c for c in contacts if c['email'] == 'new-owner@example.test']), 2)
        self.assertFalse(any(c['email'] == 'owner@example.test' for c in contacts))
        self.assertTrue(all(c['name'] == 'Renamed Owner' for c in contacts if c['email'] == 'new-owner@example.test'))
        history = self.rows("SELECT recipient_email FROM outbox WHERE status='sent'")
        self.assertEqual(history, [{'recipient_email': 'owner@example.test'}])
        self.assertFalse(self.rows("SELECT * FROM outbox WHERE status IN('pending','failed') AND recipient_email='owner@example.test'"))
        self.form(f'/api/groups/{group}', [('name', 'Operations'), ('person_id', second)], method='PUT')
        self.assertEqual({(c['role'], c['email']) for c in self.contacts(cert_id)},
                         {('business', 'tech@example.test'), ('technical', 'new-owner@example.test')})
        self.form(f'/api/groups/{group}', method='DELETE')
        self.assertEqual([(c['role'], c['email']) for c in self.contacts(cert_id)], [('technical', 'new-owner@example.test')])
        self.form(f'/api/people/{first}', method='DELETE')
        self.assertEqual(self.contacts(cert_id), [])
        self.assertTrue(self.rows("SELECT id FROM outbox WHERE status='sent'"))

    def test_editing_contact_name_updates_shared_person_and_survives_directory_changes(self):
        self.start_server()
        first_cert = self.import_old()
        status, _, body = self.upload(self.new_chain)
        self.assertEqual(status, 200, body)
        second_cert = next(cert['id'] for cert in self.state()['certificates'] if not cert['is_ca'] and cert['id'] != first_cert)
        person = self.person('Original Name', 'shared@example.test')
        self.assign(first_cert, 'business', people=[person])
        self.assign(first_cert, 'technical', people=[person])
        self.assign(second_cert, 'technical', people=[person])
        # The technical row retains its old name in the submitted form; only the edited row wins.
        status, _, body = self.save_contacts(first_cert, [('business', 'Edited Name', 'shared@example.test'),
                                                        ('technical', 'Original Name', 'shared@example.test')])
        self.assertEqual(status, 200, body)
        self.assertTrue(all(c['name'] == 'Edited Name' for c in self.contacts(first_cert)))
        self.assertEqual(self.contacts(second_cert)[0]['name'], 'Edited Name')
        directory_person = next(item for item in self.state()['people'] if item['id'] == person)
        self.assertEqual(directory_person['name'], 'Edited Name')
        self.person('Unrelated', 'unrelated@example.test')
        self.assertTrue(all(c['name'] == 'Edited Name' for c in self.contacts(first_cert)))
        self.assertEqual(self.contacts(second_cert)[0]['name'], 'Edited Name')
        # If both role names change, the business role has explicit precedence.
        status, _, body = self.save_contacts(first_cert, [('technical', 'Technical Change', 'shared@example.test'),
                                                        ('business', 'Business Change', 'shared@example.test')])
        self.assertEqual(status, 200, body)
        self.assertTrue(all(c['name'] == 'Business Change' for c in self.contacts(first_cert)))
        self.assertEqual(self.contacts(second_cert)[0]['name'], 'Business Change')

    def test_manual_removal_breaks_only_edited_group_assignment(self):
        self.start_server()
        first_cert = self.import_old()
        status, _, body = self.upload(self.new_chain)
        self.assertEqual(status, 200, body)
        second_cert = next(cert['id'] for cert in self.state()['certificates'] if not cert['is_ca'] and cert['id'] != first_cert)
        a = self.person('One', 'one@example.test')
        b = self.person('Two', 'two@example.test')
        group = self.group('Shared', [a, b])
        for cert_id in (first_cert, second_cert):
            self.assign(cert_id, 'business', groups=[group])
        status, _, body = self.save_contacts(first_cert, [('business', 'One', 'one@example.test')])
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.contacts(first_cert)), 1)
        self.assertEqual(len(self.contacts(second_cert)), 2)
        c = self.person('Three', 'three@example.test', [group])
        self.assertEqual(len(self.contacts(first_cert)), 1)
        self.assertEqual(len(self.contacts(second_cert)), 3)
        self.assertIn(c, next(item for item in self.state()['groups'] if item['id'] == group)['member_ids'])

    def test_invalid_assignment_and_contact_limit_roll_back_group_change(self):
        self.start_server()
        cert_id = self.import_old()
        ids = [self.person(f'Person {i}', f'person-{i}@example.test') for i in range(101)]
        group = self.group('Hundred', ids[:100])
        self.assign(cert_id, 'business', groups=[group])
        self.assertEqual(len(self.contacts(cert_id)), 100)
        self.form(f'/api/groups/{group}', [('name', 'Too many')] + [('person_id', item) for item in ids], method='PUT', expected=400)
        current = next(item for item in self.state()['groups'] if item['id'] == group)
        self.assertEqual(current['name'], 'Hundred')
        self.assertEqual(set(current['member_ids']), set(ids[:100]))
        self.assign(cert_id, 'technical', people=[ids[0]], expected=400)
        self.assertEqual(len(self.contacts(cert_id)), 100)
        self.assign(cert_id, 'business', people=[999999], expected=400)
        self.assertEqual(len(self.contacts(cert_id)), 100)
        self.form('/api/people', {'name': 'Invalid', 'email': 'bad\r\nBcc: evil@example.test'}, expected=400)

    def test_linking_existing_renewal_preserves_approval_when_saving_request_status(self):
        self.start_server()
        old_id = self.import_old()
        status, _, body = self.upload(self.new_chain)
        self.assertEqual(status, 200, body)
        new_id = next(cert['id'] for cert in self.state()['certificates'] if not cert['is_ca'] and cert['id'] != old_id)
        planned = self.form('/api/renewal-jobs', {'old_certificate_id': old_id, 'status': 'awaiting_ca',
                                                'responsible': 'Owner', 'notes': 'Planned overlap'})['job_id']
        result = self.form(f'/api/renewal-jobs/{planned}', {'old_certificate_id': old_id,
                          'new_certificate_id': new_id, 'status': 'awaiting_ca',
                          'responsible': 'Owner', 'notes': 'Signed certificate received'}, method='PUT')
        self.assertEqual(result['job_id'], planned)
        job = next(item for item in self.state()['renewal_jobs'] if item['id'] == planned)
        self.assertEqual(job['status'], 'signed')
        self.assertEqual(job['new_certificate_id'], new_id)
        self.form(f'/api/renewal-jobs/{planned}', {'old_certificate_id': old_id, 'status': 'requested',
                  'responsible': 'Owner', 'notes': 'Keep renewal approved'}, method='PUT')
        self.assertEqual(next(item for item in self.state()['renewal_jobs'] if item['id'] == planned)['status'], 'signed')
        self.assertFalse(next(cert for cert in self.state()['certificates'] if cert['id'] == old_id)['archived'])

    def test_custom_policy_canonical_validation_queue_and_escalation(self):
        self.start_server()
        cert_id = self.import_old()
        person = self.person('Owner', 'owner@example.test')
        self.assign(cert_id, 'business', people=[person])
        path = f'/api/certificates/{cert_id}/reminder-policy'
        values = {'thresholds': '0, 12,7', 'enabled': 1, 'escalation_email': 'manager@example.test',
                  'escalation_name': 'Manager', 'escalation_after_days': 0}
        self.form(path, values, method='PUT')
        policy = next(item for item in self.state()['reminder_policies'] if item['certificate_id'] == cert_id)
        self.assertEqual(policy['thresholds'], '12,7,0')
        self.assertTrue(any(item['threshold'] == 12 for item in self.state()['notifications']))
        self.assertTrue(any(item['kind'] == 'escalation' and item['recipient_email'] == 'manager@example.test' for item in self.state()['outbox']))
        self.assertTrue(all(item['status'] == 'pending' for item in self.state()['outbox']))
        count = len(self.state()['outbox'])
        self.form(path, values, method='PUT')
        self.assertEqual(len(self.state()['outbox']), count)
        for thresholds in ('7,2', '7,7,0', '-1,0', '3651,0', '7,,0', '7,0,'):
            self.form(path, {**values, 'thresholds': thresholds}, method='PUT', expected=400)
            self.assertEqual(next(item for item in self.state()['reminder_policies'] if item['certificate_id'] == cert_id)['thresholds'], '12,7,0')
        self.form(path, {**values, 'enabled': 0}, method='PUT')
        # Eligibility is rechecked before sending, even with SMTP paused.
        self.form('/api/delivery/process')
        self.assertFalse([item for item in self.state()['outbox'] if item['kind'] in ('expiry', 'escalation') and item['status'] == 'pending'])
        self.stop_server()
        self.start_server()
        self.assertEqual(next(item for item in self.state()['reminder_policies'] if item['certificate_id'] == cert_id)['enabled'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
