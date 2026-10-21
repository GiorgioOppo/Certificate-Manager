#!/usr/bin/env python3
"""Read-only operational previews, confirmation hashes and retained closure evidence."""
import json
import sqlite3
import time
import unittest
from urllib.parse import urlencode
import integration as core


class OperationsIntegrationTests(unittest.TestCase):
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
        for name in ('old_chain', 'new_chain', 'leaf_old', 'leaf_new', 'pem', 'root_ca', 'intermediate'):
            setattr(cls, name, getattr(core.ApplicationTests, name))

    @classmethod
    def tearDownClass(cls):
        core.ApplicationTests.tearDownClass()

    def form(self, path, values=(), method='POST', expected=200):
        status, _, body = self.mutate(method, path, urlencode(values).encode(), 'application/x-www-form-urlencoded')
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def get(self, path, expected=200):
        status, _, body = self.http('GET', path)
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def import_pair(self):
        self.assertEqual(self.upload(self.old_chain)[0], 200)
        old = next(c['id'] for c in self.state()['certificates'] if not c['is_ca'])
        self.assertEqual(self.upload(self.new_chain)[0], 200)
        new = next(c['id'] for c in self.state()['certificates'] if not c['is_ca'] and c['id'] != old)
        return old, new

    def policy(self, cert):
        return {'certificate_id': cert, 'thresholds': '45,30,15,2,0', 'enabled': 1,
                'escalation_email': 'escalation@example.test', 'escalation_name': 'Escalation', 'escalation_after_days': 7}

    def database_snapshot(self):
        return {table: self.rows(f'SELECT * FROM {table}') for table in ('notifications', 'outbox', 'reminder_policies', 'workflow_audit')}

    def test_draft_reminder_preview_is_read_only_and_chooses_urgent_reached_threshold(self):
        self.start_server()
        old, _ = self.import_pair()
        with sqlite3.connect(self.db) as db:
            db.execute('DELETE FROM notifications')
            db.execute('DELETE FROM outbox')
            db.execute('UPDATE certificates SET not_after=? WHERE id=?', (int(time.time()) + 10 * 86400, old))
        before = self.database_snapshot()
        preview = self.form('/api/operations/reminder-preview', self.policy(old))
        events = {item['threshold']: item for item in preview['events']}
        self.assertEqual(events[15]['status'], 'immediate')
        self.assertEqual(events[30]['status'], 'skipped')
        self.assertEqual(events[45]['status'], 'skipped')
        self.assertEqual(events[2]['status'], 'future')
        self.assertEqual(preview['escalation']['status'], 'future')
        self.assertEqual(before, self.database_snapshot())

        with sqlite3.connect(self.db) as db:
            db.execute('INSERT INTO notifications VALUES(?,?,?)', (old, 15, int(time.time()) - 8 * 86400))
        before = self.database_snapshot()
        preview = self.form('/api/operations/reminder-preview', self.policy(old))
        self.assertEqual(next(e for e in preview['events'] if e['threshold'] == 15)['status'], 'recorded')
        self.assertEqual(preview['escalation']['status'], 'immediate')
        self.assertEqual(before, self.database_snapshot())
        draft = self.policy(old) | {'enabled': 0}
        preview = self.form('/api/operations/reminder-preview', draft)
        self.assertEqual(preview['escalation']['status'], 'disabled')
        self.form('/api/operations/reminder-preview', self.policy(old) | {'thresholds': '15,2'}, expected=400)

    def test_proposed_memberships_show_new_certificate_impact_before_saving(self):
        self.start_server()
        old, new = self.import_pair()
        person = self.form('/api/people', {'name': 'Original', 'email': 'original@example.test'})['id']
        other = self.form('/api/people', {'name': 'Other', 'email': 'other@example.test'})['id']
        group = self.form('/api/groups', [('name', 'Operations'), ('person_id', other)])['id']
        self.form(f'/api/certificates/{old}/assignments', [('role', 'business'), ('person_id', person)])
        self.form(f'/api/certificates/{new}/assignments', [('role', 'technical'), ('group_id', group)])
        before = self.database_snapshot()
        impact = self.form('/api/operations/directory-impact', [
            ('type', 'person'), ('id', person), ('proposed', '1'), ('name', 'Renamed'),
            ('email', 'renamed@example.test'), ('group_id', group),
        ])
        self.assertEqual({c['certificate_id'] for c in impact['certificates']}, {old})
        self.assertEqual({c['certificate_id'] for c in impact['proposal']['certificates']}, {old, new})
        self.assertEqual(impact['proposal']['memberships_before'], [])
        self.assertEqual(impact['proposal']['memberships_after'][0]['id'], group)
        self.assertEqual(impact['item']['email'], 'original@example.test')
        self.assertEqual(impact['proposal']['email'], 'renamed@example.test')
        group_impact = self.form('/api/operations/directory-impact', [
            ('type', 'group'), ('id', group), ('proposed', '1'), ('name', 'Changed team'), ('person_id', person),
        ])
        self.assertEqual([p['id'] for p in group_impact['proposal']['memberships_before']], [other])
        self.assertEqual([p['id'] for p in group_impact['proposal']['memberships_after']], [person])
        self.assertEqual(before, self.database_snapshot())

    def test_policy_template_requires_current_review_and_honours_explicit_exceptions(self):
        self.start_server()
        old, new = self.import_pair()
        fields = self.policy(new) | {'name': 'Standard', 'thresholds': '60,20,0'}
        template = self.form('/api/operations/templates', fields)['id']
        selection = [('certificate_id', old), ('certificate_id', new), ('exclude_id', old)]
        plan = self.form(f'/api/operations/templates/{template}/plan', selection)
        excluded = next(c for c in plan['changes'] if c['certificate_id'] == old)
        self.assertTrue(excluded['excluded'])
        self.assertEqual(excluded['before'], excluded['after'])
        self.assertEqual(len(plan['plan_hash']), 64)
        # A concurrent policy change invalidates the whole confirmed plan.
        self.form(f'/api/certificates/{new}/reminder-policy', self.policy(new) | {'thresholds': '90,0'}, method='PUT')
        before = self.rows('SELECT * FROM reminder_policies')
        self.form(f'/api/operations/templates/{template}/apply', selection + [('plan_hash', plan['plan_hash'])], expected=400)
        self.assertEqual(before, self.rows('SELECT * FROM reminder_policies'))
        plan = self.form(f'/api/operations/templates/{template}/plan', selection)
        result = self.form(f'/api/operations/templates/{template}/apply', selection + [('plan_hash', plan['plan_hash'])])
        self.assertTrue(result['applied'])
        policies = self.rows('SELECT certificate_id,thresholds FROM reminder_policies')
        self.assertEqual(next(p['thresholds'] for p in policies if p['certificate_id'] == new), '60,20,0')
        self.assertFalse(any(p['certificate_id'] == old and p['thresholds'] == '60,20,0' for p in policies))
        self.form(f'/api/operations/templates/{template}/plan', [('certificate_id', new), ('certificate_id', 999999)], expected=400)
        self.form(f'/api/operations/templates/{template}/plan', [('certificate_id', new), ('exclude_id', old)], expected=400)
        self.form(f'/api/operations/templates/{template}', fields | {'name': 'Updated'}, method='PUT')
        self.assertEqual(self.get('/api/operations/templates')['templates'][0]['name'], 'Updated')
        self.form(f'/api/operations/templates/{template}', method='DELETE')
        self.assertEqual(self.get('/api/operations/templates')['templates'], [])

    def test_shared_person_impact_lists_roles_and_pending_mail_without_changes(self):
        self.start_server()
        old, new = self.import_pair()
        p = self.form('/api/people', {'name': 'Owner', 'email': 'owner@example.test'})['id']
        g = self.form('/api/groups', [('name', 'Operations'), ('person_id', p)])['id']
        self.form(f'/api/certificates/{old}/assignments', [('role', 'business'), ('group_id', g)])
        self.form(f'/api/certificates/{new}/assignments', [('role', 'technical'), ('person_id', p)])
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,status,created_at) VALUES(?,'expiry','Owner','owner@example.test',30,'Reminder','Pending','pending',?)", (old, int(time.time())))
        before = self.database_snapshot()
        impact = self.form('/api/operations/directory-impact', {'type': 'person', 'id': p})
        self.assertEqual({(c['certificate_id'], c['role']) for c in impact['certificates']}, {(old, 'business'), (new, 'technical')})
        self.assertGreaterEqual(len(impact['pending_mail']), 1)
        self.assertTrue(all(item['recipient_email'] == 'owner@example.test' for item in impact['pending_mail']))
        group = self.form('/api/operations/directory-impact', {'type': 'group', 'id': g})
        self.assertEqual([(c['certificate_id'], c['role']) for c in group['certificates']], [(old, 'business')])
        self.assertEqual(before, self.database_snapshot())

    def test_compare_retirement_report_and_per_recipient_delivery_are_distinct(self):
        self.start_server()
        old, new = self.import_pair()
        before = self.database_snapshot()
        comparison = self.form('/api/operations/compare', {'old_certificate_id': old, 'new_certificate_id': new})
        self.assertTrue(comparison['candidate'])
        self.assertTrue(comparison['identity_matches'])
        self.assertIn('fingerprint', comparison['differences'])
        self.assertNotEqual(comparison['previous']['fingerprint'], comparison['next']['fingerprint'])
        self.assertEqual(before, self.database_snapshot())
        status, _, body = self.save_contacts(old, [('technical', 'Operator', 'operator@example.test')])
        self.assertEqual(status, 200, body)
        linked = self.form('/api/renewal-jobs', {'old_certificate_id': old, 'new_certificate_id': new})
        job = linked['job_id']
        checklist = self.get(f'/api/operations/renewals/{job}/checklist')
        self.assertFalse(checklist['can_complete'])
        self.assertIn('no_endpoints', checklist['reason_codes'])
        delivery = self.get(f'/api/operations/renewals/{job}/delivery')
        self.assertEqual(delivery['recipients'][0]['status'], 'pending')
        self.assertFalse(delivery['recipients'][0]['smtp_accepted'])
        self.form(f'/api/renewal-jobs/{job}', {'old_certificate_id': old, 'status': 'signed', 'responsible': 'Operator', 'notes': 'Offline service explicitly retired'}, method='PUT')
        self.form(f'/api/renewal-jobs/{job}/retire')
        report = self.get(f'/api/operations/renewals/{job}/report')
        self.assertEqual(report['closure']['mode'], 'retired')
        self.assertEqual(report['closure']['evidence']['previous']['fingerprint'], comparison['previous']['fingerprint'])
        self.assertEqual(report['closure']['evidence']['next']['fingerprint'], comparison['next']['fingerprint'])
        self.assertFalse(report['closure']['evidence']['checklist']['can_complete'])
        self.assertTrue(report['live']['audit'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
