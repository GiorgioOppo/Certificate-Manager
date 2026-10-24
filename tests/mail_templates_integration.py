#!/usr/bin/env python3
"""Email templates, audience routing and immutable queue snapshots; no real SMTP."""
from email import policy
from email.parser import BytesParser
from contextlib import contextmanager
import json
import socket
import sqlite3
import time
import unittest
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


class MailTemplateTests(unittest.TestCase):
    setUp = core.ApplicationTests.setUp
    tearDown = core.ApplicationTests.tearDown
    start_server = core.ApplicationTests.start_server
    stop_server = core.ApplicationTests.stop_server
    http = core.ApplicationTests.http
    state = core.ApplicationTests.state
    upload = core.ApplicationTests.upload
    mutate = core.ApplicationTests.mutate
    save_contacts = core.ApplicationTests.save_contacts

    @classmethod
    def setUpClass(cls):
        core.ApplicationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        core.ApplicationTests.tearDownClass.__func__(cls)

    def form(self, route, values=(), method='POST', expected=200, csrf=True):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if csrf:
            headers['X-CSRF-Token'] = self.token
        status, _, body = self.http(method, route, urlencode(values).encode(), headers)
        self.assertEqual(status, expected, body)
        return json.loads(body)

    def templates(self):
        status, _, body = self.http('GET', '/api/mail-templates/state')
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def rows(self, sql):
        with database(self.db) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(sql)]

    def template(self, alert='expiry_15', audience='business', subject=None, body=None, copy_enabled=0):
        return dict(alert=alert, audience=audience,
                    subject=subject if subject is not None else audience + ' {{common_name}}',
                    body=body if body is not None else 'Ciao {{recipient_name}} ({{recipient_email}})\n{{common_name}}',
                    copy_enabled=copy_enabled)

    def save(self, **changes):
        return self.form('/api/mail-templates/template', self.template(**changes), method='PUT')

    def settings(self, email='me@example.test', name='Operatore Test'):
        return self.form('/api/mail-templates/settings', dict(self_name=name, self_email=email), method='PUT')

    def certificate(self):
        status, _, body = self.upload(self.old_chain)
        self.assertEqual(status, 200, body)
        return next(item for item in self.state()['certificates'] if not item['is_ca'])['id']

    def contact_rows(self, cert, contacts):
        status, _, body = self.save_contacts(cert, contacts)
        self.assertEqual(status, 200, body)

    def clear_reminders(self):
        with database(self.db) as db:
            db.execute('DELETE FROM notifications')
            db.execute('DELETE FROM outbox')

    def snapshot(self):
        """Include audit and SQLite sequences: preview must not write indirectly."""
        with database(self.db) as db:
            names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            return {name: db.execute('SELECT * FROM "' + name.replace('"', '""') + '"').fetchall()
                    for name in names}

    def outbox(self):
        return self.rows('SELECT * FROM outbox ORDER BY id')

    def wait_for(self, predicate, timeout=7):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.state()
            if predicate(last):
                return last
            time.sleep(0.05)
        self.fail('Stato atteso non raggiunto: ' + json.dumps(last))

    def message(self, row):
        status, _, body = self.http('GET', f"/api/outbox/{row['id']}/message")
        self.assertEqual(status, 200, body)
        return BytesParser(policy=policy.default).parsebytes(body)

    def test_catalog_defaults_and_persistence(self):
        self.start_server()
        state = self.templates()
        expected_alerts = {'expiry_45', 'expiry_30', 'expiry_15', 'expiry_2', 'expired', 'expiry',
                           'escalation', 'certificate', 'unreachable', 'tls_error', 'changed',
                           'verification_error', 'error', 'recovered'}
        self.assertEqual({item['id'] for item in state['alerts']}, expected_alerts)
        self.assertEqual({item['id'] for item in state['audiences']}, {'self', 'business', 'technical', 'other'})
        self.assertEqual(len(state['templates']), len(expected_alerts) * 4)
        self.assertTrue(all(not item['copy_enabled'] and not item['customized'] for item in state['templates']))
        self.assertIn('common_name', state['variables'])
        self.assertIn('recipient_email', state['variables'])
        self.assertEqual(state['settings']['self_email'], '')
        self.settings(name='Màrio テスト')
        self.save(subject='Rinnovo {{common_name}}', body='Messaggio personalizzato\n{{recipient_name}}')
        self.stop_server()
        self.start_server()
        state = self.templates()
        self.assertEqual(state['settings'], {'self_name': 'Màrio テスト', 'self_email': 'me@example.test'})
        saved = next(item for item in state['templates'] if item['alert'] == 'expiry_15' and item['audience'] == 'business')
        self.assertTrue(saved['customized'])
        self.assertEqual(saved['subject'], 'Rinnovo {{common_name}}')
        self.assertEqual(self.rows('PRAGMA user_version')[0]['user_version'], 7)

    def test_preview_all_alerts_is_read_only_with_sample_and_real_certificate(self):
        self.start_server()
        cert = self.certificate()
        before = self.snapshot()
        state = self.templates()
        for item in state['templates']:
            preview = self.form('/api/mail-templates/preview', {key: item[key] for key in ('alert', 'audience', 'subject', 'body')})
            self.assertTrue(preview['sample'])
            self.assertEqual(preview['attachment'], item['alert'] == 'certificate')
            self.assertNotIn('{{', preview['subject'] + preview['body'])
        draft = self.template(subject='Rinnovo di {{common_name}}', body='{{fingerprint}}\n{{not_before}}\n{{not_after}}')
        preview = self.form('/api/mail-templates/preview', draft | {'certificate_id': cert})
        self.assertFalse(preview['sample'])
        self.assertEqual(preview['subject'], 'Rinnovo di service.example.test')
        self.assertNotIn('{{', preview['body'])
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.state()['delivery']['configured'])

    def test_schema_v6_migration_preserves_historical_and_pending_messages(self):
        self.start_server()
        cert = self.certificate()
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test'), ('business', 'Marco', 'marco@example.test')])
        self.stop_server()
        with database(self.db) as db:
            db.execute("UPDATE outbox SET status='sent',sent_at=?,attempts=1 WHERE recipient_email='anna@example.test'", (int(time.time()),))
            db.commit()
            before = self.outbox()
            for row in before:
                row.update(template_alert='', template_audience='', template_copy=0)
            objects = db.execute("SELECT sql FROM sqlite_master WHERE tbl_name='outbox' AND type IN('index','trigger') AND sql IS NOT NULL").fetchall()
            db.execute('ALTER TABLE outbox RENAME TO outbox_v7_fixture')
            db.execute("CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                       "kind TEXT NOT NULL CHECK(kind IN('expiry','certificate','escalation','monitor')),"
                       "recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL,threshold INTEGER NOT NULL DEFAULT -1,"
                       "subject TEXT NOT NULL,body TEXT NOT NULL,attachment_pem TEXT NOT NULL DEFAULT '',"
                       "status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','failed')),"
                       "attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,"
                       "sent_at INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0,event_id INTEGER REFERENCES monitor_events(id) ON DELETE CASCADE)")
            columns = ','.join(key for key in before[0] if not key.startswith('template_'))
            db.execute(f'INSERT INTO outbox({columns}) SELECT {columns} FROM outbox_v7_fixture')
            db.execute('DROP TABLE outbox_v7_fixture')
            for (sql,) in objects:
                db.execute(sql)
            db.execute('DROP TABLE mail_templates')
            db.execute('DROP TABLE mail_template_settings')
            db.execute('PRAGMA user_version=6')
        self.start_server()
        self.assertEqual(self.rows('PRAGMA user_version')[0]['user_version'], 7)
        self.assertEqual(self.outbox(), before)
        self.assertTrue(all(not item['copy_enabled'] and not item['customized'] for item in self.templates()['templates']))

    def test_mutation_csrf_and_validation_reject_injection_unknown_variables_and_limits(self):
        self.start_server()
        draft = self.template()
        for route, values, method in (
                ('/api/mail-templates/settings', {'self_name': '', 'self_email': ''}, 'PUT'),
                ('/api/mail-templates/template', draft, 'PUT'),
                ('/api/mail-templates/reset', {'alert': 'expiry_15', 'audience': 'business'}, 'POST'),
                ('/api/mail-templates/preview', draft, 'POST')):
            self.form(route, values, method=method, csrf=False, expected=403)
        before = self.snapshot()
        for changes in ({'subject': 'Hello\r\nBcc: victim@example.test'}, {'subject': 'X' * 999},
                        {'subject': '界' * 333}, {'body': 'x' * (16 * 1024 + 1)},
                        {'body': '{{not_a_supported_variable}}'}, {'subject': '{{common_name}'},
                        {'body': '{{common_name'}, {'alert': 'unknown'}, {'audience': 'unknown'},
                        {'copy_enabled': 2}):
            with self.subTest(changes=changes):
                self.form('/api/mail-templates/template', draft | changes, method='PUT', expected=400)
        for email in ('broken', 'me@example.test\r\nBcc: victim@example.test'):
            self.form('/api/mail-templates/settings', {'self_name': 'Test', 'self_email': email}, method='PUT', expected=400)
        self.form('/api/mail-templates/template', list(draft.items()) + [('alert', 'expired')], method='PUT', expected=400)
        self.form('/api/mail-templates/preview', draft | {'certificate_id': 999999}, expected=400)
        self.assertEqual(before, self.snapshot())
        # A valid template can expand beyond the header limit; that draft is also rejected.
        cert = self.certificate()
        self.form('/api/mail-templates/preview', draft | {'subject': '{{common_name}}' * 60, 'certificate_id': cert}, expected=400)

    def test_customization_only_affects_new_messages_and_reset_retains_queued_snapshot(self):
        self.start_server()
        cert = self.certificate()
        self.save(subject='PRIMA {{common_name}}', body='Prima versione {{recipient_name}}')
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test')])
        original = self.outbox()
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]['subject'], 'PRIMA service.example.test')
        self.save(subject='DOPO {{common_name}}', body='Seconda versione {{recipient_name}}')
        self.assertEqual(self.outbox(), original)
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test'), ('business', 'Marco', 'marco@example.test')])
        rows = self.outbox()
        self.assertEqual(next(item for item in rows if item['recipient_email'] == 'anna@example.test'), original[0])
        self.assertEqual(next(item for item in rows if item['recipient_email'] == 'marco@example.test')['body'], 'Seconda versione Marco')
        before_reset = self.outbox()
        self.form('/api/mail-templates/reset', {'alert': 'expiry_15', 'audience': 'business'})
        saved = next(item for item in self.templates()['templates'] if item['alert'] == 'expiry_15' and item['audience'] == 'business')
        self.assertFalse(saved['customized'])
        self.assertEqual(self.outbox(), before_reset)

    def test_opt_in_expiry_copies_use_role_templates_and_deduplicate_addresses(self):
        self.start_server()
        cert = self.certificate()
        self.settings()
        contacts = [('business', 'Anna', 'anna@example.test'), ('technical', 'Luca', 'luca@example.test'),
                    ('technical', 'Anna', 'ANNA@example.test')]
        self.contact_rows(cert, contacts)
        # Saving identity/templates alone does not opt anyone into extra messages.
        self.assertEqual(len(self.outbox()), 1)
        self.clear_reminders()
        self.save(audience='business', subject='BUSINESS {{recipient_email}}')
        self.save(audience='technical', subject='TECHNICAL {{recipient_email}}', copy_enabled=1)
        self.save(audience='self', subject='SELF {{recipient_email}}', copy_enabled=1)
        self.form('/api/check')
        rows = self.outbox()
        self.assertEqual(len(rows), 3)
        routed = {item['recipient_email'].lower(): item['subject'] for item in rows}
        self.assertEqual(routed['anna@example.test'], 'BUSINESS anna@example.test')
        self.assertEqual(routed['luca@example.test'], 'TECHNICAL luca@example.test')
        self.assertEqual(routed['me@example.test'], 'SELF me@example.test')
        self.assertTrue(all(item['kind'] == 'expiry' and item['threshold'] == 15 for item in rows))
        self.form('/api/check')
        self.assertEqual(self.outbox(), rows)

    def test_signed_certificate_copies_keep_public_attachment_and_role_specific_content(self):
        self.start_server()
        old = self.certificate()
        self.settings()
        self.contact_rows(old, [('business', 'Anna', 'anna@example.test'), ('technical', 'Luca', 'luca@example.test')])
        for audience in ('business', 'technical', 'self'):
            self.save(alert='certificate', audience=audience, copy_enabled=int(audience != 'technical'),
                      subject=audience + ' {{common_name}}', body='{{recipient_name}}\n{{fingerprint}}')
        status, _, body = self.mutate('POST', f'/api/certificates/{old}/renew', self.new_chain)
        self.assertEqual(status, 200, body)
        new = json.loads(body)['certificate_id']
        rows = [item for item in self.outbox() if item['certificate_id'] == new and item['kind'] == 'certificate']
        self.assertEqual({item['recipient_email'] for item in rows}, {'anna@example.test', 'luca@example.test', 'me@example.test'})
        for item in rows:
            with self.subTest(recipient=item['recipient_email']):
                role = {'anna@example.test': 'business', 'luca@example.test': 'technical', 'me@example.test': 'self'}[item['recipient_email']]
                self.assertEqual(item['subject'], role + ' service.example.test')
                message = self.message(item)
                attachments = list(message.iter_attachments())
                self.assertEqual(len(attachments), 1)
                public = attachments[0].get_payload(decode=True)
                self.assertIn(b'-----BEGIN CERTIFICATE-----', public)
                self.assertNotIn(b'PRIVATE KEY', public)
                self.assertIn(self.leaf_new.read_bytes().strip(), public)
        self.assertEqual(len([item for item in self.state()['certificates'] if not item['is_ca'] and not item['superseded_by']]), 2)

    def test_copies_rechecked_before_claim_and_missing_self_address_sends_no_copy(self):
        self.start_server()
        cert = self.certificate()
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test'), ('technical', 'Luca', 'luca@example.test')])
        self.form('/api/mail-templates/template', self.template(audience='self', copy_enabled=1), method='PUT', expected=400)
        self.settings()
        self.save(audience='self', copy_enabled=1)
        self.settings(email='')
        self.save(audience='technical', copy_enabled=1)
        self.clear_reminders()
        self.form('/api/check')
        self.assertEqual({item['recipient_email'] for item in self.outbox()}, {'anna@example.test', 'luca@example.test'})
        self.save(audience='technical', copy_enabled=0)
        self.form('/api/delivery/process')
        rows = self.outbox()
        self.assertEqual([item['recipient_email'] for item in rows], ['anna@example.test'])
        self.assertEqual(rows[0]['attempts'], 0)

    def test_self_copy_survives_changes_to_a_matching_directory_person(self):
        self.start_server()
        cert = self.certificate()
        self.settings()
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test')])
        self.save(audience='self', copy_enabled=1)
        self.clear_reminders()
        self.form('/api/check')
        original = next(item for item in self.outbox() if item['recipient_email'] == 'me@example.test')
        self.assertEqual(original['template_copy'], 1)
        person = self.form('/api/people', {'name': 'Persona distinta', 'email': 'me@example.test'})['id']
        impact = self.form('/api/operations/directory-impact', {'type': 'person', 'id': person})
        self.assertNotIn(original['id'], [item['id'] for item in impact['pending_mail']])
        self.form(f'/api/people/{person}', {'name': 'Persona distinta', 'email': 'new-person@example.test'}, method='PUT')
        self.form('/api/delivery/process')
        self.assertEqual(next(item for item in self.outbox() if item['id'] == original['id']), original)
        second = self.form('/api/people', {'name': 'Altra persona', 'email': 'me@example.test'})['id']
        self.form(f'/api/people/{second}', method='DELETE')
        self.form('/api/delivery/process')
        self.assertEqual(next(item for item in self.outbox() if item['id'] == original['id']), original)

    def test_monitor_event_routes_legacy_recipients_and_opt_in_copies(self):
        self.start_server()
        cert = self.certificate()
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test'), ('technical', 'Luca', 'luca@example.test')])
        self.settings()
        for audience in ('business', 'technical', 'self', 'other'):
            self.save(alert='unreachable', audience=audience, copy_enabled=int(audience == 'self'),
                      subject=audience + ' {{event_type}}', body='{{service_url}}\n{{event_message}}')
        # An unused local port gives a refused TCP connection without external traffic.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            target = f"https://127.0.0.1:{reserved.getsockname()[1]}"
        self.form('/api/monitors', {'certificate_id': cert, 'target': target, 'enabled': 1,
                                  'email_alerts': 1, 'email_recipients': 'anna@example.test; luca@example.test; external@example.test'})
        state = self.wait_for(lambda state: len([item for item in state['outbox'] if item['kind'] == 'monitor']) == 4)
        rows = [item for item in self.outbox() if item['kind'] == 'monitor']
        self.assertEqual(len({item['recipient_email'].lower() for item in rows}), 4)
        expected = {'anna@example.test': 'business', 'luca@example.test': 'technical',
                    'me@example.test': 'self', 'external@example.test': 'other'}
        for item in rows:
            self.assertEqual(item['subject'], expected[item['recipient_email']] + ' unreachable')
            self.assertIn(target, item['body'])
            self.assertFalse(list(self.message(item).iter_attachments()))
        event = next(item for item in state['monitor_events'] if item['kind'] == 'unreachable')
        before = self.snapshot()
        preview = self.form('/api/mail-templates/preview', self.template(alert='unreachable', audience='other',
                                                                      body='{{service_url}}\n{{event_type}}') |
                            {'certificate_id': cert, 'event_id': event['id']})
        self.assertFalse(preview['sample'])
        self.assertIn(target, preview['body'])
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()
