#!/usr/bin/env python3
"""Six-language mail variants, activation, queue snapshots and v7 upgrade; no SMTP."""
import json
from pathlib import Path
import re
import unittest
from urllib.parse import urlencode

import mail_templates_integration as mail_base
from mail_templates_integration import database

LANGUAGES = ('it', 'en', 'fr', 'es', 'zh-CN', 'ja')
CATALOGS = {language: json.loads((Path(__file__).resolve().parents[1] / 'web' / 'mail-locales' / (language + '.json')).read_text())
            for language in LANGUAGES}


class MailLanguageTests(unittest.TestCase):
    setUp = mail_base.MailTemplateTests.setUp
    tearDown = mail_base.MailTemplateTests.tearDown
    start_server = mail_base.MailTemplateTests.start_server
    stop_server = mail_base.MailTemplateTests.stop_server
    http = mail_base.MailTemplateTests.http
    state = mail_base.MailTemplateTests.state
    upload = mail_base.MailTemplateTests.upload
    mutate = mail_base.MailTemplateTests.mutate
    save_contacts = mail_base.MailTemplateTests.save_contacts
    form = mail_base.MailTemplateTests.form
    rows = mail_base.MailTemplateTests.rows
    certificate = mail_base.MailTemplateTests.certificate
    contact_rows = mail_base.MailTemplateTests.contact_rows
    settings = mail_base.MailTemplateTests.settings
    outbox = mail_base.MailTemplateTests.outbox
    snapshot = mail_base.MailTemplateTests.snapshot
    message = mail_base.MailTemplateTests.message

    @classmethod
    def setUpClass(cls):
        mail_base.MailTemplateTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        mail_base.MailTemplateTests.tearDownClass.__func__(cls)

    def templates(self, language=None):
        route = '/api/mail-templates/state' + ('?' + urlencode({'language': language}) if language else '')
        status, _, body = self.http('GET', route)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def find(self, language=None, alert='expiry_15', audience='business'):
        return next(item for item in self.templates(language)['templates']
                    if item['alert'] == alert and item['audience'] == audience)

    def save(self, language, alert='expiry_15', audience='business', **changes):
        item = self.find(language, alert, audience)
        payload = {key: item[key] for key in ('alert', 'audience', 'language', 'subject', 'body')}
        payload['copy_enabled'] = int(item['copy_enabled'])
        payload.update(changes)
        return self.form('/api/mail-templates/template', payload, method='PUT')

    def reset(self, language, alert='expiry_15', audience='business'):
        return self.form('/api/mail-templates/reset', dict(alert=alert, audience=audience, language=language))

    def test_all_336_defaults_preview_without_writes_or_activation(self):
        self.start_server()
        before = self.snapshot()
        subjects = set()
        for language in LANGUAGES:
            state = self.templates(language)
            self.assertEqual({item['id'] for item in state['languages']}, set(LANGUAGES))
            self.assertEqual(len(state['templates']), 56)
            for item in state['templates']:
                self.assertEqual(item['language'], language)
                self.assertEqual(item['active_language'], 'it')
                self.assertFalse(item['customized'])
                preview = self.form('/api/mail-templates/preview', {key: item[key] for key in ('alert', 'audience', 'language', 'subject', 'body')})
                self.assertEqual(preview['language'], language)
                self.assertEqual(preview['active_language'], 'it')
                self.assertNotIn('{{', preview['subject'] + preview['body'])
                self.assertIn(CATALOGS[language]['demo_recipient'], preview['body'])
                self.assertNotIn(' alle ', preview['body'])
                subjects.add(preview['subject'])
        self.assertGreater(len(subjects), 250)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.state()['delivery']['configured'])

    def test_independent_variants_persist_and_reset_inactive_does_not_change_copies(self):
        self.start_server()
        self.save('it', subject='Originale {{common_name}}')
        self.save('fr', subject='À renouveler : {{common_name}}', copy_enabled=1)
        self.save('ja', subject='更新の確認：{{common_name}}', copy_enabled=1)
        self.stop_server()
        self.start_server()
        self.assertEqual(self.find()['language'], 'ja')
        self.assertTrue(self.find()['copy_enabled'])
        self.assertEqual(self.find('fr')['subject'], 'À renouveler : {{common_name}}')
        self.assertEqual(self.find('it')['subject'], 'Originale {{common_name}}')
        self.assertEqual(self.find('fr')['active_language'], 'ja')
        self.reset('fr')
        self.assertFalse(self.find('fr')['customized'])
        self.assertTrue(self.find('fr')['copy_enabled'])
        self.assertEqual(self.find()['language'], 'ja')
        self.reset('ja')
        self.assertEqual(self.find()['language'], 'ja')
        self.assertFalse(self.find()['customized'])
        self.assertFalse(self.find()['copy_enabled'])
        self.assertEqual(self.find('it')['subject'], 'Originale {{common_name}}')

    def test_background_queue_uses_route_languages_and_preserves_utf8_mime_snapshot(self):
        self.start_server()
        cert = self.certificate()
        self.settings()
        self.save('fr', subject='Échéance : {{common_name}}')
        self.save('zh-CN', audience='self', copy_enabled=1, subject='到期提醒：{{common_name}}')
        self.save('ja', alert='certificate', audience='technical', subject='署名済み証明書：{{common_name}}')
        self.contact_rows(cert, [('business', 'Élodie', 'business@example.test'), ('technical', '山田', 'technical@example.test')])
        status, _, body = self.mutate('POST', f'/api/certificates/{cert}/renew', self.new_chain)
        self.assertEqual(status, 200, body)
        rows = self.outbox()
        expected = {('expiry', 'business@example.test'): ('fr', 'Échéance : service.example.test'),
                    ('expiry', 'me@example.test'): ('zh-CN', '到期提醒：service.example.test'),
                    ('certificate', 'technical@example.test'): ('ja', '署名済み証明書：service.example.test')}
        self.assertEqual(len(rows), len(expected))
        for row in rows:
            language, subject = expected[(row['kind'], row['recipient_email'])]
            self.assertEqual((row['template_language'], row['subject']), (language, subject))
            message = self.message(row)
            self.assertEqual(message['Subject'], subject)
            body = message.get_body(preferencelist=('plain',)).get_content()
            self.assertIn(CATALOGS[language]['fields']['not_after'], body)
            self.assertNotIn(' alle ', body)
            self.assertEqual(len(list(message.iter_attachments())), int(row['kind'] == 'certificate'))
        # New language is persisted for future alerts, with no duplicate or rewrite.
        self.save('en')
        self.form('/api/delivery/process')
        self.assertEqual(self.outbox(), rows)
        self.assertEqual({item['template_language'] for item in self.state()['outbox']}, {'fr', 'ja', 'zh-CN'})

    def test_bad_language_is_rejected_atomically_by_all_endpoints(self):
        self.start_server()
        draft = self.find('it')
        payload = {key: draft[key] for key in ('alert', 'audience', 'subject', 'body')}
        before = self.snapshot()
        for language in ('de', '../it', 'zh', 'EN', '', 'it\nBcc: injected@example.test'):
            self.form('/api/mail-templates/template', payload | {'language': language, 'copy_enabled': 0}, method='PUT', expected=400)
            self.form('/api/mail-templates/preview', payload | {'language': language}, expected=400)
            self.form('/api/mail-templates/reset', payload | {'language': language}, expected=400)
            status, _, _ = self.http('GET', '/api/mail-templates/state?' + urlencode({'language': language}))
            self.assertEqual(status, 400)
        duplicate = list(payload.items()) + [('language', 'fr'), ('language', 'ja'), ('copy_enabled', '0')]
        self.form('/api/mail-templates/template', duplicate, method='PUT', expected=400)
        self.assertEqual(self.snapshot(), before)

    def test_v7_migration_preserves_custom_text_copies_owner_and_queued_messages(self):
        self.start_server()
        cert = self.certificate()
        self.settings(name='Operatore esistente')
        self.save('it', subject='Personalizzato {{common_name}}', body='Testo salvato per {{recipient_name}}', copy_enabled=1)
        self.contact_rows(cert, [('business', 'Anna', 'anna@example.test')])
        self.stop_server()
        original = self.outbox()
        old_settings = self.rows('SELECT * FROM mail_template_settings')
        with database(self.db) as db:
            db.execute('DROP TABLE mail_template_variants')
            db.execute('ALTER TABLE mail_templates RENAME TO mail_templates_v8_fixture')
            db.execute("CREATE TABLE mail_templates(alert TEXT NOT NULL,audience TEXT NOT NULL CHECK(audience IN('self','business','technical','other')),subject TEXT NOT NULL,body TEXT NOT NULL,copy_enabled INTEGER NOT NULL DEFAULT 0 CHECK(copy_enabled IN(0,1)),updated_at INTEGER NOT NULL,PRIMARY KEY(alert,audience))")
            db.execute('INSERT INTO mail_templates SELECT alert,audience,subject,body,copy_enabled,updated_at FROM mail_templates_v8_fixture')
            db.execute('DROP TABLE mail_templates_v8_fixture')
            ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='outbox'").fetchone()[0]
            ddl, count = re.subn(r",\s*template_language TEXT NOT NULL DEFAULT ''\s*(?=\))", '', ddl)
            self.assertEqual(count, 1, ddl)
            objects = db.execute("SELECT sql FROM sqlite_master WHERE tbl_name='outbox' AND type IN('index','trigger') AND sql IS NOT NULL").fetchall()
            columns = ','.join(key for key in original[0] if key != 'template_language')
            db.execute('ALTER TABLE outbox RENAME TO outbox_v8_fixture')
            db.execute(ddl)
            db.execute(f'INSERT INTO outbox({columns}) SELECT {columns} FROM outbox_v8_fixture')
            db.execute('DROP TABLE outbox_v8_fixture')
            for (sql,) in objects:
                db.execute(sql)
            db.execute('PRAGMA user_version=7')
        self.start_server()
        self.assertEqual(self.rows('PRAGMA user_version')[0]['user_version'], 8)
        self.assertEqual(self.rows('SELECT * FROM mail_template_settings'), old_settings)
        self.assertEqual(self.outbox(), original)
        self.assertEqual(self.find()['language'], 'it')
        self.assertTrue(self.find()['customized'])
        self.assertTrue(self.find()['copy_enabled'])
        self.assertEqual(self.find('it')['subject'], 'Personalizzato {{common_name}}')
        self.assertFalse(self.find('en')['customized'])
        self.save('fr')
        self.assertEqual(self.find('it')['subject'], 'Personalizzato {{common_name}}')
        self.assertEqual(self.outbox(), original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
