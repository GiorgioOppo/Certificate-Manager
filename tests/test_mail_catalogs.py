#!/usr/bin/env python3
"""Catalog contract, translation completeness and generated C safety."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mail_catalogs', ROOT / 'scripts' / 'embed_mail_templates.py')
MAIL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAIL)


class MailCatalogTests(unittest.TestCase):
    def test_all_336_routes_are_translated_and_distinct_by_audience(self):
        catalogs = MAIL.load_catalogs(ROOT)
        self.assertEqual(set(catalogs), {'it','en','fr','es','zh-CN','ja'})
        count = 0
        for language, catalog in catalogs.items():
            for alert in MAIL.ALERTS:
                bodies = []
                subjects = []
                for audience in MAIL.AUDIENCES:
                    subject, body = MAIL.compose(catalog, alert, audience)
                    self.assertIn('{{recipient_name}}', body)
                    self.assertIn('{{app_name}}', body)
                    self.assertIn('UTC', body)
                    self.assertNotIn('\r', subject)
                    self.assertNotIn('\n', subject)
                    if alert in ('unreachable','tls_error','changed','verification_error','error','recovered'):
                        self.assertIn(catalog['alerts'][alert]['text'], body)
                        self.assertIn(catalog['event_message_label'], body)
                    bodies.append(body)
                    subjects.append(subject)
                    count += 1
                self.assertEqual(len(set(bodies)), 4, (language, alert))
                self.assertEqual(len(set(subjects)), 4, (language, alert))
        self.assertEqual(count, 336)

    def test_certificate_field_labels_describe_the_right_data(self):
        expected = {
            'it': ('Emittente', 'CA radice', 'CA intermedia', 'Numero di serie'),
            'en': ('Issuer', 'Root CA', 'Intermediate CA', 'Serial number'),
            'fr': ('Émetteur', 'AC racine', 'AC intermédiaire', 'Numéro de série'),
            'es': ('Emisor', 'CA raíz', 'CA intermedia', 'Número de serie'),
            'zh-CN': ('签发者', '根 CA', '中间 CA', '序列号'),
            'ja': ('発行者', 'ルート CA', '中間 CA', 'シリアル番号'),
        }
        for language, catalog in MAIL.load_catalogs(ROOT).items():
            self.assertEqual(tuple(catalog['fields'][key] for key in ('issuer','root_ca','intermediate_ca','serial')), expected[language])
            self.assertIn('{{common_name}}', catalog['alerts']['certificate']['text'])

    def test_diagnostic_explanations_do_not_rely_on_untranslated_event_message(self):
        catalogs = MAIL.load_catalogs(ROOT)
        for language, catalog in catalogs.items():
            explanations = [catalog['alerts'][a]['text'] for a in MAIL.ALERTS[-6:]]
            self.assertEqual(len(set(explanations)), 6, language)
            for explanation in explanations:
                self.assertGreater(len(explanation), 20)
                self.assertNotIn('{{event_message}}', explanation)

    def mutate_and_validate(self, callback):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / 'web' / 'mail-locales', root / 'web' / 'mail-locales')
            path = root / 'web' / 'mail-locales' / 'ja.json'
            catalog = json.loads(path.read_text(encoding='utf-8'))
            callback(catalog)
            path.write_text(json.dumps(catalog, ensure_ascii=False), encoding='utf-8')
            with self.assertRaises(ValueError):
                MAIL.generate(root)

    def test_missing_alert_is_rejected(self):
        self.mutate_and_validate(lambda c: c['alerts'].pop('changed'))

    def test_unknown_placeholder_is_rejected(self):
        self.mutate_and_validate(lambda c: c['alerts']['changed'].update(text='{{not_a_known_variable}}'))

    def test_malformed_placeholder_is_rejected(self):
        self.mutate_and_validate(lambda c: c['alerts']['changed'].update(text='{{event_message}'))

    def test_translation_losing_a_placeholder_is_rejected(self):
        self.mutate_and_validate(lambda c: c['alerts']['certificate'].update(subject='Certificate for {{common_name}}'))

    def test_subject_header_injection_is_rejected(self):
        self.mutate_and_validate(lambda c: c['alerts']['changed'].update(subject='Title\r\nBcc: person@example.test'))

    def test_subject_and_body_limits_are_enforced_in_utf8_bytes(self):
        self.mutate_and_validate(lambda c: c['alerts']['changed'].update(subject='あ'*334))
        self.mutate_and_validate(lambda c: c['alerts']['changed'].update(text='あ'*5462))

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"language":"it","language":"ja"}', object_pairs_hook=MAIL.unique_object)

    def test_output_is_deterministic_and_header_compiles_with_all_helpers(self):
        first = MAIL.generate(ROOT)
        self.assertEqual(first, MAIL.generate(ROOT))
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'mail_catalogs.h').write_text(first, encoding='utf-8')
            (folder / 'test.c').write_text('''#include "mail_catalogs.h"
#include <assert.h>
int main(void) {
  const char *languages[]={"it","en","fr","es","zh-CN","ja"};
  for (size_t i=0;i<6;i++) {
    const MailDefault *d=mail_default_lookup(languages[i],"changed","technical");
    assert(d && d->subject && d->body);
    assert(mail_default_demo_name(languages[i])[0]);
    assert(mail_default_demo_message(languages[i])[0]);
    assert(mail_default_role_label(languages[i],"technical")[0]);
    assert(mail_default_event_label(languages[i],"changed")[0]);
  }
  assert(mail_default_lookup(NULL,"expired","self"));
  assert(!mail_default_lookup("unknown","expired","self"));
  assert(!mail_default_lookup("it","not-alert","self"));
  assert(!mail_default_lookup("it","expired","not-role"));
  return 0;
}
''', encoding='utf-8')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Wpedantic','-Werror',str(folder/'test.c'),'-o',str(folder/'test')], check=True, capture_output=True)
            subprocess.run([str(folder/'test')], check=True)

    def test_cli_does_not_overwrite_existing_header_when_validation_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / 'web' / 'mail-locales', root / 'web' / 'mail-locales')
            output = root / 'build' / 'mail_catalogs.h'
            output.parent.mkdir()
            output.write_text('previous valid header', encoding='utf-8')
            (root / 'web' / 'mail-locales' / 'fr.json').write_text('{}', encoding='utf-8')
            result = subprocess.run(['python3',str(ROOT/'scripts'/'embed_mail_templates.py'),'--root',str(root),'--output',str(output)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(encoding='utf-8'), 'previous valid header')


if __name__ == '__main__':
    unittest.main(verbosity=2)
