#!/usr/bin/env python3
"""Validate six composed mail catalogs and generate a self-contained C header.

Catalog schema 1 combines an audience greeting, an alert's explanation, translated
field labels, an audience action for the alert category, and a footer. All rendered
routes have the same interpolation variables in every language. No runtime files
or external translation service are required by the executable.
"""
import argparse
import json
from pathlib import Path
import re
import tempfile
import os

LANGUAGES = ('it', 'en', 'fr', 'es', 'zh-CN', 'ja')
ALERTS = ('expiry_45','expiry_30','expiry_15','expiry_2','expired','expiry','escalation','certificate','unreachable','tls_error','changed','verification_error','error','recovered')
AUDIENCES = ('self','business','technical','other')
VARIABLES = frozenset(('app_name','common_name','fingerprint','not_before','not_after','serial','issuer','root_ca','intermediate_ca','sans','recipient_name','recipient_email','recipient_role','threshold','days_remaining','service_url','event_type','event_message','expected_fingerprint','observed_fingerprint'))
CATEGORIES = ('expiry','expired','escalation','certificate','monitor','recovered')
FIELDS = ('common_name','not_before','not_after','days_remaining','threshold','fingerprint','serial','issuer','root_ca','intermediate_ca','sans','service_url','event_type','event_message','expected_fingerprint','observed_fingerprint')
TOP_KEYS = {'schema_version','language','label_native','demo_recipient','demo_message','event_message_label','footer','fields','audiences','alerts'}


def require_keys(value, keys, context):
    if not isinstance(value, dict) or set(value) != set(keys):
        got = set(value) if isinstance(value, dict) else set()
        raise ValueError(f'{context}: keys differ (missing={set(keys)-got}, extra={got-set(keys)})')


def check_text(text, context, multiline=True):
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f'{context}: empty or invalid text')
    if any((ord(c) < 32 and (not multiline or c not in '\n\r\t')) or ord(c) == 127 for c in text):
        raise ValueError(f'{context}: forbidden control character')
    text.encode('utf-8', errors='strict')
    return text


def placeholders(text, context):
    keys = re.findall(r'\{\{([a-z_]+)\}\}', text)
    remainder = re.sub(r'\{\{[a-z_]+\}\}', '', text)
    if '{' in remainder or '}' in remainder or set(keys)-VARIABLES:
        raise ValueError(f'{context}: malformed or unknown placeholder')
    return frozenset(keys)


def compose(catalog, alert, audience):
    event = catalog['alerts'][alert]
    person = catalog['audiences'][audience]
    category = event['category']
    subject = person['subject_prefix'] + event['subject']
    fields = ['common_name','not_before','not_after']
    if category in ('expiry','expired','escalation'):
        fields += ['days_remaining','threshold']
    fields += ['fingerprint','issuer','root_ca','intermediate_ca']
    if category == 'certificate':
        fields += ['serial','sans']
    if category in ('monitor','recovered'):
        fields = ['service_url'] + fields + ['event_type','expected_fingerprint','observed_fingerprint','event_message']
    details = '\n'.join(catalog['fields'][field] + ': {{' + field + '}}' for field in fields)
    body = '\n\n'.join((person['greeting'], event['text'], details, person['actions'][category], catalog['footer'])) + '\n'
    return subject, body


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load_catalogs(root):
    catalogs = {}
    routes = {}
    for language in LANGUAGES:
        path = root / 'web' / 'mail-locales' / f'{language}.json'
        catalog = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        require_keys(catalog, TOP_KEYS, str(path))
        if catalog['schema_version'] != 1 or catalog['language'] != language:
            raise ValueError(f'{path}: invalid schema version or language')
        require_keys(catalog['fields'], FIELDS, f'{language}/fields')
        require_keys(catalog['audiences'], AUDIENCES, f'{language}/audiences')
        require_keys(catalog['alerts'], ALERTS, f'{language}/alerts')
        for key in ('label_native','demo_recipient','demo_message','event_message_label','footer'):
            check_text(catalog[key], f'{language}/{key}', key == 'footer')
            placeholders(catalog[key], f'{language}/{key}')
        for key, value in catalog['fields'].items():
            check_text(value, f'{language}/fields/{key}', False)
            if placeholders(value, f'{language}/fields/{key}'):
                raise ValueError(f'{language}/fields/{key}: a label cannot contain variables')
        if catalog['fields']['event_message'] != catalog['event_message_label']:
            raise ValueError(f'{language}: inconsistent diagnostic label')
        for audience, person in catalog['audiences'].items():
            require_keys(person, ('label','subject_prefix','greeting','actions'), f'{language}/{audience}')
            require_keys(person['actions'], CATEGORIES, f'{language}/{audience}/actions')
            for key in ('label','subject_prefix','greeting'):
                check_text(person[key], f'{language}/{audience}/{key}', False)
                placeholders(person[key], f'{language}/{audience}/{key}')
            for category, action in person['actions'].items():
                check_text(action, f'{language}/{audience}/{category}')
                placeholders(action, f'{language}/{audience}/{category}')
        for alert, event in catalog['alerts'].items():
            require_keys(event, ('label','category','subject','text'), f'{language}/{alert}')
            if event['category'] not in CATEGORIES:
                raise ValueError(f'{language}/{alert}: unknown category')
            for key in ('label','subject','text'):
                check_text(event[key], f'{language}/{alert}/{key}', key == 'text')
                placeholders(event[key], f'{language}/{alert}/{key}')
            for audience in AUDIENCES:
                subject, body = compose(catalog, alert, audience)
                check_text(subject, f'{language}/{alert}/{audience}/subject', False)
                check_text(body, f'{language}/{alert}/{audience}/body')
                if len(subject.encode('utf-8')) > 998 or len(body.encode('utf-8')) > 16384:
                    raise ValueError(f'{language}/{alert}/{audience}: message too long')
                signature = (placeholders(subject, f'{language}/{alert}/subject'), placeholders(body, f'{language}/{alert}/body'))
                key = (alert, audience)
                if language != 'it' and signature != routes[key]:
                    raise ValueError(f'{language}/{alert}/{audience}: interpolation variables differ from Italian')
                if language == 'it':
                    routes[key] = signature
        catalogs[language] = catalog
    return catalogs


def c_string(value):
    # JSON escaping is C-compatible for our UTF-8 strings; avoid trigraph expansion.
    return json.dumps(value, ensure_ascii=False).replace('??', '?" "?')


def generate(root):
    catalogs = load_catalogs(root)
    result = ['/* Generated by scripts/embed_mail_templates.py; do not edit. */',
              '#ifndef CERTIFICATE_MANAGER_MAIL_CATALOGS_H', '#define CERTIFICATE_MANAGER_MAIL_CATALOGS_H',
              '#include <stddef.h>', '#include <string.h>',
              'typedef struct MailDefault { const char *language,*alert,*audience,*subject,*body; } MailDefault;',
              'typedef struct MailLanguage { const char *code,*label_native,*demo_recipient,*demo_message,*event_message_label,*role_self,*role_business,*role_technical,*role_other; } MailLanguage;',
              'static const MailLanguage mail_catalog_languages[] = {']
    for language, catalog in catalogs.items():
        values = [language, catalog['label_native'], catalog['demo_recipient'], catalog['demo_message'], catalog['event_message_label']]
        values += [catalog['audiences'][audience]['label'] for audience in AUDIENCES]
        result.append('    {' + ','.join(c_string(v) for v in values) + '},')
    result += ['};', 'static const MailDefault mail_catalog_defaults[] = {']
    for language, catalog in catalogs.items():
        for alert in ALERTS:
            for audience in AUDIENCES:
                subject, body = compose(catalog, alert, audience)
                result.append('    {' + ','.join(c_string(v) for v in (language, alert, audience, subject, body)) + '},')
    result += ['};',
      'static inline const MailLanguage *mail_language_lookup(const char *language) {',
      '    if (!language) language="it";',
      '    for (size_t i=0;i<sizeof(mail_catalog_languages)/sizeof(mail_catalog_languages[0]);i++) if (!strcmp(language,mail_catalog_languages[i].code)) return &mail_catalog_languages[i];',
      '    return NULL;', '}',
      'static inline const MailDefault *mail_default_lookup(const char *language,const char *alert,const char *audience) {',
      '    if (!language) language="it";', '    if (!alert || !audience) return NULL;',
      '    for (size_t i=0;i<sizeof(mail_catalog_defaults)/sizeof(mail_catalog_defaults[0]);i++) { const MailDefault *entry=&mail_catalog_defaults[i]; if (!strcmp(language,entry->language) && !strcmp(alert,entry->alert) && !strcmp(audience,entry->audience)) return entry; }',
      '    return NULL;', '}',
      'static inline const char *mail_event_label(const char *language,const char *event_type) {',
      '    if (!language) language="it";', '    if (!event_type) return "";']
    for language, catalog in catalogs.items():
        result.append('    if (!strcmp(language,' + c_string(language) + ')) {')
        for alert in ALERTS:
            result.append('        if (!strcmp(event_type,' + c_string(alert) + ')) return ' + c_string(catalog['alerts'][alert]['label']) + ';')
        result.append('    }')
    result += ['    return event_type;', '}',
      'static inline const char *mail_default_event_label(const char *language,const char *event_type) { return mail_event_label(language,event_type); }',
      'static inline const char *mail_default_role_label(const char *language,const char *audience) {',
      '    const MailLanguage *entry=mail_language_lookup(language); if (!entry || !audience) return "";',
      '    if (!strcmp(audience,"self")) return entry->role_self;', '    if (!strcmp(audience,"business")) return entry->role_business;',
      '    if (!strcmp(audience,"technical")) return entry->role_technical;', '    if (!strcmp(audience,"other")) return entry->role_other;', '    return audience;', '}',
      'static inline const char *mail_default_demo_name(const char *language) { const MailLanguage *entry=mail_language_lookup(language); return entry?entry->demo_recipient:""; }',
      'static inline const char *mail_default_demo_message(const char *language) { const MailLanguage *entry=mail_language_lookup(language); return entry?entry->demo_message:""; }',
      '#endif', '']
    return '\n'.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    content = generate(args.root)
    output = args.output or args.root / 'build' / 'mail_catalogs.h'
    output.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement only after all six catalogs pass validation.
    fd, temporary = tempfile.mkstemp(prefix=output.name + '.', dir=output.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
