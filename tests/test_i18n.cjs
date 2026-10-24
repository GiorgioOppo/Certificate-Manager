'use strict';

// Exercise the real runtime without a DOM. Browser rendering is checked separately.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const languages = ['it', 'en', 'fr', 'es', 'zh-CN', 'ja'];
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');
const catalogs = Object.fromEntries(languages.map(language => [language, JSON.parse(read(`web/locales/${language}.json`))]));
const serverKeys = JSON.parse(read('web/server-messages.json'));
const runtime = read('web/i18n.js');
const keys = Object.keys(catalogs.it).sort();
const keyFor = source => {
  const pair = Object.entries(catalogs.it).find(([, value]) => value === source);
  assert.ok(pair, `Missing source message: ${source}`);
  return pair[0];
};
const interpolate = (text, values) => text.replace(/\{(\d+)\}/g, (match, index) => index < values.length ? String(values[index]) : match);

function load({ query = '', stored = null, browser = ['it-IT'], storageThrows = false } = {}) {
  const window = {
    CertificateManagerCatalogs: catalogs,
    CertificateManagerServerMessages: serverKeys,
    navigator: { languages: browser, language: browser[0] },
    location: { search: query, href: `http://127.0.0.1:8080/certificati${query}` },
    localStorage: { getItem() { if (storageThrows) throw new Error('Storage unavailable'); return stored; } }
  };
  vm.runInNewContext(runtime, { window, URL, URLSearchParams }, { filename: 'web/i18n.js', timeout: 1000 });
  assert.ok(Object.isFrozen(window.CertificateI18n));
  return window.CertificateI18n;
}

let passed = 0;
function test(name, callback) {
  callback();
  passed++;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test('six catalogs contain identical keys, placeholders and significant whitespace', () => {
  for (const language of languages) {
    const catalog = catalogs[language];
    assert.deepEqual(Object.keys(catalog).sort(), keys, language);
    for (const key of keys) {
      assert.equal(typeof catalog[key], 'string', `${language}:${key}`);
      assert.ok(catalog[key].length > 0, `${language}:${key}`);
      assert.deepEqual(catalog[key].match(/\{\d+\}/g)?.sort() || [], catalogs.it[key].match(/\{\d+\}/g)?.sort() || [], `${language}:${key}: placeholders`);
      assert.equal(catalog[key].match(/^\s*/)[0], catalogs.it[key].match(/^\s*/)[0], `${language}:${key}: leading whitespace`);
      assert.equal(catalog[key].match(/\s*$/)[0], catalogs.it[key].match(/\s*$/)[0], `${language}:${key}: trailing whitespace`);
    }
  }
});

test('all static, dynamic and server translation references exist', () => {
  const references = [...serverKeys];
  for (const match of read('web/index.html').matchAll(/data-i18n(?:-[\w-]+)?="([^"]+)"/g)) references.push(match[1]);
  for (const match of read('web/app.js').matchAll(/\bmsg\(\s*['"]([^'"]+)['"]/g)) references.push(match[1]);
  for (const [filename,prefix] of [['extensions.js','flow.x_'],['operations-ui.js','ops.'],['incidents-ui.js','incident.'],['mail-templates-ui.js','mailTemplates.']]) {
    for(const match of read('web/'+filename).matchAll(/(?<![\w.])t\('([^']+)'\s*[,)]/g))references.push(prefix+match[1]);
  }
  for (const alert of ['expiry_45','expiry_30','expiry_15','expiry_2','expired','expiry','escalation','certificate','unreachable','tls_error','changed','verification_error','error','recovered']) references.push(`mailTemplates.alert_${alert}`);
  for (const audience of ['self','business','technical','other']) references.push(`mailTemplates.audience_${audience}`, `mailTemplates.audience_${audience}_help`);
  for (const key of ['reset_help_active','reset_help_inactive','reset_done_active','reset_done_inactive']) references.push(`mailTemplates.${key}`);
  for(const match of read('src/lifecycle.c').matchAll(/(?:FAIL_IF\([^\n]+,|reason\(out,&first,)\s*"([a-z_]+)"/g)) references.push('ops.reason_'+match[1]);
  for (const key of references) assert.ok(Object.hasOwn(catalogs.it, key), `Unknown translation reference ${key}`);
  assert.equal(new Set(serverKeys).size, serverKeys.length, 'Duplicate server message references');
});

test('language normalization accepts supported regional variants only', () => {
  const i18n = load();
  for (const [input, expected] of [['en-GB', 'en'], ['EN-us', 'en'], ['fr-CA', 'fr'], ['it-IT', 'it'], ['es-MX', 'es'], ['zh', 'zh-CN'], ['zh-Hant-TW', 'zh-CN'], ['ZH-cn', 'zh-CN'], ['ja-JP', 'ja'], ['de-DE', null], ['', null], [null, null], ['../../en', null]]) {
    assert.equal(i18n.normalizeLanguage(input), expected, String(input));
  }
});

test('query, saved preference and browser language have the correct priority', () => {
  assert.equal(load({ query: '?lang=fr-CA', stored: 'es', browser: ['ja-JP'] }).language, 'fr');
  assert.equal(load({ query: '?lang=invalid', stored: 'es-MX', browser: ['ja-JP'] }).language, 'es');
  assert.equal(load({ stored: 'invalid', browser: ['de-DE', 'zh-TW', 'en-US'] }).language, 'zh-CN');
  assert.equal(load({ browser: ['de-DE'] }).language, 'en');
  assert.equal(load({ browser: [] }).language, 'en');
  assert.equal(load({ query: '?lang=ja', storageThrows: true }).language, 'ja');
  assert.equal(load({ storageThrows: true, browser: ['fr-FR'] }).language, 'fr');
});

test('all six languages format literal adversarial placeholder values once', () => {
  const key = keyFor('Confronto con il certificato nel registro: {0} (ID {1})');
  const values = ['<img src=x onerror=alert(1)> $& $1 {1} {0} \\ 日', 73];
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    assert.equal(i18n.language, language);
    assert.equal(i18n.t(key, values), interpolate(catalogs[language][key], values));
    assert.equal(i18n.t(key), catalogs[language][key], 'Missing values stay as placeholders');
    assert.equal(i18n.t('__unknown_translation_key__'), '__unknown_translation_key__');
  }
});

test('known server errors localize while unrecognized diagnostics remain literal', () => {
  const source = 'Certificato non trovato.';
  const nestedSource = 'Errore archivio: Memoria insufficiente.';
  const unknown = 'OpenSSL: certificate verify failed at /tmp/Valido.pem (0x123)';
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    assert.equal(i18n.serverMessage(source), catalogs[language][keyFor(source)]);
    assert.equal(i18n.serverMessage(nestedSource), interpolate(catalogs[language][keyFor('Errore archivio: {0}')], [catalogs[language][keyFor('Memoria insufficiente.')]]));
    assert.equal(i18n.serverMessage(unknown), unknown);
    for (const value of [null, 17, false, '']) assert.equal(i18n.serverMessage(value), value);
  }
});

test('server messages preserve certificate names, addresses and literal placeholder content', () => {
  const cases = [
    ['Certificato HTTPS scaduto: {0}', ['Valido']],
    ['Certificato HTTPS firmato per {0} - validità fino al {1}', ['Scaduto', '2027-04-01']],
    ['Scadenza certificato HTTPS {0}: soglia {1} giorni', ['Nessun referente tecnico', 15]],
    ['Impossibile aprire il certificato: {0}.', ['Certificato non trovato.']],
    ['Il servizio {0} non e raggiungibile. {1}', ['https://Valido.example/{0}?x=$&', 'Memoria insufficiente.']]
  ];
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    for (const [source, values] of cases) {
      const expectedValues = values.slice();
      // The monitor's final argument is explicitly a backend diagnostic.
      if (source.startsWith('Il servizio ')) expectedValues[1] = catalogs[language][keyFor(values[1])];
      assert.equal(i18n.serverMessage(interpolate(source, values)), interpolate(catalogs[language][keyFor(source)], expectedValues), `${language}: ${source}`);
    }
  }
});

test('custom email subjects remain literal for every UI language', () => {
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    const subject = 'Certificato HTTPS scaduto: localhost';
    const data = { outbox: [{ template_alert: 'expired', template_audience: 'self', template_copy: true, template_language: 'ja', subject }] };
    i18n.localizeResponse(data);
    assert.equal(data.outbox[0].subject, subject, `${language}: custom subject`);
    assert.equal(data.outbox[0].template_language, 'ja', `${language}: sending language`);
  }
});

test('message template variants remain independent of interface translation', () => {
  const subjects = { it: 'Certificato scaduto', en: 'Certificate expired', fr: 'Certificat expiré', es: 'Certificado caducado', 'zh-CN': '证书已过期', ja: '証明書の有効期限が切れました' };
  for (const uiLanguage of languages) {
    const i18n = load({ query: `?lang=${uiLanguage}` });
    const data = { templates: languages.map(language => ({ alert: 'expired', audience: 'business', language, active_language: 'fr', subject: subjects[language], body: `{{recipient_name}}\n${subjects[language]}\n{{fingerprint}}` })) };
    const original = JSON.stringify(data);
    i18n.localizeResponse(data);
    assert.equal(JSON.stringify(data), original, `${uiLanguage}: localized interface must not rewrite stored message variants`);
  }
});

test('response localization preserves certificate data, contact data and SMTP values', () => {
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    const data = {
      certificates: [{ common_name: 'Valido', subject: 'Scaduto', issuer: 'Emittente', root_ca: 'Root CA', intermediate_ca: 'CA intermedia', sans: ['Valido', 'https://Valido.example'], source: '/tmp/Valido.pem', fingerprint: '00:FF', contacts: [{ role: 'business', name: 'Nessun referente', email: 'Valido@example.test' }] }],
      smtp: { host: 'Valido', username: 'Valido', from_email: 'Scaduto@example.test', error: 'Configurazione SMTP mancante.' },
      monitors: [{ target: 'https://Valido.example/{0}', common_name: 'Scaduto', last_error: 'Certificato non trovato.' }],
      monitor_events: [{ target: 'https://Scaduto.example', common_name: 'Valido', message: 'Il servizio https://Scaduto.example non e raggiungibile. Memoria insufficiente.' }],
      outbox: [{ common_name: 'Valido', email: 'Valido@example.test', subject: 'Certificato HTTPS scaduto: Valido', last_error: 'Certificato non trovato.' }],
      message: 'Configurazione SMTP salvata.'
    };
    const original = JSON.parse(JSON.stringify(data));
    assert.equal(i18n.localizeResponse(data), data, 'Return the original object');
    assert.deepEqual(data.certificates, original.certificates, `${language}: certificate and contact data`);
    for (const key of ['host', 'username', 'from_email']) assert.equal(data.smtp[key], original.smtp[key]);
    for (const key of ['target', 'common_name']) {
      assert.equal(data.monitors[0][key], original.monitors[0][key]);
      assert.equal(data.monitor_events[0][key], original.monitor_events[0][key]);
    }
    assert.equal(data.outbox[0].common_name, 'Valido');
    assert.equal(data.outbox[0].email, 'Valido@example.test');
    assert.equal(data.outbox[0].subject, interpolate(catalogs[language][keyFor('Certificato HTTPS scaduto: {0}')], ['Valido']));
    assert.equal(data.message, catalogs[language][keyFor('Configurazione SMTP salvata.')]);
    assert.equal(data.smtp.error, catalogs[language][keyFor('Configurazione SMTP mancante.')]);
    assert.equal(data.monitors[0].last_error, catalogs[language][keyFor('Certificato non trovato.')]);
  }
});

test('local navigation preserves language, certificate context, queries and fragments without storage', () => {
  for (const language of languages) {
    const i18n = load({ query: `?certificate_id=7&lang=${language}`, storageThrows: true });
    const input = '/servizi?certificate_id=19&search=Root%20CA&status=valid#monitor-form';
    const url = new URL(i18n.localURL(input), 'http://127.0.0.1:8080');
    assert.equal(url.pathname, '/servizi');
    assert.equal(url.hash, '#monitor-form');
    assert.equal(url.searchParams.get('certificate_id'), '19');
    assert.equal(url.searchParams.get('search'), 'Root CA');
    assert.equal(url.searchParams.get('status'), 'valid');
    assert.equal(url.searchParams.get('lang'), language);
    assert.equal(url.searchParams.getAll('lang').length, 1);
    const replaced = new URL(i18n.localURL('/verifica?lang=de&certificate_id=2'), 'http://127.0.0.1:8080');
    assert.equal(replaced.searchParams.get('lang'), language);
    assert.equal(replaced.searchParams.get('certificate_id'), '2');
    assert.equal(i18n.localURL('/api/certificates/1/download?chain=1'), '/api/certificates/1/download?chain=1');
  }
});

test('only allowlisted diagnostic arguments are recursively translated', () => {
  const wrappers = {
    m_13a96f788f14: 1, m_39c378694c91: 1, m_441d47593e06: 1,
    m_85973eee8e01: 1, m_954efc52b40c: 1,
    m_29db299e77f2: 0, m_8ac5cc509814: 0, m_a2357c6874a5: 0, m_cafebc3d6e1b: 0
  };
  const nestedKey = keyFor('Certificato HTTPS scaduto: {0}');
  for (const language of languages) {
    const i18n = load({ query: `?lang=${language}` });
    for (const [key, index] of Object.entries(wrappers)) {
      const input = index ? ['https://Valido.example/{0}?q=$&', 'Certificato HTTPS scaduto: Valido'] : ['Certificato HTTPS scaduto: Valido'];
      const expected = input.slice();
      expected[index] = interpolate(catalogs[language][nestedKey], ['Valido']);
      assert.equal(i18n.serverMessage(interpolate(catalogs.it[key], input)), interpolate(catalogs[language][key], expected), `${language}: ${key}`);
    }
  }
});

process.stdout.write(`i18n: ${passed} checks passed across ${languages.length} languages.\n`);
