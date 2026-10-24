(() => {
  'use strict';

  const catalogs = window.CertificateManagerCatalogs;
  const languages = ['it', 'en', 'fr', 'es', 'zh-CN', 'ja'];
  const locales = { it: 'it-IT', en: 'en-GB', fr: 'fr-FR', es: 'es-ES', 'zh-CN': 'zh-CN', ja: 'ja-JP' };
  const preferenceKey = 'certificate-manager-language';
  const normalizeLanguage = value => {
    const raw = String(value || '').toLowerCase();
    if (raw === 'zh' || raw.startsWith('zh-')) return 'zh-CN';
    const short = raw.split('-')[0];
    return languages.includes(short) ? short : null;
  };
  let stored;
  try { stored = window.localStorage.getItem(preferenceKey); } catch (_) { /* Private browsing can disable storage. */ }
  const requested = new URLSearchParams(window.location.search).get('lang');
  const preferred = (window.navigator.languages || [window.navigator.language]).map(normalizeLanguage).find(Boolean);
  const language = normalizeLanguage(requested) || normalizeLanguage(stored) || preferred || 'en';
  const format = (text, values = []) => text.replace(/\{(\d+)\}/g, (match, index) => index < values.length ? String(values[index]) : match);
  const t = (key, values = []) => format((catalogs[language] && catalogs[language][key]) || catalogs.it[key] || key, values);
  const sourceKeys = new Map(Object.entries(catalogs.it).map(([key, value]) => [value, key]));
  const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const serverPatterns = (window.CertificateManagerServerMessages || []).map(key => {
    const source = catalogs.it[key];
    if (!source || !/\{\d+\}/.test(source)) return null;
    const indices = [];
    let expression = '^';
    let start = 0;
    for (const match of source.matchAll(/\{(\d+)\}/g)) {
      expression += escapeRegex(source.slice(start, match.index)) + '([\\s\\S]*?)';
      indices.push(Number(match[1]));
      start = match.index + match[0].length;
    }
    expression += escapeRegex(source.slice(start)) + '$';
    return { key, indices, pattern: new RegExp(expression), specificity: source.replace(/\{\d+\}/g, '').length };
  }).filter(Boolean).sort((a, b) => b.specificity - a.specificity);
  // Only these positions are backend diagnostics; all other arguments are data.
  const diagnosticArguments = {
    m_13a96f788f14: [1], m_39c378694c91: [1], m_441d47593e06: [1],
    m_85973eee8e01: [1], m_954efc52b40c: [1],
    m_29db299e77f2: [0], m_8ac5cc509814: [0], m_a2357c6874a5: [0], m_cafebc3d6e1b: [0]
  };

  function serverMessage(value, depth = 0) {
    if (typeof value !== 'string' || !value || depth > 3) return value;
    const key = sourceKeys.get(value);
    if (key) return t(key);
    for (const entry of serverPatterns) {
      const match = entry.pattern.exec(value);
      if (!match) continue;
      const values = [];
      // Captures can contain a CN, filename, URL or a person's name. Never translate data.
      entry.indices.forEach((index, position) => { values[index] = match[position + 1]; });
      for (const index of diagnosticArguments[entry.key] || []) values[index] = serverMessage(values[index], depth + 1);
      return t(entry.key, values);
    }
    return value; // Keep unrecognized OpenSSL/curl diagnostics intact.
  }

  function localizeResponse(value, context = '') {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) { value.forEach(item => localizeResponse(item, context)); return value; }
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === 'string' && (key === 'message' || key === 'error' || key.endsWith('_error') || (key === 'subject' && context === 'outbox' && !value.template_alert))) value[key] = serverMessage(child);
      else if (child && typeof child === 'object') localizeResponse(child, key);
    }
    return value;
  }

  function applyStaticTranslations() {
    document.documentElement.lang = language;
    document.documentElement.dir = 'ltr';
    for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = t(node.dataset.i18n);
    for (const attribute of ['aria-label', 'title', 'placeholder', 'alt']) {
      for (const node of document.querySelectorAll(`[data-i18n-${attribute}]`)) node.setAttribute(attribute, t(node.getAttribute(`data-i18n-${attribute}`)));
    }
  }

  function localURL(destination) {
    const url = new URL(destination, window.location.href);
    if (url.origin === new URL(window.location.href).origin && !url.pathname.startsWith('/api/')) url.searchParams.set('lang', language);
    return url.pathname + url.search + url.hash;
  }

  window.CertificateI18n = Object.freeze({ language, locale: locales[language], languages, t, serverMessage, localizeResponse, normalizeLanguage, localURL });
  if (typeof document === 'undefined') return;
  applyStaticTranslations();
  const selector = document.getElementById('language-select');
  if (!selector) return;
  selector.value = language;
  selector.addEventListener('change', () => {
    const selected = normalizeLanguage(selector.value);
    if (!selected || selected === language) return;
    const event = new CustomEvent('certificate-language-change', { cancelable: true });
    if (!window.dispatchEvent(event)) { selector.value = language; return; }
    try { window.localStorage.setItem(preferenceKey, selected); } catch (_) { /* The query parameter also preserves the chosen language on reload. */ }
    const url = new URL(window.location.href);
    url.searchParams.set('lang', selected);
    window.location.replace(url.pathname + url.search + url.hash);
  });
  // Keep navigation usable even when localStorage is unavailable.
  if (requested) {
    for (const link of document.querySelectorAll('a[href^="/"]')) {
      const url = new URL(link.getAttribute('href'), window.location.href);
      if (url.pathname.startsWith('/api/')) continue;
      url.searchParams.set('lang', language);
      link.setAttribute('href', url.pathname + url.search + url.hash);
    }
  }
})();
