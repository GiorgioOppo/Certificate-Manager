# Translating Certificate Manager

The web interface supports Italian (`it`), English (`en`), French (`fr`), Spanish (`es`), Simplified Chinese (`zh-CN`) and Japanese (`ja`). Select a language in the page header or open a page with `?lang=en`. The browser remembers the preference locally. A supported browser language is used on a first visit; English is the fallback.

## Catalogs and messages

`web/locales/it.json` is the canonical source catalog. Each other locale must contain exactly the same keys. Message IDs are stable; existing IDs must not be renamed during translation. New IDs follow `m_` plus the first 12 hexadecimal characters of the SHA-256 digest of the Italian source text.

Keep all `{0}`, `{1}` and other numbered placeholders, including their multiplicity. Their order may change to fit the target language. Preserve significant leading and trailing spaces in fragments. Do not translate protocols, field names, command names, example hostnames or email addresses unless the message is explaining them in prose.

Static HTML uses `data-i18n` for text and `data-i18n-aria-label`, `data-i18n-title` or `data-i18n-placeholder` for attributes. JavaScript uses `msg('message_id', [value0, value1])`. Values are inserted as literal text with `textContent`; they are never HTML or executable templates. Date and time formatters use the selected locale and the browser's time zone.

Certificate subjects, CA distinguished names, URLs, filenames, fingerprints, email addresses, contact names and SMTP settings are data. Keep them unchanged. Do not pass arbitrary data through the message lookup function. API status codes, role names and routes remain language-independent.

## Server diagnostics

The C backend retains its original messages and API contract. `web/server-messages.json` lists known diagnostic templates that the browser may translate. Captured arguments are data by default. `diagnosticArguments` in `web/i18n.js` explicitly identifies the few nested error positions that are diagnostics; do not expand this list to certificate names or URLs. Unknown OpenSSL, curl or SQLite diagnostics remain intact for troubleshooting.

The command-line interface, generated `.eml` messages and their attachments remain in Italian or their original certificate encoding. A browser language preference does not change outgoing communications or stored records.

## Validation

Run `make test`. The build rejects missing translations, undefined message references and altered placeholders. Node tests also verify whitespace, language selection, literal placeholder data, URL preservation and diagnostic handling. Browser checks should cover all languages, a populated registry, contacts with non-Latin names, filters, details, SMTP drafts and narrow screens.

Language changes reload the current page and preserve its query parameters and registry filters. Save or cancel changes to contacts, SMTP or monitor forms before changing language. Switching language is blocked while a mutation is running.
