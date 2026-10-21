#!/usr/bin/env python3
"""Multilingual documents and assets over HTTP, with unchanged API user data."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode

import ui_pages as ui


LANGUAGES = {
    "it": "Italiano",
    "en": "English",
    "fr": "Français",
    "es": "Español",
    "zh-CN": "简体中文",
    "ja": "日本語",
}


class LanguageDocument(ui.PageDocument):
    def __init__(self, content):
        self.language_selects = 0
        self.options = []
        self.scripts = []
        self.in_languages = False
        self.option = None
        self.workflow_depth = 0
        self.workflow_keys = set()
        super().__init__(content)

    def handle_starttag(self, tag, attributes):
        super().handle_starttag(tag, attributes)
        attrs = dict(attributes)
        if tag == "section" and (self.workflow_depth or attrs.get("data-view") == "workflow"):
            self.workflow_depth += 1
        if self.workflow_depth:
            self.workflow_keys.update(value for name, value in attributes
                                      if name == "data-i18n" or name.startswith("data-i18n-"))
        if tag == "select" and attrs.get("id") == "language-select":
            self.language_selects += 1
            self.in_languages = True
        if tag == "option" and self.in_languages:
            self.option = [attrs.get("value"), ""]
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs)

    def handle_data(self, value):
        if self.option is not None:
            self.option[1] += value

    def handle_endtag(self, tag):
        if tag == "section" and self.workflow_depth:
            self.workflow_depth -= 1
        if tag == "option" and self.option is not None:
            self.options.append(tuple(self.option))
            self.option = None
        if tag == "select":
            self.in_languages = False


class I18nHttpTests(unittest.TestCase):
    # Reuse only the isolated local HTTP harness; no inherited fixture/test suite.
    setUp = ui.UiPagesTests.setUp
    tearDown = ui.UiPagesTests.tearDown
    start_server = ui.UiPagesTests.start_server
    stop_server = ui.UiPagesTests.stop_server
    http = ui.UiPagesTests.http

    def assert_security_headers(self, headers):
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        csp = headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("'unsafe-inline'", csp)

    def test_language_assets_are_served_as_utf8_javascript_with_csp(self):
        for path in ("/i18n.js", "/i18n-catalogs.js"):
            with self.subTest(path=path):
                status, headers, body = self.http("GET", path)
                self.assertEqual(status, 200, body[:200])
                self.assertIn("text/javascript", headers.get("Content-Type", ""))
                self.assertIn("charset=utf-8", headers.get("Content-Type", ""))
                decoded = body.decode("utf-8", errors="strict")
                self.assertTrue(decoded.strip())
                self.assert_security_headers(headers)
                if path == "/i18n-catalogs.js":
                    # Non-Latin translations must survive the actual byte transport.
                    self.assertRegex(decoded, "[\u3040-\u30ff]")
                    self.assertRegex(decoded, "[\u4e00-\u9fff]")

    def test_every_document_offers_six_autonyms_and_loads_translation_assets(self):
        for path, (view, _) in ui.PAGES.items():
            with self.subTest(path=path):
                status, headers, body = self.http("GET", path)
                self.assertEqual(status, 200, body[:200])
                document = LanguageDocument(body)
                self.assertEqual(document.body_pages, [view])
                self.assertEqual(document.language_selects, 1)
                self.assertEqual(len(document.options), len(LANGUAGES))
                self.assertEqual(dict(document.options), LANGUAGES)
                sources = [script["src"] for script in document.scripts]
                for asset in ("/i18n-catalogs.js", "/i18n.js", "/app.js"):
                    self.assertIn(asset, sources)
                    self.assertIn("defer", document.scripts[sources.index(asset)])
                self.assertLess(sources.index("/i18n-catalogs.js"), sources.index("/i18n.js"))
                self.assertLess(sources.index("/i18n.js"), sources.index("/app.js"))
                self.assert_security_headers(headers)

    def test_direct_language_links_preserve_the_requested_page(self):
        for path, (view, _) in ui.PAGES.items():
            for language in LANGUAGES:
                with self.subTest(path=path, language=language):
                    status, headers, body = self.http("GET", path + "?" + urlencode({"lang": language}))
                    self.assertEqual(status, 200, body[:200])
                    self.assertIn("text/html", headers.get("Content-Type", ""))
                    document = LanguageDocument(body)
                    self.assertEqual(document.body_pages, [view])
                    self.assertEqual(document.views, [("section", view)])
                    self.assertEqual(dict(document.options), LANGUAGES)
        # Browser language selection must not turn an unknown path into a valid page.
        status, _, _ = self.http("GET", "/not-a-page?lang=ja")
        self.assertEqual(status, 404)

    def test_workflow_explanations_and_diagrams_are_available_in_all_six_languages(self):
        status, _, body = self.http("GET", "/workflow")
        self.assertEqual(status, 200, body[:200])
        document = LanguageDocument(body)
        self.assertTrue(document.workflow_keys, "Workflow content must participate in localization")
        status, _, body = self.http("GET", "/i18n-catalogs.js")
        self.assertEqual(status, 200, body[:200])
        source = body.decode("utf-8")
        prefix = "window.CertificateManagerCatalogs="
        self.assertTrue(source.startswith(prefix))
        catalogs, _ = json.JSONDecoder().raw_decode(source[len(prefix):])
        for language in LANGUAGES:
            with self.subTest(language=language):
                self.assertIn(language, catalogs)
                for key in document.workflow_keys:
                    self.assertIn(key, catalogs[language], (language, key))
                    self.assertTrue(catalogs[language][key].strip(), (language, key))
        # These explanations must have genuine translations rather than an
        # untranslated Italian fallback for the entire page.
        for language in set(LANGUAGES) - {"it"}:
            self.assertTrue(any(catalogs[language][key] != catalogs["it"][key]
                                for key in document.workflow_keys), language)

    def test_languages_do_not_translate_certificate_or_contact_data_in_the_api(self):
        with tempfile.TemporaryDirectory(prefix="certificate-manager-i18n-") as directory:
            certificate = Path(directory) / "literal-name.pem"
            key = Path(directory) / "temporary.key"
            result = subprocess.run([
                os.environ.get("OPENSSL", "openssl"), "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-sha256", "-days", "120", "-subj", "/CN=Valido",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-keyout", str(key), "-out", str(certificate),
            ], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            status, _, body = self.http("POST", "/api/certificates", certificate.read_bytes(), {
                "Content-Type": "application/octet-stream", "X-Filename": "literal-name.pem",
                "X-CSRF-Token": self.token,
            })
            self.assertEqual(status, 200, body)
        status, _, body = self.http("GET", "/api/state")
        self.assertEqual(status, 200, body)
        certificate = json.loads(body)["certificates"][0]
        self.assertEqual(certificate["common_name"], "Valido")
        self.assertEqual(certificate["status"], "healthy")
        contacts = [
            ("role", "business"), ("name", "Valido"), ("email", "valido@example.test"),
            ("role", "technical"), ("name", "李明 / 山田"), ("email", "technical@example.test"),
        ]
        status, _, body = self.http("PUT", f"/api/certificates/{certificate['id']}/contacts",
                                    urlencode(contacts).encode(), {
            "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": self.token,
        })
        self.assertEqual(status, 200, body)
        for language in LANGUAGES:
            with self.subTest(language=language):
                status, _, _ = self.http("GET", "/certificati?" + urlencode({"lang": language}))
                self.assertEqual(status, 200)
                status, _, body = self.http("GET", "/api/state", headers={"Accept-Language": language})
                self.assertEqual(status, 200, body)
                current = json.loads(body)["certificates"][0]
                for field in ("id", "common_name", "subject", "issuer", "status", "fingerprint"):
                    self.assertEqual(current[field], certificate[field], (language, field))
                self.assertEqual({item["role"]: item["name"] for item in current["contacts"]}, {
                    "business": "Valido", "technical": "李明 / 山田",
                })
                self.assertEqual(json.loads(body)["smtp"]["security"], "starttls")


if __name__ == "__main__":
    unittest.main(verbosity=2)
