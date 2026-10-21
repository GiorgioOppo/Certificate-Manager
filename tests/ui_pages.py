#!/usr/bin/env python3
"""Separate UI documents served directly, using an isolated local database."""

from html.parser import HTMLParser
import json
import unittest

import integration as core


PAGES = {
    "/": ("overview", "overview-expiries"),
    "/certificati": ("registry", "certificate-table"),
    "/servizi": ("monitoring", "monitor-form"),
    "/importa": ("import", "drop-zone"),
    "/verifica": ("verify", "remote-form"),
    "/promemoria": ("reminders", "notification-list"),
    "/email": ("delivery", "outbox-list"),
    "/workflow": ("workflow", "workflow-components"),
}


class PageDocument(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.body_pages = []
        self.views = []
        self.ids = []
        self.navigation = []
        self.asset_urls = []
        self.inline_handlers = []
        self.script_elements = []
        self.feed(content.decode("utf-8"))
        self.close()

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "body":
            self.body_pages.append(attrs.get("data-page"))
        if attrs.get("id"):
            self.ids.append(attrs["id"])
        if "data-view" in attrs:
            self.views.append((tag, attrs["data-view"]))
        if tag == "a" and "nav-link" in attrs.get("class", "").split():
            self.navigation.append(attrs)
        if tag in ("script", "img", "iframe", "source") and attrs.get("src"):
            self.asset_urls.append(attrs["src"])
        if tag == "link" and attrs.get("href"):
            self.asset_urls.append(attrs["href"])
        if tag == "script":
            self.script_elements.append(attrs)
        self.inline_handlers.extend(name for name in attrs if name.startswith("on"))


class UiPagesTests(unittest.TestCase):
    # Reuse only the local HTTP harness, without the certificate fixture suite.
    tearDown = core.ApplicationTests.tearDown
    start_server = core.ApplicationTests.start_server
    stop_server = core.ApplicationTests.stop_server
    http = core.ApplicationTests.http

    def setUp(self):
        core.ApplicationTests.setUp(self)
        self.start_server()

    def assert_page(self, path, expected_path):
        expected_view, required_control = PAGES[expected_path]
        status, headers, content = self.http("GET", path)
        self.assertEqual(status, 200, content)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        document = PageDocument(content)
        self.assertEqual(document.body_pages, [expected_view], path)
        self.assertEqual(document.views, [("section", expected_view)], path)
        self.assertEqual(len(document.ids), len(set(document.ids)), "ID duplicati: " + path)
        self.assertIn(required_control, document.ids, path)
        for other_path, (_, control) in PAGES.items():
            if other_path != expected_path:
                self.assertNotIn(control, document.ids, path)
        self.assertIn("details-dialog", document.ids, path)
        self.assertEqual({link.get("href") for link in document.navigation}, set(PAGES), path)
        self.assertEqual(
            [link.get("href") for link in document.navigation if link.get("aria-current") == "page"],
            [expected_path], path,
        )
        csp = headers.get("Content-Security-Policy", "")
        for directive in ("script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "form-action 'self'"):
            self.assertIn(directive, csp)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        return content

    def test_each_navigation_destination_is_a_separate_document(self):
        documents = []
        for path in PAGES:
            with self.subTest(path=path):
                documents.append(self.assert_page(path, path))
        self.assertEqual(len(set(documents)), len(PAGES))

    def test_direct_links_query_context_and_refresh(self):
        # Context is read by page JavaScript, without turning it into an API route.
        for path in ("/servizi?certificate_id=1", "/verifica?certificate_id=1", "/workflow?lang=it"):
            expected_path = path.split("?", 1)[0]
            with self.subTest(path=path):
                first = self.assert_page(path, expected_path)
                self.assertEqual(self.assert_page(path, expected_path), first)
        self.assert_page("/certificati/", "/certificati")
        self.assert_page("/workflow/", "/workflow")

    def test_workflow_uses_only_embedded_local_assets(self):
        content = self.assert_page("/workflow", "/workflow")
        document = PageDocument(content)
        for diagram in ("workflow-component-diagram", "workflow-lifecycle-diagram", "workflow-renewal-diagram"):
            self.assertIn(diagram, document.ids)
        self.assertTrue(document.asset_urls)
        for asset in document.asset_urls:
            self.assertTrue(asset.startswith("/") and not asset.startswith("//"), asset)
            status, _, body = self.http("GET", asset)
            self.assertEqual(status, 200, asset)
            self.assertTrue(body, asset)
        self.assertTrue(document.script_elements)
        self.assertTrue(all(script.get("src") for script in document.script_elements))
        self.assertEqual(document.inline_handlers, [])

    def test_missing_pages_do_not_fall_back_to_a_long_single_document(self):
        for path in ("/pagina-inesistente", "/servizi/altro", "//", "/api/pagina-inesistente"):
            with self.subTest(path=path):
                status, headers, content = self.http("GET", path)
                self.assertEqual(status, 404, content)
                self.assertIn("application/json", headers.get("Content-Type", ""))
                self.assertIn("error", json.loads(content))
        status, headers, content = self.http("GET", "/api/state")
        self.assertEqual(status, 200, content)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertIn("csrf_token", json.loads(content))
        status, _, _ = self.http("POST", "/api/check", body=b"")
        self.assertEqual(status, 403)

    def test_shared_assets_remain_available_with_security_headers(self):
        for path, content_type in (("/app.css", "text/css"), ("/app.js", "text/javascript")):
            with self.subTest(path=path):
                status, headers, content = self.http("GET", path)
                self.assertEqual(status, 200, content)
                self.assertIn(content_type, headers.get("Content-Type", ""))
                self.assertTrue(content)
                self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
                self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
