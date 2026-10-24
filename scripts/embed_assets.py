#!/usr/bin/env python3
"""Build independent HTML pages and embed all UI assets in the C executable.

The source template shares navigation and dialogs, while each generated document
contains exactly one data-view section. No JavaScript is needed to select a page.
"""
from dataclasses import dataclass
import hashlib
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys


@dataclass(frozen=True)
class Page:
    name: str
    route: str
    title: str
    eyebrow: str
    description: str


PAGES = (
    Page("overview", "/", "Panoramica", "Centro di controllo",
         "Scadenze, servizi monitorati e attività del registro, in un unico posto."),
    Page("registry", "/certificati", "Registro certificati", "Certificati HTTPS",
         "Cerca i certificati e gestisci referenti, catene di certificazione e rinnovi."),
    Page("monitoring", "/servizi", "Servizi monitorati", "Controllo periodico",
         "Controlla la raggiungibilità dei servizi e le variazioni dei certificati."),
    Page("import", "/importa", "Importa certificati", "Aggiungi al registro",
         "Carica i certificati e le loro catene per estrarre automaticamente i dati."),
    Page("verify", "/verifica", "Verifica URL", "Verifica TLS",
         "Controlla un servizio HTTPS e recupera il certificato che presenta."),
    Page("reminders", "/promemoria", "Promemoria", "Scadenze dei certificati",
         "Consulta gli avvisi di scadenza e gestisci le notifiche desktop."),
    Page("delivery", "/email", "Coda email", "Comunicazioni",
         "Consulta i promemoria ai referenti e le distribuzioni ai referenti tecnici."),
    Page("workflow", "/workflow", "Workflow", "Come funziona",
         "Scopri come dialogano interfaccia, registro, controlli e invii email."),
    Page("directory", "/rubrica", "Rubrica referenti", "Persone e gruppi",
         "Gestisci persone, gruppi e assegnazioni condivise ai certificati."),
    Page("renewals", "/rinnovi", "Agenda rinnovi", "Pianificazione operativa",
         "Pianifica richieste, rinnovi e installazioni e controlla le attività in ritardo."),
)

LANGUAGES = ("it", "en", "fr", "es", "zh-CN", "ja")


def message_key(text):
    return "m_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def load_catalogs(root):
    """Fail the build on untranslated messages or damaged interpolation tokens."""
    catalogs = {language: json.loads((root / "web" / "locales" / f"{language}.json").read_text(encoding="utf-8"))
                for language in LANGUAGES}
    source = catalogs["it"]
    for language, catalog in catalogs.items():
        if catalog.keys() != source.keys():
            raise ValueError(f"Translation keys differ for {language}: missing={source.keys() - catalog.keys()}, extra={catalog.keys() - source.keys()}")
        for key, text in catalog.items():
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"Empty translation: {language}/{key}")
            if sorted(re.findall(r"\{\d+\}", text)) != sorted(re.findall(r"\{\d+\}", source[key])):
                raise ValueError(f"Translation placeholders differ: {language}/{key}")
    template = (root / "web" / "index.html").read_text(encoding="utf-8")
    app = '\n'.join((root / "web" / filename).read_text(encoding="utf-8") for filename in ("app.js","extensions.js","operations-ui.js","incidents-ui.js","mail-templates-ui.js"))
    references = set(re.findall(r'data-i18n(?:-[a-z-]+)?="([^"]+)"', template))
    references.update(re.findall(r"\bmsg\('([^']+)'", app))
    server_keys = json.loads((root / "web" / "server-messages.json").read_text(encoding="utf-8"))
    references.update(server_keys)
    for page in PAGES:
        references.update(message_key(text) for text in (page.title, page.eyebrow, page.description, f"{page.title} — Certificati HTTPS"))
    if references - source.keys():
        raise ValueError(f"Undefined translation keys: {references - source.keys()}")
    return catalogs, server_keys


@dataclass
class Element:
    tag: str
    attrs: dict
    start: int
    content_start: int
    content_end: int = 0
    end: int = 0


class Template(HTMLParser):
    """Locate complete elements without assuming how sections are nested."""

    VOID_TAGS = frozenset((
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    ))

    def __init__(self, source):
        super().__init__(convert_charrefs=False)
        self.source = source
        self.line_offsets = []
        offset = 0
        for line in source.splitlines(keepends=True):
            self.line_offsets.append(offset)
            offset += len(line)
        self.elements = []
        self.stack = []
        self.feed(source)
        self.close()
        if self.stack:
            raise ValueError(f"Unclosed template element: {self.stack[-1].tag}")

    def position(self):
        line, column = self.getpos()
        return self.line_offsets[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self.position()
        content_start = start + len(self.get_starttag_text())
        element = Element(tag, dict(attrs), start, content_start)
        self.elements.append(element)
        if tag in self.VOID_TAGS:
            element.content_end = element.end = content_start
        else:
            self.stack.append(element)

    def handle_startendtag(self, tag, attrs):
        start = self.position()
        end = start + len(self.get_starttag_text())
        self.elements.append(Element(tag, dict(attrs), start, end, end, end))

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1].tag != tag:
            raise ValueError(f"Unexpected closing template element: {tag}")
        element = self.stack.pop()
        element.content_end = self.position()
        element.end = self.source.index(">", element.content_end) + 1

    def one(self, *, tag=None, element_id=None):
        matches = [element for element in self.elements
                   if (tag is None or element.tag == tag)
                   and (element_id is None or element.attrs.get("id") == element_id)]
        if len(matches) != 1:
            raise ValueError(f"Expected one template element: {tag or element_id}")
        return matches[0]


def opening_tag(element, attrs):
    attributes = "".join(
        f" {key}" if value is None else f' {key}="{escape(value, quote=True)}"'
        for key, value in attrs.items()
    )
    return f"<{element.tag}{attributes}>"


def render_page(template, page):
    views = [element for element in template.elements if "data-view" in element.attrs]
    names = [element.attrs["data-view"] for element in views]
    if sorted(names) != sorted(item.name for item in PAGES):
        raise ValueError("The template must have exactly one section for each page")
    if any(element.tag != "section" for element in views):
        raise ValueError("Page content must be a section element")
    if any(first.start < second.start < first.end
           for first in views for second in views if first is not second):
        raise ValueError("Page sections cannot be nested")

    edits = [(element.start, element.end, "") for element in views
             if element.attrs["data-view"] != page.name]
    body = template.one(tag="body")
    edits.append((body.start, body.content_start,
                  opening_tag(body, {**body.attrs, "data-page": page.name})))
    for element, text in (
        (template.one(tag="title"), f"{page.title} — Certificati HTTPS"),
        (template.one(element_id="page-title"), page.title),
        (template.one(element_id="page-eyebrow"), page.eyebrow),
        (template.one(element_id="page-description"), page.description),
    ):
        edits.append((element.start, element.content_start,
                      opening_tag(element, {**element.attrs, "data-i18n": message_key(text)})))
        edits.append((element.content_start, element.content_end, escape(text)))

    for element in template.elements:
        classes = (element.attrs.get("class") or "").split()
        if element.tag != "a" or "nav-link" not in classes:
            continue
        attrs = dict(element.attrs)
        classes = [name for name in classes if name != "active"]
        attrs.pop("aria-current", None)
        if attrs.get("href") == page.route:
            classes.append("active")
            attrs["aria-current"] = "page"
        attrs["class"] = " ".join(classes)
        edits.append((element.start, element.content_start, opening_tag(element, attrs)))

    # Apply disjoint edits back to front so source positions stay valid.
    source = template.source
    for start, end, replacement in sorted(edits, reverse=True):
        source = source[:start] + replacement + source[end:]
    return source.encode("utf-8")


def main():
    root = Path(__file__).resolve().parent.parent
    target = Path(sys.argv[1])
    target.parent.mkdir(parents=True, exist_ok=True)
    pages_dir = target.parent / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    template = Template((root / "web" / "index.html").read_text(encoding="utf-8"))
    catalogs, server_keys = load_catalogs(root)
    assets = []
    for page in PAGES:
        name = "index" if page.name == "overview" else page.name
        data = render_page(template, page)
        (pages_dir / f"{name}.html").write_bytes(data)
        assets.append((f"{name}_html", data))
    assets.extend((name, (root / "web" / filename).read_bytes()) for name, filename in (
        ("app_css", "app.css"), ("app_js", "app.js"), ("i18n_js", "i18n.js"), ("extensions_js", "extensions.js"),
        ("operations_ui_js", "operations-ui.js"), ("incidents_ui_js", "incidents-ui.js"),
        ("mail_templates_ui_js", "mail-templates-ui.js"),
    ))
    catalog_script = "window.CertificateManagerCatalogs=" + json.dumps(catalogs, ensure_ascii=False, separators=(",", ":")) + ";\n"
    catalog_script += "window.CertificateManagerServerMessages=" + json.dumps(server_keys) + ";\n"
    assets.append(("i18n_catalogs_js", catalog_script.encode("utf-8")))

    parts = ["/* Generated by scripts/embed_assets.py. */\n#ifndef ASSETS_H\n#define ASSETS_H\n"]
    for name, data in assets:
        parts.append(f"static const unsigned char asset_{name}[] = {{\n")
        for start in range(0, len(data), 20):
            parts.append(",".join(str(byte) for byte in data[start:start + 20]) + ",\n")
        parts.append(f"}};\nstatic const size_t asset_{name}_size = {len(data)};\n")
    parts.append("#endif\n")
    target.write_text("".join(parts), encoding="utf-8")


if __name__ == "__main__":
    main()
