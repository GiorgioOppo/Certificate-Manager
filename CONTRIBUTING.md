# Contributing to Certificate Manager

Build the application using the dependencies and commands in [README.md](README.md), then run `make test` before submitting a change. Tests use disposable databases and local TLS/SMTP servers; do not introduce live credentials, production certificates or public-network dependencies.

## Source layout

- `src/`: C backend, certificate parsing, SQLite storage, local HTTP server, TLS checks, monitors and email delivery.
- `web/`: shared HTML, CSS, JavaScript and language resources.
- `scripts/embed_assets.py`: generates the eight page documents and embeds interface assets during the build.
- `tests/`: C unit tests and Python integration tests.
- `docs/`: workflow explanations in English and Italian, the Italian user guide, translation and publication guidance.

The executable embeds the web interface. Rebuild with `make` after changing web assets and restart the application to load the updated executable. Keep the local-only server model, existing Host/Origin/CSRF protections and strict TLS verification intact.

## Changes and review

Describe the problem, resulting behavior and checks performed in your pull request. Add focused coverage for behavior changes, especially parsing, migrations, date boundaries, contact role handling and security-sensitive code. Keep user-provided certificate data separate from translated interface text.

When changing visible text, update all six interface languages and verify placeholders remain consistent. Check affected pages at wide and narrow widths, including empty states and errors. Do not translate API field names, stored certificate subjects, user names, addresses or URLs.

Keep [README.md](README.md), the [Italian guide](docs/README.it.md) and the workflow explanations in [English](docs/WORKFLOW.md) and [Italian](docs/WORKFLOW.it.md) consistent when changing setup or behavior. Contributions are distributed under the project's [MIT license](LICENSE).

## Sensitive information

Never include database files, `.smtp.key` files, environment files, TLS private keys or real credentials in a patch, screenshot or test fixture. Use generated local test material and example domains. Report security concerns according to [SECURITY.md](SECURITY.md).
