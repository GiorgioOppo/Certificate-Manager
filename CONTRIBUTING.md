# Contributing to Certificate Manager

Build the application using the dependencies and commands in [README.md](README.md), then run `make test` before submitting a change. Tests use disposable databases and local TLS/SMTP servers; do not introduce live credentials, production certificates or public-network dependencies.

## Source layout

- `src/`: C backend, certificate parsing, SQLite storage, local HTTP server, TLS checks, monitors and email delivery.
- `src/lifecycle.c`: overlapping renewal relationships, operational plans, per-endpoint deployment evidence and guarded completion.
- `src/workspace.c`: directory/group assignments, reminder and monitor-mail settings, and read-only import previews using a temporary database.
- `web/`: shared HTML, CSS, JavaScript, guided file/CSV import and language resources.
- `scripts/embed_assets.py`: generates the nine page documents and embeds interface assets during the build.
- `tests/`: C unit tests and Python integration tests.
- `Dockerfile` and `docker-compose.yml`: multi-stage Linux image and local container deployment with a persistent data volume.
- `docs/`: workflow explanations in English and Italian, the Italian user guide, translation and publication guidance.

The executable embeds the web interface. Rebuild with `make` after changing web assets and restart the application to load the updated executable. Keep the local deployment model, existing Host/Origin/CSRF protections and strict TLS verification intact. The native server defaults to loopback; container use explicitly selects its listener address while Compose publishes only on host loopback. Keep the internal and published ports equal. After container changes, build the image and check startup, HTTP health, non-root execution and data persistence with disposable volumes; never use a production database for these checks.

```sh
docker compose config --quiet
docker compose build
python3 tests/container_smoke.py
```

The container smoke test requires Docker Compose, Python 3 and the `openssl` command. It creates a unique project and temporary certificates, verifies HTTP protections and background monitoring, then checks a complete volume backup and recreation with the existing SMTP key. It removes only its own disposable containers and volume. GitHub Actions runs it alongside the native build and test job.

## Changes and review

Describe the problem, resulting behavior and checks performed in your pull request. Add focused coverage for behavior changes, especially parsing, migrations, date boundaries, contact role handling and security-sensitive code. Keep user-provided certificate data separate from translated interface text.

When changing visible text, update all six interface languages and verify placeholders remain consistent. Check affected pages at wide and narrow widths, including empty states and errors. Do not translate API field names, stored certificate subjects, user names, addresses or URLs.

Keep [README.md](README.md), the [Italian guide](docs/README.it.md) and the workflow explanations in [English](docs/WORKFLOW.md) and [Italian](docs/WORKFLOW.it.md) consistent when changing setup or behavior. Contributions are distributed under the project's [MIT license](LICENSE).

## Workflow invariants

Schema version **5** separates certificate time validity from operational state. CN is not a unique key: multiple valid certificates can share it, while SHA-256 fingerprint identifies each certificate. Loading or linking a renewal must preserve the predecessor's active entry, reminders and monitor associations. Copy contact and group origins so later directory changes propagate correctly.

A monitor may recognize the predecessor or an explicitly approved, valid replacement. Approval never bypasses TLS trust, hostname or validity checks. Only fresh results after an installation-verification request may prove deployment; changing monitor revisions invalidates older workers. Completion requires every endpoint's request and successful result to be at most 15 minutes old. Transfer monitors and archive the predecessor atomically only after the guard passes. With no endpoints, explicit manual retirement requires responsibility and notes and must never be labelled verified installation.

Test guided import without changing the real database, duplicate and renewal-candidate classification, CSV quoting and row limits, partial-failure retry, directory/group propagation, reminder thresholds including `0`, escalation timing and opt-in monitor email deduplication. New alert opt-in must not replay historical events. Preserve existing queued messages and history during schema migration. Operational request/renewal/installation dates must not modify X.509 validity dates.

## Sensitive information

Never include database files, `.smtp.key` files, environment files, TLS private keys or real credentials in a patch, screenshot or test fixture. Use generated local test material and example domains. Report security concerns according to [SECURITY.md](SECURITY.md).
