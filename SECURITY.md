# Security

## Intended deployment

Certificate Manager is a local desktop/server utility. Its HTTP interface binds to `127.0.0.1` by default. The Docker Compose configuration explicitly binds the listener to `0.0.0.0` inside the container and publishes its port only on the host’s `127.0.0.1`; keep that host restriction. It does not implement user authentication, authorization roles, tenant isolation or an HTTPS listener. Host, Origin and CSRF checks protect the local web workflow, but they do not replace user authentication.

Do not expose the HTTP interface directly to an untrusted network. A deployment for other users needs an independently reviewed access-control design, authenticated reverse proxy, TLS termination and compatible origin/host handling. A proxy alone does not make the current local-only design a supported multi-user service.

The container runs as UID/GID `10001:10001`, drops Linux capabilities, disallows privilege escalation and uses a read-only root filesystem. Its writable named volume contains both the database and SMTP encryption key; container isolation does not protect these files from a Docker administrator. Protect volume backups and retain ownership and key permissions on restoration. Removing the volume destroys stored data.

Endpoint verification and monitoring create outbound network connections to the destinations selected in the interface. Limit access to the application accordingly; this behavior is intended for trusted local operators.

## Data and credentials

The database contains public certificate material, contact names and email addresses, monitoring targets and history, email queue content and SMTP settings. TLS private keys are not required and are rejected on import.

SMTP passwords are encrypted with AES-256-GCM. The encryption key is a local 32-byte `<database>.smtp.key` file, restricted to its owner with permissions `0600`. Encryption does not protect against an account that can access both the database and key. Protect backups of both files. Do not place secrets in command-line arguments, issue reports, screenshots or Git history.

HTTPS and SMTP connections verify certificate trust and hostname identity. Do not disable these checks to accommodate a private CA; configure `CERTIFICATI_TLS_CA_FILE` or `CERTIFICATI_SMTP_CA_FILE` with the appropriate trusted CA file instead. The application does not implement revocation checks or certificate issuance.

## Reporting a vulnerability

There is no published security contact or response-time commitment yet. Once the GitHub repository is available, use **Security → Report a vulnerability** if private reporting is enabled, or contact a maintainer through a private channel listed on their profile. Do not disclose exploitable details or personal data in a public issue while arranging private contact.

Include a minimal reproduction using generated test certificates, the affected revision and platform, the security impact, and any proposed fix. Never attach a real database, SMTP key or password. Security fixes currently target the latest development revision; no supported release series has been established.
