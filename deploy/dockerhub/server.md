# qualor/server

Short description: Qualor server: self-hosted code quality platform (API, web UI, worker, PostgreSQL 18).

## Overview

Qualor is an open-source, self-hosted, GitLab-first code quality platform: a SonarQube
alternative without lines-of-code licensing. It runs existing open-source analyzers (ESLint, PMD,
SpotBugs, OpenGrep, Gitleaks, or any SARIF) in your CI through
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner), tracks their issues across commits,
measures coverage, duplication and complexity, and applies a quality gate to new code.

This image is the server: the HTTP API, the web UI and the analysis worker in one Node.js
process, plus its own PostgreSQL 18, which it starts itself and keeps on the volume
`/var/lib/qualor`. Set `DATABASE_URL` to use an external PostgreSQL 16 or later instead.

- Source, documentation and issues: <https://github.com/qualor-dev/qualor>
- Documentation: <https://qualor.dev/docs>

### The image

- Distroless (`gcr.io/distroless/cc-debian12`, no shell, no package manager) with Node.js
  22.23.3 and PostgreSQL 18, about 340 MB; every base image is pinned by digest.
- Runs as the non-root user 65532. Nothing under `/app` is writable by it; its data is on the
  volume `/var/lib/qualor` (`QUALOR_DATA_DIR`).
- Listens on port 8080 (`HOST=0.0.0.0`, `PORT=8080`) and serves the web UI from `/app/ui` on the
  same origin (`QUALOR_UI_DIR=/app/ui`).
- Entrypoint `node --enable-source-maps dist/main.js`. It applies the database migrations at every
  start, before it listens, under a PostgreSQL advisory lock, so replicas starting together apply
  them once.
- `GET /healthz` (liveness, the image's `HEALTHCHECK`) and `GET /readyz` (503 until the database
  answers within 2 s and the migrations are applied).
- No secret is baked into the image.

### Quick start with docker compose

The install guide, <https://qualor.dev/docs/install-server>, runs the server from two files: a
`compose.yml` with one `server` service and the `data` volume, and an `.env` with
`QUALOR_VERSION`, `QUALOR_SECRET_KEY` and `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` (each generated, for
example with `openssl rand -hex 32`). Then:

```sh
docker compose up -d
docker compose ps      # wait until the server is "healthy"
```

Open <http://127.0.0.1:8080> and sign in as `admin` with the bootstrap password, then change it.
The guide also covers an external PostgreSQL, Kubernetes with Helm, TLS, backups and upgrades.

### Configuration

| Variable                                                             | Default           | Meaning                                                                                                           |
| -------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                                       | empty             | `postgres://` URL of an external database; empty runs the embedded PostgreSQL 18                                  |
| `QUALOR_SECRET_KEY`                                                  | required          | at least 32 characters; keys the session CSRF tokens and encrypts stored webhook secrets                          |
| `QUALOR_BOOTSTRAP_ADMIN_USERNAME`, `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` | `admin`, none     | the first instance admin, created on the first start only; the password (at least 12 characters) is required then |
| `HOST`, `PORT`                                                       | `0.0.0.0`, `8080` | listen address                                                                                                    |
| `QUALOR_TRUST_PROXY`                                                 | off               | the reverse proxies in front of the server: a hop count or a comma-separated list of IPs and CIDRs                |
| `QUALOR_LOG_LEVEL`                                                   | `info`            | log level                                                                                                         |
| `QUALOR_SESSION_TTL_HOURS`                                           | `168`             | browser session lifetime                                                                                          |
| `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES`                                 | 50 MiB            | report upload limit as sent                                                                                       |
| `QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES`                               | 500 MiB           | report upload limit decompressed (also the maximum)                                                               |
| `QUALOR_MAX_CONCURRENT_UPLOADS`                                      | `4`               | uploads read at once                                                                                              |
| `QUALOR_REQUEST_TIMEOUT_MS`                                          | `300000`          | the longest any one request may run                                                                               |
| `QUALOR_WORKER_CONCURRENCY`                                          | `1`               | analysis jobs processed at once                                                                                   |

Give the server at least 1 GiB of memory; reports near the 500 MiB ceiling need about 4 GiB.

### Security notes

- There are no default secrets: the guide's compose file refuses to start while
  `QUALOR_SECRET_KEY` or `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` is empty. Use generated hex values.
- The guide's compose file publishes the server on `127.0.0.1:8080` only, with a read-only root
  filesystem, no capabilities and `no-new-privileges`; the embedded PostgreSQL listens on a Unix
  socket only.
- Qualor does not terminate TLS. Put a reverse proxy with TLS in front of it and set
  `QUALOR_TRUST_PROXY`; never expose the server on `0.0.0.0` without TLS.
- Passwords and access tokens are stored hashed; a database dump still holds those hashes and the
  encrypted webhook secrets, so store it like a secret. Back up `QUALOR_SECRET_KEY` separately:
  changing it signs everyone out and makes stored webhook secrets unreadable.

### Licence

Qualor is MIT-licensed (`/app/LICENSE`), except the enterprise plugin in `/app/enterprise`
(Qualor Enterprise Licence, `/app/enterprise/LICENSE`), which the server loads only with a valid
licence key and never reads without one. Third-party notices are in `/app/NOTICE.md`. The source
of the image's copyleft components (its Debian packages) is published as
[`qualor/server-sources`](https://hub.docker.com/r/qualor/server-sources) with the same tag;
`/app/SOURCES.md` is its index.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
