# qualor/server

Short description: Open-source SonarQube alternative: self-hosted code quality with no lines-of-code licence

Categories: Developer tools, Integration & delivery, Security

## Overview

**Quality gates for new code. No lines-of-code licence.**

Qualor is an open-source, self-hosted SonarQube alternative for GitLab and GitHub. It runs the
analyzers you already trust, follows every issue across commits, and fails the merge request that
makes the code worse. MIT licensed, with no limit on lines, users or projects.

- **It judges only the code you changed.** A quality gate on new code, a summary and a status on
  every GitLab merge request and GitHub pull request, and new issues marked on the lines that
  caused them.
- **Your analyzers, one list.** ESLint, PMD, SpotBugs, detekt for Kotlin, SwiftLint for Swift,
  PHPStan for PHP, RuboCop for Ruby, staticcheck, go vet and gosec for Go, cppcheck and clang-tidy
  for C and C++, Roslyn and Roslynator for C#, OpenGrep, Gitleaks, Trivy, SonarQube-compatible rules
  (SonarAnalyzer.CSharp 9.32, eslint-plugin-sonarjs 2.0.4, LGPL-3.0) or any SARIF. The same finding
  from two tools shows once.
- **Issues that survive a refactor.** Qualor recognises an issue by its code, not its line number,
  so the issue keeps its history and its status when the code moves.
- **Coverage, duplication, complexity.** Coverage from LCOV, Cobertura and JaCoCo, cognitive
  complexity and copy-pasted code, with the history of every branch and merge request.
- **Leave SonarQube in one command.** `qualor import sonarqube` brings over quality profiles,
  quality gates and accepted issues.
- **An assistant on your terms.** Explanations, false-positive triage and fix suggestions from the
  model you choose: any OpenAI-compatible endpoint, Anthropic, or a local model through Ollama or
  vLLM.
- **Private and simple.** No telemetry. One container, database included.

Website: <https://qualor.dev> · Documentation: <https://qualor.dev/docs> · Source and issues:
<https://github.com/qualor-dev/qualor>

### Tags

Every release has its full version tag, such as `0.3.1`, and a minor tag, such as `0.3`, that
follows its patch releases. There is no `latest` tag: pin a version and upgrade when you choose to.

### Try it

```sh
export QUALOR_SECRET_KEY=$(openssl rand -hex 32)
export QUALOR_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 16)
docker run -d --name qualor -p 127.0.0.1:8080:8080 -v qualor-data:/var/lib/qualor \
  -e QUALOR_SECRET_KEY -e QUALOR_BOOTSTRAP_ADMIN_PASSWORD qualor/server:0.3
echo "$QUALOR_BOOTSTRAP_ADMIN_PASSWORD"   # the admin password for the first sign-in
```

Open <http://127.0.0.1:8080> and sign in as `admin`. The
[quick start](https://qualor.dev/docs/quick-start) goes on from there to a first analysis of your
own code with [`qualor/scanner`](https://hub.docker.com/r/qualor/scanner).

### Run it for your team

For a server you keep, follow the install guide, <https://qualor.dev/docs/install-server>: a
`compose.yml` with one `server` service and the `data` volume, an `.env` with generated secrets,
TLS behind a reverse proxy, an external PostgreSQL if you prefer one, backups and upgrades. On
Kubernetes, use the Helm chart [`qualor/qualor`](https://hub.docker.com/r/qualor/qualor).

### Business and Enterprise

Single sign-on, SCIM provisioning, a tamper-evident audit log, SIEM streaming and priority support
come with a licence key for this same image. Priced per server, never by lines of code or by
seat: <https://qualor.dev/enterprise>.

### The image

This image is the server: the HTTP API, the web UI and the analysis worker in one Node.js
process, plus its own PostgreSQL 18, which it starts itself and keeps on the volume
`/var/lib/qualor`. Set `DATABASE_URL` to use an external PostgreSQL 16 or later instead.

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
