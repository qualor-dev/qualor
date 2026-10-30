# Install the server

The server is one container, `qualor/server`: the API, the web UI, the analysis worker and its own
PostgreSQL 18 on a volume. It needs no Elasticsearch, Redis or message broker. Run it with
[Docker Compose](#docker-compose), which needs only `compose.yml` and `.env`, or with the
[Helm chart](#kubernetes-helm). For a managed database or several replicas, use an
[external PostgreSQL](#external-postgresql).

## Requirements

| | Minimum | Notes |
|---|---|---|
| CPU | 1 vCPU | 2 or more for many parallel pipelines |
| Memory | 1.5 GiB for the server with its database | about 4 GiB for reports near the 500 MiB decompressed limit. With [AI review](./ai-review.md) on, add up to 512 MiB for each AI review or answer to a reply that runs at once (`QUALOR_REVIEW_WORKER_CONCURRENCY`, 2 by default) |
| Disk | a few GiB for the data volume | reports are kept 7 days; analyses and measures are small |
| Software | Docker with Compose v2 | or Kubernetes 1.29+ with Helm, or any container platform that runs the image with a volume |
| Inbound network | HTTPS from CI runners and users | |
| Outbound network | your GitLab or GitHub, and your webhook receivers | if configured: the AI model provider ([AI assistant](./ai-assistant.md)), the SMTP server ([Email](./email.md)), the identity provider ([Single sign-on](./sso-and-scim.md)), Slack or Teams ([Slack and Microsoft Teams](./chat-notifications.md)). Unless turned off: `qualor.dev` ([Telemetry](./telemetry.md)) and `hub.docker.com` ([Update check](./telemetry.md#update-check)) |

## Images

The images are on Docker Hub, for `linux/amd64`, with the Helm chart next to them.

| Image | What it is | Size |
|---|---|---|
| [`qualor/server`](https://hub.docker.com/r/qualor/server) | API, web UI and worker in one Node process, plus PostgreSQL 18; distroless, user 65532 | ~340 MB |
| [`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) | the `qualor` CLI (its entrypoint), Node.js, a JRE 17, git and the pinned analyzers, with Trivy's database | ~4.1 GB |
| [`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet) | `qualor/scanner` plus the .NET 8 and .NET 10 SDKs and Roslynator, for C# | ~5.8 GB |

**Tags.** Every release is tagged with its full version (`0.14.0`) and its minor version (`0.14`).
The minor tag moves to the newest patch release of that minor. In 0.x there is no `0` tag: a new
minor version may change behaviour, so you move to it on purpose. The examples use `0.14`. Pin the
full version where every pipeline must run exactly the same analyzers. Keep the server and the
scanner on the same release. Never use `latest`.

**Signatures.** Every release, from 0.1.0 on, signs its images, the Helm chart and its files with
cosign. Verify them with the published `cosign.pub`, as
[`SECURITY.md`](../../SECURITY.md#verifying-a-release) shows, and pin what you verified by digest.
The signatures are not recorded in the public Rekor transparency log, so cosign needs
`--insecure-ignore-tlog=true`. Without it, cosign looks for a log entry and fails:

```sh
cosign verify --key https://qualor.dev/cosign.pub --insecure-ignore-tlog=true qualor/server:0.14
```

The source of the copyleft components in each image is published next to it, as
`qualor/server-sources` and `qualor/scanner-sources` with the same tag.

**Air-gapped or rate-limited networks.** Copy the images into your own registry and use those names
everywhere below:

```sh
for image in server scanner scanner-dotnet; do
  docker pull qualor/$image:0.14
  docker tag  qualor/$image:0.14 mirror.acme.internal/qualor/$image:0.14
  docker push mirror.acme.internal/qualor/$image:0.14
done
```

For Compose, set `QUALOR_IMAGE_PREFIX=mirror.acme.internal/qualor` in `.env`.

To build the images from source, see [`deploy/README.md`](../../deploy/README.md).

## Docker Compose

Create a directory for Qualor, for example `/opt/qualor`, with two files in it.

### The compose file

`compose.yml`:

```yaml
name: qualor

services:
  server:
    image: ${QUALOR_IMAGE_PREFIX:-qualor}/server:${QUALOR_VERSION:?set QUALOR_VERSION in .env}
    restart: unless-stopped
    environment:
      # Empty: the server runs its own PostgreSQL on the volume below.
      DATABASE_URL: ${DATABASE_URL:-}
      QUALOR_SECRET_KEY: ${QUALOR_SECRET_KEY:?set QUALOR_SECRET_KEY in .env}
      QUALOR_BOOTSTRAP_ADMIN_USERNAME: ${QUALOR_BOOTSTRAP_ADMIN_USERNAME:-admin}
      QUALOR_BOOTSTRAP_ADMIN_PASSWORD: ${QUALOR_BOOTSTRAP_ADMIN_PASSWORD:?set QUALOR_BOOTSTRAP_ADMIN_PASSWORD in .env}
      QUALOR_PUBLIC_URL: ${QUALOR_PUBLIC_URL:-}
      QUALOR_TRUST_PROXY: ${QUALOR_TRUST_PROXY:-}
      QUALOR_SCM_INTERNAL_HOSTS: ${QUALOR_SCM_INTERNAL_HOSTS:-}
      QUALOR_LLM_INTERNAL_HOSTS: ${QUALOR_LLM_INTERNAL_HOSTS:-}
      QUALOR_SSO_INTERNAL_HOSTS: ${QUALOR_SSO_INTERNAL_HOSTS:-}
      QUALOR_FORCE_PASSWORD_SIGN_IN: ${QUALOR_FORCE_PASSWORD_SIGN_IN:-}
      # Email (email.md), if you send it: the SMTP server and the sender.
      # QUALOR_SMTP_URL: ${QUALOR_SMTP_URL}
      # QUALOR_SMTP_FROM: ${QUALOR_SMTP_FROM}
      QUALOR_WORKER_CONCURRENCY: ${QUALOR_WORKER_CONCURRENCY:-1}
      QUALOR_LOG_LEVEL: ${QUALOR_LOG_LEVEL:-info}
    volumes:
      - data:/var/lib/qualor
    ports:
      - '${QUALOR_BIND_ADDRESS:-127.0.0.1}:${QUALOR_PORT:-8080}:8080'
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ['no-new-privileges:true']
    stop_grace_period: 60s # time for the database to shut down cleanly
    healthcheck:
      test:
        - CMD
        - /usr/local/bin/node
        - -e
        - "fetch('http://127.0.0.1:8080/readyz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
      interval: 10s
      timeout: 5s
      start_period: 60s
      retries: 3

volumes:
  data:
```

### The settings file

Create `.env` with generated secrets, readable only by you:

```sh
cd /opt/qualor
umask 077
cat > .env <<EOF
QUALOR_VERSION=0.14
QUALOR_SECRET_KEY=$(openssl rand -hex 32)
QUALOR_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 16)
# The address users and CI open Qualor at (links in MR/PR comments, the GitHub webhook URL):
QUALOR_PUBLIC_URL=https://qualor.example.com
# A TLS reverse proxy on this host (see below):
QUALOR_TRUST_PROXY=1
# Self-managed GitLab / GitHub Enterprise on an internal network, if any:
# QUALOR_SCM_INTERNAL_HOSTS=gitlab.corp.example.com
# A local model for the AI assistant (see ai-assistant.md), if any:
# QUALOR_LLM_INTERNAL_HOSTS=ollama:11434
# An identity provider for single sign-on on an internal network (see sso-and-scim.md), if any:
# QUALOR_SSO_INTERNAL_HOSTS=keycloak.corp.example.com:8443
# An SMTP server for email (see email.md), if any:
# QUALOR_SMTP_URL=smtp://qualor%40example.com:<password>@smtp.example.com:587
# QUALOR_SMTP_FROM=Qualor <qualor@example.com>
EOF
grep BOOTSTRAP .env     # the first admin password; you change it at the first sign-in
```

### Start

```sh
docker compose up -d
docker compose ps       # wait until "server" is healthy (15–30 s)
```

- **Secrets.** `QUALOR_SECRET_KEY` (at least 32 characters) and `QUALOR_BOOTSTRAP_ADMIN_PASSWORD`
  (at least 12) are required. Compose refuses to start without them.
- **Database.** Without `DATABASE_URL`, the server runs the PostgreSQL 18 of its image on the volume
  at `/var/lib/qualor`. It listens only on a Unix socket inside the container and stops cleanly
  with the server. **One server per volume:** a second container on the same volume refuses to
  start.
- **First sign-in.** The first start creates the `default` organisation and the instance admin
  `admin` (`QUALOR_BOOTSTRAP_ADMIN_USERNAME`). Sign in with the bootstrap password, then change it:
  open the menu under your name at the top right and choose **Change password**. Once a user
  exists, the bootstrap password is no longer used.
- **Network.** The server publishes `127.0.0.1:8080` only (`QUALOR_BIND_ADDRESS`, `QUALOR_PORT`).
  For other machines, put a [reverse proxy with TLS](#reverse-proxy-and-tls) in front.
- **Migrations** run at every start, under a lock, before the server listens. `/readyz` answers 503
  until they are applied.
- **Hardening.** The container runs as non-root, with a read-only root filesystem, no capabilities
  and `no-new-privileges`.

Add any other [server setting](#server-settings) to the `environment` of the `server` service, for
example `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES: '104857600'`.

## Kubernetes (Helm)

The Helm chart `qualor` runs the same `qualor/server` image, and its version is the server's
version. It needs Kubernetes 1.29 or later and a default StorageClass for its volume.

Create the namespace and the secrets:

```sh
kubectl create namespace qualor
kubectl -n qualor create secret generic qualor-secrets \
  --from-literal=QUALOR_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=QUALOR_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)"
```

Write `values.yaml`:

```yaml
secrets:
  existingSecret: qualor-secrets
config:
  publicUrl: https://qualor.example.com
  trustProxy: '1'
ingress:
  enabled: true
  className: nginx
  host: qualor.example.com
  tls:
    secretName: qualor-tls # a certificate Secret, for example from cert-manager
```

Install, wait, and read the first admin password:

```sh
helm install qualor oci://registry-1.docker.io/qualor/qualor --version 0.14.0 -n qualor -f values.yaml
kubectl -n qualor rollout status statefulset/qualor
kubectl -n qualor get secret qualor-secrets -o jsonpath='{.data.QUALOR_BOOTSTRAP_ADMIN_PASSWORD}' | base64 -d
```

### Database

| `database.mode` | What runs | Replicas |
|---|---|---|
| `embedded` (default) | the server with its own PostgreSQL 18 on a 10 GiB volume (`persistence.size`) | 1. The chart refuses more |
| `external` | the server only. `DATABASE_URL` comes from the Secret `database.external.existingSecret` (key `DATABASE_URL`) | `replicaCount` |
| `bundled` | the server and a PostgreSQL 18 StatefulSet in the release, with its password from `database.bundled.existingSecret` (key `POSTGRES_PASSWORD`, hex) | `replicaCount` |

For a managed database (RDS, Cloud SQL, Azure Database), use `external`:

```sh
kubectl -n qualor create secret generic qualor-database \
  --from-literal=DATABASE_URL='postgres://qualor:<password>@db.example.com:5432/qualor?sslmode=require'
```

```yaml
database:
  mode: external
  external:
    existingSecret: qualor-database
replicaCount: 2
```

If a private CA signed the database's certificate, put the CA certificate in a Secret and name it
in `caSecret`. The chart mounts it read-only and sets `NODE_EXTRA_CA_CERTS`, so the server trusts
that CA, for GitLab, GitHub Enterprise and webhooks too:

```sh
kubectl -n qualor create secret generic qualor-database-ca --from-file=ca.crt=./ca.crt
```

```yaml
database:
  mode: external
  external:
    existingSecret: qualor-database
    caSecret: qualor-database-ca
```

Uninstalling the release **keeps** the embedded volume, the claim `data-qualor-0`. Delete it
(`kubectl -n qualor delete pvc data-qualor-0`) only when you want the data gone.

In `bundled` mode, PostgreSQL reads its password only when it creates the database. To change the
password, change it in PostgreSQL first, then in the Secret that `database.bundled.existingSecret`
names (here `qualor-postgres`), then restart the servers. If you use `database.bundled.password`
instead, the last two steps are one `helm upgrade` with the new value:

```sh
kubectl -n qualor exec qualor-postgres-0 -- psql -U qualor -d qualor -c "ALTER USER qualor PASSWORD '<new hex password>'"
kubectl -n qualor create secret generic qualor-postgres --from-literal=POSTGRES_PASSWORD='<new hex password>' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n qualor rollout restart deployment/qualor
```

### Settings

These [server settings](#server-settings) have a value in `config`: `bootstrapAdminUsername`,
`publicUrl`, `trustProxy`, `scmInternalHosts`, `llmInternalHosts`, `ssoInternalHosts`,
`forcePasswordSignIn`, `telemetry`, `workerConcurrency`, `logLevel`, `smtpFrom` and `smtpReplyTo`.
Every other one goes into `extraEnv`:

```yaml
extraEnv:
  - name: QUALOR_UPLOAD_MAX_COMPRESSED_BYTES
    value: '104857600'
```

For [email](./email.md), put the SMTP URL into the Secret as the key `QUALOR_SMTP_URL`, and set the
sender. Then restart the server: the chart does not watch a Secret you own.

```sh
kubectl -n qualor patch secret qualor-secrets --type merge \
  -p '{"stringData":{"QUALOR_SMTP_URL":"smtp://qualor%40example.com:<password>@smtp.example.com:587"}}'
```

```yaml
config:
  smtpFrom: Qualor <qualor@example.com>
```

Without `secrets.existingSecret`, set `secrets.smtpUrl` instead, and the chart's own Secret holds
it.

The chart checks its values against a schema, so a misspelt key fails the install instead of being
ignored. To run exactly the image you verified with `cosign.pub`, pin it by digest with
`image.digest: sha256:…`.

### Security and network

The pods run as non-root, with a read-only root filesystem, no capabilities and no service account
token: they meet the Pod Security Standard `restricted`.

The default ingress annotations are for ingress-nginx: a 50 MB request body, no request buffering
and a 300 s read timeout. Give any other ingress controller or load balancer the same limits. Your
`ingress.annotations` add to these defaults. Set one to `null` to drop it.

The NetworkPolicy is off by default. With it on, the server accepts connections only on its port,
from the sources you list or from anywhere, and a `bundled` PostgreSQL only from the server.
Outgoing connections stay open unless you list `egress` rules. If you do, list your SCM, model,
webhook, SMTP and database hosts there.

```yaml
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
```

### Backups and restore on Kubernetes

Back up the embedded database while it runs:

```sh
kubectl -n qualor exec qualor-0 -- /opt/postgresql/bin/pg_dump -h /var/lib/qualor/run -U qualor -Fc qualor \
  > qualor-$(date +%F).dump
```

Restore with the server stopped, in a one-off pod on the same volume:

```sh
kubectl -n qualor scale statefulset/qualor --replicas=0
kubectl -n qualor run qualor-restore --rm -i --restart=Never --image=qualor/server:0.14.0 \
  --overrides='{"spec":{"automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,"fsGroupChangePolicy":"OnRootMismatch","seccompProfile":{"type":"RuntimeDefault"}},"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-qualor-0"}},{"name":"tmp","emptyDir":{"sizeLimit":"64Mi"}}],"containers":[{"name":"qualor-restore","image":"qualor/server:0.14.0","imagePullPolicy":"IfNotPresent","args":["restore"],"stdin":true,"stdinOnce":true,"env":[{"name":"QUALOR_SECRET_KEY","valueFrom":{"secretKeyRef":{"name":"qualor-secrets","key":"QUALOR_SECRET_KEY"}}}],"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"data","mountPath":"/var/lib/qualor"},{"name":"tmp","mountPath":"/tmp"}]}]}}' \
  < qualor-YYYY-MM-DD.dump
kubectl -n qualor scale statefulset/qualor --replicas=1
```

The pod reads `QUALOR_SECRET_KEY` from the Secret `qualor-secrets`: put your own Secret's name there
if it differs. It has the chart's security settings, so a namespace that enforces `restricted`
admits it. `fsGroupChangePolicy: OnRootMismatch` stops the kubelet from re-owning the data
directory, which would leave it group-writable, and PostgreSQL refuses that.

With `external` or `bundled`, use the database's own tools, as in [Backups](#backups).

## External PostgreSQL

Use your own PostgreSQL 16 or later for a managed database (RDS, Cloud SQL, Azure Database), for
your DBA's backups and monitoring, or for more than one server replica. Qualor is tested with
PostgreSQL 18. Set `DATABASE_URL`, and the server starts no database of its own:

```sh
# in .env
DATABASE_URL=postgres://qualor:<password>@db.example.com:5432/qualor?sslmode=require
```

The user must own the database, or be allowed to create the extensions `citext` and `pg_trgm` in
it. The server's volume then stays empty.

To run PostgreSQL next to the server with Compose, add it as a second service:

```yaml
services:
  server:
    # ... as above, plus:
    environment:
      DATABASE_URL: postgres://qualor:${POSTGRES_PASSWORD}@postgres:5432/qualor
    depends_on:
      postgres: { condition: service_healthy }

  postgres:
    image: postgres:18-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: qualor
      POSTGRES_DB: qualor
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
    volumes:
      - pgdata:/var/lib/postgresql # PostgreSQL 18 images keep their data below this path
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U qualor -d qualor']
      interval: 5s
      timeout: 5s
      retries: 20

volumes:
  pgdata:
```

Add `POSTGRES_PASSWORD=$(openssl rand -hex 32)` to `.env`. Use a hex value, because the password
goes into a `postgres://` URL.

## Server settings

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | none | an [external PostgreSQL](#external-postgresql) 16 or later. Unset: the server runs its own |
| `QUALOR_DATA_DIR` | `/var/lib/qualor` | the volume of the server's own PostgreSQL (unused with `DATABASE_URL`) |
| `QUALOR_SECRET_KEY` | required | at least 32 characters. It keys the CSRF tokens and encrypts stored secrets: SCM tokens, GitHub App keys, webhook secrets, the AI provider's API key and the SMTP password. Changing it signs everyone out and makes stored secrets unreadable until they are set again |
| `QUALOR_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | `admin` / none | the first instance admin, used on the first start only |
| `QUALOR_PUBLIC_URL` | none | the address users open Qualor at. **Set it** once Qualor has a real address. Qualor uses it for the links in MR/PR comments, commit statuses, check runs and [Slack and Teams](./chat-notifications.md) messages, for the GitHub webhook URL, and for the single sign-on and SCIM addresses. With an SMTP server it turns on password reset links and invitations ([Email](./email.md#account-emails)). It also turns on the [MCP server](./mcp.md) at `/mcp` for AI agents, which needs HTTPS in front of the server. [Single sign-on](./sso-and-scim.md) needs it |
| `QUALOR_SCM_INTERNAL_HOSTS` | none | the GitLab or GitHub Enterprise hosts on your internal network that Qualor may call, comma-separated, each with an optional port (`gitlab.corp:8443`). Without an entry, Qualor calls only hosts that resolve to public addresses |
| `QUALOR_LLM_INTERNAL_HOSTS` | none | the same for the [AI assistant](./ai-assistant.md)'s model provider on your internal network (`ollama:11434`), which may then use plain `http`. A separate list: an SCM host listed above is not allowed for the model, nor the reverse |
| `QUALOR_SSO_INTERNAL_HOSTS` | none | the same for the identity provider of [single sign-on](./sso-and-scim.md) on your internal network (`keycloak.corp:8443`), which may then use plain `http`. A list of its own, like the two above |
| `QUALOR_CHAT_TEST_HOSTS` | none | for testing only: extra hosts a Slack or Teams webhook may use, comma-separated, each with an optional port, such as a local stand-in for Slack. Leave it unset in production |
| `QUALOR_FORCE_PASSWORD_SIGN_IN` | `false` | `true` lets every user who has a password sign in with it, whatever the single sign-on setting says. It is the emergency switch for a broken identity provider ([If your identity provider is down](./sso-and-scim.md#if-your-identity-provider-is-down)). It is logged as a warning at every start and recorded in the audit log. Any value but `true`, `false` or empty stops the start. Remove it once single sign-on works again |
| `QUALOR_TRUST_PROXY` | off | the reverse proxy in front: a hop count (`1`) or its IPs/CIDRs. `true` is rejected |
| `QUALOR_LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug` |
| `QUALOR_SESSION_TTL_HOURS` | `168` | browser session lifetime |
| `QUALOR_DEMO_USER` | none | a user name anyone may sign in as from the sign-in page, read-only and without a password: a [public demo](./users-projects-tokens.md#a-public-read-only-demo). Not the bootstrap admin |
| `QUALOR_TELEMETRY` | `true` | `false`, `0`, `off` or `no` turns off the daily anonymous usage statistics ([Telemetry](./telemetry.md)). Any other value but `true`, `1`, `on`, `yes` or empty stops the start |
| `QUALOR_SMTP_URL` | none | the SMTP server for [email](./email.md): `smtp://user:password@host:587` (STARTTLS), `smtps://…:465` (TLS), or `?security=none` for a relay without TLS. It replaces the server set in **Settings → Email**, which then shows it read-only |
| `QUALOR_SMTP_FROM` | none | the sender of Qualor's email, `Qualor <qualor@example.com>` or an address. Required with `QUALOR_SMTP_URL` |
| `QUALOR_SMTP_REPLY_TO` | none | an address replies go to |
| `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES` | 50 MiB | largest report upload, as sent |
| `QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES` | 500 MiB | largest report once inflated (500 MiB is also the maximum) |
| `QUALOR_REVIEW_SNAPSHOT_MAX_COMPRESSED_BYTES` | 50 MiB | largest [AI review](./ai-review.md) snapshot upload, as sent |
| `QUALOR_REVIEW_SNAPSHOT_MAX_DECOMPRESSED_BYTES` | 500 MiB | largest snapshot once inflated (500 MiB is also the maximum, 1 MiB the minimum) |
| `QUALOR_MAX_CONCURRENT_UPLOADS` | `4` | uploads read at once, reports and AI review snapshots together. More get 503 with `Retry-After` |
| `QUALOR_REQUEST_TIMEOUT_MS` | `300000` | longest a request may run |
| `QUALOR_WORKER_CONCURRENCY` | `1` | analysis jobs processed at once. Each slot can use several times one report's size in memory |
| `QUALOR_REVIEW_WORKER_CONCURRENCY` | `2` | [AI reviews](./ai-review.md) and answers to replies that run at once, 1 to 8. They have a worker of their own, so a review never delays analyses or the AI assistant's answers. The masking worker of each running review or answer can use up to 512 MiB of heap: plan for that times this number |
| `QUALOR_AI_REVIEW_MAX_MINUTES` | `45` | an [AI review](./ai-review.md)'s time in all, 5 to 240 minutes. Raise it for a slow model. Any other value stops the start |
| `NODE_EXTRA_CA_CERTS` | none | a PEM bundle, when your GitLab, GitHub Enterprise, webhook receivers or SMTP server use a private CA. Mount the file into the container |
| `QUALOR_LICENSE` | none | an [enterprise licence](./enterprise.md) key. Not together with `QUALOR_LICENSE_FILE` |
| `QUALOR_LICENSE_FILE` | none | the path of a file holding the licence key, such as a Docker or Kubernetes secret, read at start: UTF-8, or UTF-16 with a byte-order mark. A file that cannot be read stops the start |

## Reverse proxy and TLS

Qualor does not terminate TLS. Put a reverse proxy on the same host in front of `127.0.0.1:8080`,
and set `QUALOR_TRUST_PROXY=1` in `.env`. Never publish the server on `0.0.0.0` without TLS: tokens
and passwords would cross the network in clear text.

Caddy obtains the certificate itself:

```text
qualor.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

With nginx, put this inside a `server` block that has your certificate:

```nginx
client_max_body_size 50m;          # = QUALOR_UPLOAD_MAX_COMPRESSED_BYTES
proxy_request_buffering off;       # the CLI waits for 100 Continue before it sends a report
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 300s;
}
```

The same body limit covers [AI review](./ai-review.md) snapshots, whose own limit
(`QUALOR_REVIEW_SNAPSHOT_MAX_COMPRESSED_BYTES`) is also 50 MiB by default. Set the proxy to the
larger of the two limits.

A cloud load balancer works too. Give it the same body size limit and a 300 s timeout, and set
`QUALOR_TRUST_PROXY` to its hop count or address range.

**Under a path**, such as `QUALOR_PUBLIC_URL=https://example.com/qualor`, the proxy removes
`/qualor` before it passes a request to Qualor. Pass every address that starts with
`/.well-known/oauth-` to Qualor unchanged, or AI agents cannot sign in to the
[MCP server](./mcp.md). They read these documents at the root of the host:
`https://example.com/.well-known/oauth-authorization-server/qualor` and
`https://example.com/.well-known/oauth-protected-resource/qualor/mcp`.

**A private CA.** If CI runners reach Qualor through a certificate from a private CA, set
`QUALOR_CA_FILE` (a path outside the checkout) or `NODE_EXTRA_CA_CERTS` in the job.

## Backups

With the server's own database, back up while it runs. From `/opt/qualor`:

```sh
docker compose exec -T server /opt/postgresql/bin/pg_dump -h /var/lib/qualor/run -U qualor -Fc qualor \
  > /var/backups/qualor/qualor-$(date +%F).dump
```

A dump holds user names, password hashes, token hashes and encrypted secrets: store it like a
secret. Back up `.env` too, **separately** from the dumps, since it holds `QUALOR_SECRET_KEY`.
Without that key, the restored secrets, such as SCM tokens and the AI provider's API key, cannot be
decrypted, and you have to enter them again.

**Restore** with the server stopped. The `restore` command loads the dump into a new database and
replaces the old one only when the whole dump has loaded, so a truncated or wrong file leaves the
data as it was:

```sh
docker compose stop server
docker compose run --rm -T server restore < qualor-YYYY-MM-DD.dump
docker compose up -d
```

With an [external PostgreSQL](#external-postgresql), use its own tools: `pg_dump -Fc`, and
`pg_restore` into an **empty** database while the server is stopped, never over the live one.

## Upgrades

1. Read the release notes.
2. [Back up](#backups) the database.
3. Set the new version in `.env`: `QUALOR_VERSION=0.14.0`, or the minor tag `0.14`, which takes
   patch releases (`0.14.1`, `0.14.2`) without a change here. Then:

   ```sh
   docker compose pull server
   docker compose up -d
   ```

   `/readyz` turns 200 once the migrations are applied. On Kubernetes:

   ```sh
   helm upgrade qualor oci://registry-1.docker.io/qualor/qualor --version 0.14.0 -n qualor -f values.yaml
   ```

   With the embedded database, the pod is replaced, not doubled.

4. Move the scanner in your CI to the same release. Until you do, every scan warns that the scanner
   and the server are different releases. The user menu (your name, top right) shows the server's
   version.

Migrations only go forward. To roll back, set `QUALOR_VERSION` back to the previous version and
restore the backup you took before the upgrade.

**Migration `0006`** (single sign-on and SCIM) locks the organisation and project membership
tables while it adds a column, a foreign key and an index. With the server's own database, or a few
thousand memberships, that takes a moment. On a large external database it takes longer.
Meanwhile, servers of the previous version wait on nearly every request, since permission checks
read those tables. Run that upgrade at a quiet time.

The server's own PostgreSQL follows the image within 18.x and needs nothing. A new major version
will come with steps in its release notes: back up with the old release, restore with the new one.

## Health and monitoring

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | the process is alive (no database access) |
| `GET /readyz` | the database is reachable and migrations are applied |
| `GET /api/v0/system/info` (signed in) | version, edition, features and UI extensions |

The Compose health check only reports status. Watch `docker compose ps` or `/readyz` from your
monitoring.

## Retention

A daily housekeeping job deletes old data:

| Data | Kept |
|---|---|
| uploaded reports | 7 days after processing |
| closed issues | 30 days |
| branches and MRs that have no analysis | 30 days |
| webhook deliveries | 30 days |
| the email log (**Settings → Email**) | 30 days; a message still waiting after 2 days is given up |
| AI assistant requests and answers | 90 days, an automatic fix suggestion while its issue exists; stored prompts (off by default) 1–90 days, default 7 |
| [AI review](./ai-review.md) snapshots (copies of a merge request's repository) | until a newer analysis of the merge request replaces them, the merge request is merged or closed (within an hour), or AI review stops covering the project; 14 days at most; one the server refused, 1 day ([How long copies live](./ai-review.md#how-long-copies-live)) |
| Qualor's answers to replies and commands in merge requests (who wrote the note, what came of it, the answer, the tokens) | 90 days after they are finished, and with their merge request or project ([What Qualor keeps](./ai-review.md#what-qualor-keeps)) |
| audit log events (enterprise, `audit-log`) | 365 days by default, 30 days to 100 years (**Settings → Audit settings**; [Roles and the audit log](./roles-and-audit.md#retention)) |
| analyses and measures | forever |

## Trivy's vulnerability database

Each scanner image carries a snapshot of Trivy's vulnerability database from the day it was built,
and the scan never downloads one. Reports carry the database date, and a scan warns with
`VULNERABILITY_DB_STALE` once it is more than 14 days old. Keep the scanner on a current release
(the minor tag `0.14` follows its patch releases), or fetch a fresh database in the job and point
`QUALOR_TRIVY_CACHE_DIR` at it: see
[Languages and analyzers](./languages-and-analyzers.md#dependencies-trivy).
