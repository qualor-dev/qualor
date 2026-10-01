# Install the server

The server is one container, `qualor/server`. It holds the API, the web UI, the analysis worker and
its own PostgreSQL 18, which it starts itself and keeps on a volume. It needs no Elasticsearch, Redis
or message broker. You need two files, `compose.yml` and `.env`, and nothing else from the Qualor
repository. For a larger installation, a managed database or several server replicas, point it at
an [external PostgreSQL](#external-postgresql) instead. On Kubernetes, install the
[Helm chart](#kubernetes-helm), which runs the same image.

## Requirements

| | Minimum | Notes |
|---|---|---|
| CPU | 1 vCPU | 2+ for many parallel pipelines |
| Memory | 1.5 GiB for the server with its database | reports near the 500 MiB decompressed ceiling need about 4 GiB |
| Disk | a few GiB for the data volume | reports are kept 7 days; analyses and measures are small |
| Software | Docker with Compose v2 | or Kubernetes 1.29+ with Helm, or any container platform that runs the image with a volume |
| Network | inbound HTTPS from CI runners and users | outbound only to your GitLab/GitHub, webhook receivers and, if configured, the [AI assistant](./ai-assistant.md)'s model provider |

## Images

The images are published on Docker Hub, for `linux/amd64`, and the Helm chart next to them. The
first release is `0.1.0`.

| Image | What it is | Size |
|---|---|---|
| [`qualor/server`](https://hub.docker.com/r/qualor/server) | API, web UI and worker in one Node process, plus PostgreSQL 18; distroless, user 65532 | ~340 MB |
| [`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) | the `qualor` CLI (its entrypoint), Node.js, a JRE 17, git and the pinned analyzers, with Trivy's database | ~3.5 GB |
| [`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet) | `qualor/scanner` plus the .NET 8 and .NET 10 SDKs and Roslynator, for C# | ~5.3 GB |

**Tags.** Every release is tagged with its full version (`0.3.0`) and its minor version (`0.3`), which
moves to the newest patch release of that minor. While Qualor is in 0.x there is no `0` tag: a new
minor version may change behaviour, so you move to it on purpose. From 1.0 on, releases are also
tagged with their major version (`1`). The examples use `0.3`. Pin the full version where you want
every pipeline to run exactly the same analyzers. Keep the server and the scanner on the same
release. Never use `latest`.

**Signatures.** Every release, from 0.1.0 on, signs its images, the Helm chart and its files with cosign. Verify them with the
published `cosign.pub`, as [`SECURITY.md`](../../SECURITY.md#verifying-a-release) shows, and pin
what you verified by digest. The signatures are not recorded in the public Rekor transparency log,
so cosign needs `--insecure-ignore-tlog=true` (without it, it looks for a log entry and fails):

```sh
cosign verify --key https://qualor.dev/cosign.pub --insecure-ignore-tlog=true qualor/server:0.3
```

The source of the copyleft components in each image is published next to it, as `qualor/server-sources`
and `qualor/scanner-sources` with the same tag.

**Air-gapped or rate-limited networks.** Copy the images into your own registry and use those names
everywhere below:

```sh
for image in server scanner scanner-dotnet; do
  docker pull qualor/$image:0.3
  docker tag  qualor/$image:0.3 mirror.acme.internal/qualor/$image:0.3
  docker push mirror.acme.internal/qualor/$image:0.3
done
```

## Docker Compose

Create a directory for Qualor, for example `/opt/qualor`, and the two files in it.

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

Create `.env` with generated secrets. It must be readable only by you:

```sh
cd /opt/qualor
umask 077
cat > .env <<EOF
QUALOR_VERSION=0.3
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
EOF
grep BOOTSTRAP .env     # the first admin password; you change it at the first sign-in
```

### Start

```sh
docker compose up -d
docker compose ps       # wait until "server" is healthy (15–30 s)
```

- **Secrets.** `QUALOR_SECRET_KEY` (at least 32 characters) and `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` (at
  least 12) have no defaults, and compose refuses to start without them.
- **The database.** Without `DATABASE_URL`, the server starts the PostgreSQL 18 its image carries. The
  database lives on the volume at `/var/lib/qualor`, listens on a Unix socket inside the container
  only, and stops cleanly with the server. **One server per volume:** a second container on the same
  volume refuses to start.
- **First sign-in.** The first start creates the `default` organisation and the instance admin `admin`
  (`QUALOR_BOOTSTRAP_ADMIN_USERNAME`) with the bootstrap password. Open the server, sign in, and
  change the password: open the menu under your name at the top right and choose **Change
  password**. After a user exists, the bootstrap password is no longer used.
- **Network.** The server publishes `127.0.0.1:8080` only (`QUALOR_BIND_ADDRESS`, `QUALOR_PORT`).
- **Migrations** run at every start, before the server listens, under a lock. `/readyz` answers 503
  until they are applied.
- **Hardening.** The container runs as non-root with a read-only root filesystem, no capabilities
  and `no-new-privileges`. Health checks only report status. Watch `docker compose ps` or `/readyz`
  from your monitoring.
- **Your own registry.** Set `QUALOR_IMAGE_PREFIX=mirror.acme.internal/qualor` in `.env`.

Other server settings from the table below go into the `environment` of the `server` service, for
example `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES: '104857600'`.

## Kubernetes (Helm)

The Helm chart `qualor` runs the same `qualor/server` image. Its version is the server's version.
It needs Kubernetes 1.29 or later, and a default StorageClass for its volume. The chart
is published with every release since `0.1.0`; to try a change of your own, install it from a
checkout (`./deploy/helm/qualor` in place of the `oci://` name) with an image you built yourself.

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
helm install qualor oci://registry-1.docker.io/qualor/qualor --version 0.3.0 -n qualor -f values.yaml
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

When a private CA signed the database's certificate, put the CA certificate in a Secret and name
it. The chart mounts it read-only and sets `NODE_EXTRA_CA_CERTS`, so the server trusts it (for
GitLab, GitHub Enterprise and webhooks behind the same CA too):

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

The embedded volume (the claim `data-qualor-0`) is **kept** when you uninstall the release. Delete
it yourself (`kubectl -n qualor delete pvc data-qualor-0`) only when you want the data gone.

In `bundled` mode, PostgreSQL reads its password only when it creates the database. To change it,
change it in PostgreSQL first, then in the Secret `database.bundled.existingSecret` names (here
`qualor-postgres`), then restart the servers. With `database.bundled.password` instead, the last
two steps are a `helm upgrade` with the new value:

```sh
kubectl -n qualor exec qualor-postgres-0 -- psql -U qualor -d qualor -c "ALTER USER qualor PASSWORD '<new hex password>'"
kubectl -n qualor create secret generic qualor-postgres --from-literal=POSTGRES_PASSWORD='<new hex password>' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n qualor rollout restart deployment/qualor
```

### Settings

Every server setting of the table below has a value in `config` (`publicUrl`, `trustProxy`,
`scmInternalHosts`, `llmInternalHosts`, `ssoInternalHosts`, `forcePasswordSignIn`,
`workerConcurrency`, `logLevel`) or goes into `extraEnv`, for example:

```yaml
extraEnv:
  - name: QUALOR_UPLOAD_MAX_COMPRESSED_BYTES
    value: '104857600'
```

The chart checks its values against a schema, so a misspelt key fails the install instead of
being ignored. Pin the image by digest with `image.digest: sha256:…` to run exactly the image you
verified with the published `cosign.pub`.

The pods run as non-root with a read-only root filesystem, no capabilities and no service account
token: they meet the Pod Security Standard `restricted`. The default ingress annotations are for
ingress-nginx: a 50 MB request body, no request buffering, a 300 s read timeout. Give any other
ingress controller or load balancer the same limits. Your `ingress.annotations` are added to these
defaults. To drop one, set it to `null`.

A NetworkPolicy is available and off by default. With it on, the server accepts connections only
on its port (from the sources you list, or from anywhere), and in `bundled` mode PostgreSQL only
from the server. The server's outgoing connections stay open unless you list `egress` rules; then
add your SCM, model, webhook and database hosts there:

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

Restore with the server stopped, in a one-off pod on the same volume. The pod reads
`QUALOR_SECRET_KEY` from the Secret `qualor-secrets` (put your own Secret's name there if it
differs), and `fsGroupChangePolicy: OnRootMismatch` keeps the kubelet from re-owning the data
directory on the way in, which would leave it group-writable and PostgreSQL would refuse it. The
pod has the chart's own security settings, so a namespace that enforces the `restricted` standard
admits it:

```sh
kubectl -n qualor scale statefulset/qualor --replicas=0
kubectl -n qualor run qualor-restore --rm -i --restart=Never --image=qualor/server:0.3.0 \
  --overrides='{"spec":{"automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,"fsGroupChangePolicy":"OnRootMismatch","seccompProfile":{"type":"RuntimeDefault"}},"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-qualor-0"}},{"name":"tmp","emptyDir":{"sizeLimit":"64Mi"}}],"containers":[{"name":"qualor-restore","image":"qualor/server:0.3.0","imagePullPolicy":"IfNotPresent","args":["restore"],"stdin":true,"stdinOnce":true,"env":[{"name":"QUALOR_SECRET_KEY","valueFrom":{"secretKeyRef":{"name":"qualor-secrets","key":"QUALOR_SECRET_KEY"}}}],"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"data","mountPath":"/var/lib/qualor"},{"name":"tmp","mountPath":"/tmp"}]}]}}' \
  < qualor-YYYY-MM-DD.dump
kubectl -n qualor scale statefulset/qualor --replicas=1
```

With `external` or `bundled`, back up and restore the database with its own tools, as for Compose.

## External PostgreSQL

Use your own PostgreSQL 16 or later (18 is what Qualor is tested with) for a managed database (RDS,
Cloud SQL, Azure Database), your DBA's backups and monitoring, or more than one server replica. Set
`DATABASE_URL`, and the server starts no database of its own:

```sh
# in .env
DATABASE_URL=postgres://qualor:<password>@db.example.com:5432/qualor?sslmode=require
```

The user needs to own the database, or be allowed to create the extensions `citext` and `pg_trgm`
in it. The server's volume then stays empty.

To run PostgreSQL next to the server with Compose instead, add it as a second service:

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

Add `POSTGRES_PASSWORD=$(openssl rand -hex 32)` to `.env`. Use a hex value, because the password goes
into a `postgres://` URL.

## Server settings

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | none | an [external PostgreSQL](#external-postgresql) 16+. Unset: the server runs its own |
| `QUALOR_DATA_DIR` | `/var/lib/qualor` | the volume of the server's own PostgreSQL (unused with `DATABASE_URL`) |
| `QUALOR_SECRET_KEY` | required | at least 32 characters. It keys the CSRF tokens and encrypts stored secrets (SCM tokens, GitHub App keys, webhook secrets, the AI provider's API key) |
| `QUALOR_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | `admin` / none | the first instance admin, used on the first start only |
| `QUALOR_PUBLIC_URL` | none | the address users open Qualor at. It makes the links in MR/PR comments, commit statuses and check runs, the GitHub webhook URL, and the single sign-on and SCIM addresses. **Set it** once Qualor has a real address. [Single sign-on](./sso-and-scim.md) needs it |
| `QUALOR_SCM_INTERNAL_HOSTS` | none | the GitLab/GitHub Enterprise hosts on your internal network that Qualor may call, comma-separated, each with an optional port (`gitlab.corp:8443`). Without an entry, Qualor calls only hosts that resolve to public addresses |
| `QUALOR_LLM_INTERNAL_HOSTS` | none | the same, for the [AI assistant](./ai-assistant.md)'s model provider on your internal network (`ollama:11434`), which may then use plain `http`. A separate list: an SCM host listed above is not allowed for the model, nor the reverse |
| `QUALOR_SSO_INTERNAL_HOSTS` | none | the same, for the identity provider of [single sign-on](./sso-and-scim.md) on your internal network (`keycloak.corp:8443`), which may then use plain `http`. Its own list, like the two above |
| `QUALOR_FORCE_PASSWORD_SIGN_IN` | `false` | `true` lets every user who has a password sign in with it, whatever the single sign-on setting says: the emergency switch for a broken identity provider ([If your identity provider is down](./sso-and-scim.md#if-your-identity-provider-is-down)). Logged as a warning at every start, and recorded in the audit log. Any value but `true`, `false` or empty stops the start. Remove it once single sign-on works again |
| `QUALOR_TRUST_PROXY` | off | the reverse proxy in front: a hop count (`1`) or its IPs/CIDRs. `true` is rejected |
| `QUALOR_LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug` |
| `QUALOR_SESSION_TTL_HOURS` | `168` | browser session lifetime |
| `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES` | 50 MiB | largest report upload, as sent |
| `QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES` | 500 MiB | largest report once inflated (500 MiB is also the maximum) |
| `QUALOR_MAX_CONCURRENT_UPLOADS` | `4` | uploads read at once. More get 503 with `Retry-After` |
| `QUALOR_REQUEST_TIMEOUT_MS` | `300000` | longest a request may run |
| `QUALOR_WORKER_CONCURRENCY` | `1` | analysis jobs processed at once. Each slot can use several times one report's size in memory |
| `NODE_EXTRA_CA_CERTS` | none | a PEM bundle, when your GitLab, GitHub Enterprise or webhook receivers use a private CA. Mount the file into the container |
| `QUALOR_LICENSE` | none | an [enterprise licence](./enterprise.md) key. Not together with `QUALOR_LICENSE_FILE` |
| `QUALOR_LICENSE_FILE` | none | the path of a file holding the licence key (for example a Docker or Kubernetes secret), read at start: UTF-8, or UTF-16 with a byte-order mark. A file that cannot be read stops the start |

## Reverse proxy and TLS

Qualor does not terminate TLS. Put a reverse proxy on the same host in front of `127.0.0.1:8080`, and
set `QUALOR_TRUST_PROXY=1` in `.env`. Never publish the server on `0.0.0.0` without TLS, or tokens and
passwords cross the network in clear text.

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

A cloud load balancer works too. Give it the same body size limit and a 300 s timeout, and set
`QUALOR_TRUST_PROXY` to its hop count or address range.

If CI runners reach Qualor through a certificate from a private CA, give them that CA: set
`QUALOR_CA_FILE` (a path outside the checkout) or `NODE_EXTRA_CA_CERTS` in the job.

## Backups

With the server's own database, back up while it runs. From `/opt/qualor`:

```sh
docker compose exec -T server /opt/postgresql/bin/pg_dump -h /var/lib/qualor/run -U qualor -Fc qualor \
  > /var/backups/qualor/qualor-$(date +%F).dump
```

A dump holds user names, password hashes, token hashes and encrypted secrets, so store it like a
secret. Back up `.env` as well (it holds `QUALOR_SECRET_KEY`), but **separately** from the dumps.
Without that key, the restored SCM tokens, GitHub keys, webhook secrets and the AI provider's API key
cannot be decrypted, and you have to enter them again.

**Restore** with the server stopped. The `restore` command loads the dump into a new database and
replaces the old one only when the whole dump loaded, so a truncated or wrong file leaves the data
as it was:

```sh
docker compose stop server
docker compose run --rm -T server restore < qualor-YYYY-MM-DD.dump
docker compose up -d
```

With an [external PostgreSQL](#external-postgresql), use its own tools: `pg_dump -Fc`, and
`pg_restore` into an **empty** database while the server is stopped (never over the live one).

## Upgrades

1. Read the release notes.
2. Back up the database (above).
3. Set the new version in `.env` (`QUALOR_VERSION=0.3.0`, or its minor tag `0.3`). With the minor tag
   `0.3`, patch releases (`0.3.1`, `0.3.2`) need no change here; a new minor version needs a new tag.
   Then:

   ```sh
   docker compose pull server
   docker compose up -d
   ```

   Migrations run at start, and `/readyz` turns 200 once they have.

   On Kubernetes:

   ```sh
   helm upgrade qualor oci://registry-1.docker.io/qualor/qualor --version 0.3.0 -n qualor -f values.yaml
   ```

   Migrations run the same way; with the embedded database the pod is replaced, not doubled.
4. Move the scanner in your CI to the same release.

**Migration `0006` (single sign-on and SCIM)** adds a column, a foreign key and an index to the
two membership tables (organisation and project members), and holds a lock on both until it
finishes. With the server's own database, or a few thousand memberships, that takes a moment. On a
large external database it takes longer, and any server of the previous version still serving
requests waits on nearly every request meanwhile, since permission checks read those tables. Run
that upgrade at a quiet time. No existing row is rewritten.

Migrations only go forward. To roll back, set `QUALOR_VERSION` back to the previous version, and
restore the backup you took before the upgrade, as above.

The server's own PostgreSQL moves between minor versions (18.x) with the image and needs nothing. A
future move to a new major version will be described in that release's notes (back up with the old
release, restore with the new one).

Changing `QUALOR_SECRET_KEY` signs everyone out and makes stored secrets unreadable until they are
set again.

## Health and monitoring

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | the process is alive (no database access) |
| `GET /readyz` | the database is reachable and migrations are applied |
| `GET /api/v0/system/info` (signed in) | version, edition, features and UI extensions |

## Retention

A daily housekeeping job deletes old data:

| Data | Kept |
|---|---|
| uploaded reports | 7 days after processing |
| closed issues | 30 days |
| branches and MRs that have no analysis | 30 days |
| webhook deliveries | 30 days |
| AI assistant requests and answers | 90 days; stored prompts (off by default) 1–90 days, default 7 |
| audit log events (enterprise, `audit-log`) | 365 days by default, 30 days to 100 years (**Settings → Audit settings**; [Roles and the audit log](./roles-and-audit.md#retention)) |
| analyses and measures | forever |

## Trivy's vulnerability database

Each scanner image carries a snapshot of Trivy's vulnerability database from the day it was built,
and the scan never downloads one. Reports carry the database date, and a scan warns with
`VULNERABILITY_DB_STALE` once it is more than 14 days old. Keep the scanner on a current release
(the minor tag `0.3` does that for its patch releases), or fetch a fresh database in the job and
point `QUALOR_TRIVY_CACHE_DIR` at it; see [Languages and analyzers](./languages-and-analyzers.md#dependencies-trivy).

Building the images from source is described in [`deploy/README.md`](../../deploy/README.md), for
contributors and for anyone who wants to.
