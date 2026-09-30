# Deploying Qualor

Three images, all built from this repository. `qualor/server`, `qualor/scanner` and
`qualor/scanner-dotnet` are released on Docker Hub as `qualor/server:<tag>`,
`qualor/scanner:<tag>` and `qualor/scanner-dotnet:<tag>` (the source repository is
<https://github.com/qualor-dev/qualor>). To build them yourself:

| Image                   | Dockerfile                         | What it is                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `qualor/server`         | `deploy/server/Dockerfile`         | the API, the web UI (`QUALOR_UI_DIR=/app/ui`) and the analysis worker in one Node process, plus PostgreSQL 18 built from source, which the server runs itself when `DATABASE_URL` is unset; distroless, user 65532, about 340 MB                                                                                                                                                                                   |
| `qualor/scanner`        | `deploy/scanner/Dockerfile`        | the `qualor` CLI (entrypoint) with Node.js, a Temurin JRE 17, git, Qualor's own sonarjs pass (eslint-plugin-sonarjs 2.0.4), its own HTML and CSS linters (stylelint 17.15, HTMLHint 1.9.2) and the pinned analyzers of `tools/analyzers/install.sh` (PMD, SpotBugs, OpenGrep, Gitleaks, Trivy, Ruff, detekt, SwiftLint) with Trivy's vulnerability database; user `node`, about 3.5 GB (1.4 GB of it the database) |
| `qualor/scanner-dotnet` | `deploy/scanner-dotnet/Dockerfile` | `qualor/scanner` plus the .NET 8 and .NET 10 SDKs, the bundled Roslynator analyzers and SonarAnalyzer.CSharp 9.32 of `tools/analyzers/install-dotnet.sh`, for C# projects; about 5.3 GB (about 1.8 GB more than `qualor/scanner`)                                                                                                                                                                                  |

`qualor/server` also carries the enterprise plugin (`/app/enterprise/plugin.js`, built from
`enterprise/`) under its own licence, the Qualor Enterprise Licence in
`/app/enterprise/LICENSE`, not MIT. The image sets `QUALOR_PLUGIN_PATHS=/app/enterprise/plugin.js`,
and the server imports that file only while a valid licence key is configured, including its
14-day grace period; without one the file is never read.
Building, running, mirroring or redistributing the image with the plugin unused needs no
subscription; production use of the plugin does, and is limited to what the key enables (its
features and its validity, grace period included), as `enterprise/LICENSE` says.

```sh
docker build -f deploy/server/Dockerfile -t qualor/server:dev .
docker build -f deploy/scanner/Dockerfile -t qualor/scanner:dev .
docker build -f deploy/scanner-dotnet/Dockerfile --build-arg SCANNER_IMAGE=qualor/scanner:dev -t qualor/scanner-dotnet:dev .
```

`qualor/scanner-dotnet` is built from an already-built `qualor/scanner` (`SCANNER_IMAGE`, a
required build argument: `docker build -f deploy/scanner-dotnet/Dockerfile .` alone fails at once,
before any layer runs, since the base image name is left invalid on purpose), so
`docker build -f deploy/scanner/Dockerfile .` on its own still produces a plain `qualor/scanner`
with no C# tooling. A local build of any of the three can stand in where the examples say
`qualor/scanner:<tag>` or `qualor/scanner-dotnet:<tag>`.

`pnpm deploy:scanner-dotnet-check [image]` (default `qualor/scanner-dotnet:dev`) checks a built
`qualor/scanner-dotnet` in one `docker run`: `dotnet --list-sdks` lists the SDK versions of
`tools/analyzers/install-dotnet.sh`, `/opt/qualor/dotnet/analyzers` holds the 8 Roslynator DLLs,
`/opt/qualor/licenses/` has the .NET, Roslynator and tree-sitter-c-sharp licence files, and
`qualor version` lists the `csharp` grammar. Run it after building the image and before releasing
it.

Every base image is pinned by digest. The server and scanner Dockerfiles map `TARGETARCH` for
amd64 and arm64, so `docker buildx build --platform linux/arm64 …` should work, but only amd64 has
been built so far; `deploy/scanner-dotnet/Dockerfile` detects its architecture itself
(`tools/analyzers/install-dotnet.sh`, `uname -m`), so it needs no `TARGETARCH` build argument.

Scan a built scanner image for known vulnerabilities with the accepted ones left out:

```sh
trivy image --severity HIGH,CRITICAL --ignorefile deploy/scanner/.trivyignore.yaml qualor/scanner:dev
```

`deploy/scanner/.trivyignore.yaml` (both scanner images) lists each accepted vulnerability with its
reason and a review date (`expired_at`, after which Trivy reports it again): Debian packages
without a fix yet, npm's own dependencies in the npm that Node.js 22 bundles, and parts of PMD,
Trivy and the .NET 8 SDK that the latest releases still carry. A finding with a fix is a version
bump, not an entry. Gitleaks is built from its release tag with a current Go in
`deploy/scanner/Dockerfile`, because its release binaries use a Go with known vulnerabilities.

`qualor/server` and `qualor/scanner` each have a companion image, `qualor/server-sources` and
`qualor/scanner-sources`, which carries the source code of its copyleft components and is always
released with the same tag (see [Releasing the images](#releasing-the-images)).
`qualor/scanner-dotnet` adds one copyleft component of its own, SonarAnalyzer.CSharp (LGPL-3.0;
the .NET SDK is MIT and Roslynator is Apache-2.0), whose source is in the combined
`qualor/scanner-sources` next to what `qualor/scanner` already puts there, so
`qualor/scanner-dotnet` still has no `-sources` companion of its own; it carries `qualor/scanner`'s.

## docker compose

`deploy/docker-compose.yml` runs the server against an external PostgreSQL 18 (the development and
test stack). Users run the image alone, with its embedded PostgreSQL on a volume: the compose file
of `docs/guide/install-server.md`; `pnpm deploy:embedded-check [image]` checks that mode end to end
(start, restart, a second container refused, backup and `restore`).

`deploy/docker-compose.yml`:

```sh
cp deploy/.env.example deploy/.env      # fill in the three secrets: openssl rand -hex 32
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml ps     # wait for "healthy"
```

- **Secrets.** `POSTGRES_PASSWORD`, `QUALOR_SECRET_KEY` (at least 32 characters) and
  `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` (at least 12) have no defaults: compose stops with
  `required variable … is missing a value` while any is empty. Use hex secrets (the database
  password goes into a `postgres://` URL). Nothing secret is baked into either image, and
  `.dockerignore` keeps `deploy/.env` out of the build context.
- **The server image is never pulled.** The `server` service has `pull_policy: never`: compose
  builds `qualor/server:dev` from this checkout when it is missing (`up --build` rebuilds it).
  That tag is never published, and with `pull_policy: missing` every first `up` would ask Docker
  Hub for it and print `pull access denied` before building. To run a released image, pull it
  yourself, name it in `deploy/.env` and start without building:

  ```sh
  docker pull qualor/server:<version>
  echo 'QUALOR_SERVER_IMAGE=qualor/server:<version>' >> deploy/.env
  docker compose -f deploy/docker-compose.yml up -d --no-build
  ```

  `--no-build` matters: without it, an image missing from the host is built from this checkout
  and tagged with the release's name. With it, `up` stops with `No such image`. The same goes for
  an image you built or loaded elsewhere (`docker load`).

- **First login.** The first start creates the `default` organisation and the instance admin
  `admin` (`QUALOR_BOOTSTRAP_ADMIN_USERNAME`) with the bootstrap password. Change it after
  signing in; the variable is ignored once a user exists.
- **Network.** The server publishes `127.0.0.1:8080` only (`QUALOR_BIND_ADDRESS`, `QUALOR_PORT`).
  PostgreSQL has no published port and sits on an internal network only the server joins, but
  processes on the Docker host itself can still reach it at its container's bridge address (on
  Linux), so its password matters: keep `POSTGRES_PASSWORD` a generated one.
- **Hardening.** The server runs as a non-root user with a read-only root filesystem, no
  capabilities, `no-new-privileges` (PostgreSQL too) and a tmpfs `/tmp`. Its health check
  (`/healthz` in the image, `/readyz` in compose) needs no shell. Health checks only report:
  nothing restarts an `unhealthy` container (`restart: unless-stopped` acts when a process exits),
  so watch `docker compose ps` or `/readyz` from your monitoring.
- **Migrations** run at every start, before the server listens, under a PostgreSQL advisory lock,
  so replicas starting together apply them once. `/readyz` answers 503 until they are applied.
- **Configuration.** Every server variable of [configuration.md](../docs/guide/configuration.md) can be added to
  the `environment` of the `server` service (for example `QUALOR_WORKER_CONCURRENCY`).
- **Memory.** Give the server at least 1 GiB; reports near the 500 MiB decompressed ceiling need
  about 4 GiB.

`pnpm deploy:smoke` (`--build` to rebuild the image first) checks all of this against a throwaway
stack with generated secrets: compose refusing to start without them, health, the admin login,
the UI with its CSP nonce, the hardening and the unpublished database.

## A local model with Ollama

The AI assistant (README, [ai-assistant.md](../docs/guide/ai-assistant.md)) is off by default. To use a local model
instead of a hosted provider, run [Ollama](https://ollama.com) as another service on the
stack's `internal` network, with a volume for its models and **no published port**, in a file of
your own next to the stack, for example `deploy/docker-compose.ollama.yml`:

```yaml
services:
  ollama:
    image: ollama/ollama:<version> # pin a version (and its digest) as postgres is pinned
    restart: unless-stopped
    volumes:
      - ollama:/root/.ollama
    security_opt: ['no-new-privileges:true']
    networks: [internal]
  server:
    environment:
      QUALOR_LLM_INTERNAL_HOSTS: ollama:11434

volumes:
  ollama:
```

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.ollama.yml up -d
```

- **Listing the host.** A provider URL must be `https` unless its host is listed in
  `QUALOR_LLM_INTERNAL_HOSTS` (the syntax of `QUALOR_SCM_INTERNAL_HOSTS`, host and port; a separate
  list). `deploy/docker-compose.yml` carries the line commented out. Link-local and cloud metadata
  addresses stay refused, and a listed name that resolves to a loopback address is refused too.
- **The model.** The `internal` network has no route out, so Ollama cannot download models from
  there. Once the stack is up (compose has created the volume), pull one into the same volume with
  a throwaway container on the default network (restart the `ollama` service if it does not
  list the model afterwards):

  ```sh
  docker run -d --name ollama-pull -v qualor_ollama:/root/.ollama ollama/ollama:<version>
  docker exec ollama-pull ollama pull qwen2.5-coder:7b
  docker rm -f ollama-pull
  ```

  (`qualor_ollama` is the volume compose names for the project `qualor`; check with
  `docker volume ls`.)

- **Settings.** Sign in as an instance admin, open **Settings → AI assistant**, choose the
  OpenAI-compatible kind, base URL `http://ollama:11434/v1`, the model (`qwen2.5-coder:7b`) and no
  API key, and press **Test**. Then enable the organisations and features you want.
- **Speed.** On a CPU a fix suggestion can take a minute or more: raise the timeout in the same
  settings (up to 600 s) if requests end with "The model did not answer in time". Give Ollama the
  memory its model needs (several GiB for a 7B model).

## Reverse proxy and TLS

Qualor does not terminate TLS. Put a reverse proxy on the same host in front of
`127.0.0.1:8080` and tell the server to trust it with `QUALOR_TRUST_PROXY=1` in `deploy/.env`
(one hop; or the proxy's address). Session cookies are marked `Secure` when the proxy says the
request came over HTTPS. Caddy (it obtains the certificate itself):

```
qualor.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

nginx (inside a `server` block with your certificate):

```nginx
client_max_body_size 50m;          # QUALOR_UPLOAD_MAX_COMPRESSED_BYTES
proxy_request_buffering off;       # the CLI waits for 100 Continue before sending a report
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 300s;
}
```

Neither snippet has been run against Qualor yet. Never publish the server on `0.0.0.0` without
TLS in front of it: tokens and passwords would cross the network in clear text.

## Backups

The only state is the PostgreSQL volume (`qualor_pgdata`). Back it up with:

```sh
docker compose -f deploy/docker-compose.yml exec -T postgres pg_dump -U qualor -Fc qualor > qualor-$(date +%F).dump
```

A dump holds everything the server knows: user names and emails, password hashes, the hashes of
every access token, and webhook secrets (encrypted). Store it like a secret: readable only by
you, encrypted at rest when it leaves the host. Back up `QUALOR_SECRET_KEY` too, but securely and
**separately** from the dumps: the webhook secrets are encrypted with a key derived from it, so a
restore without it keeps them unreadable, and a dump stored next to its key protects
nothing.

**Restore into an empty database**, never over the live one: `pg_restore --clean` only drops what
the dump itself contains, so tables a newer migration added would survive next to a migration
journal that no longer lists them, and the next start would fail on `CREATE TABLE`. Stop the
server, recreate the database, restore, start:

```sh
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml exec -T postgres dropdb -U qualor qualor
docker compose -f deploy/docker-compose.yml exec -T postgres createdb -U qualor qualor
docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore -U qualor -d qualor < qualor-YYYY-MM-DD.dump
docker compose -f deploy/docker-compose.yml up -d
```

(Removing the volume instead, `docker compose -f deploy/docker-compose.yml down --volumes`, then
`up -d postgres` alone before `pg_restore`, works too; the new volume takes the current
`POSTGRES_PASSWORD`.)

## Upgrading

1. Read the release notes (v0 changes are listed in the plan and, later, `CHANGELOG.md`).
2. Back up the database (above), and keep the image you run now under a second name, so you can
   go back to it: `docker tag qualor/server:dev qualor/server:previous`.
3. Update the checkout and run `docker compose -f deploy/docker-compose.yml up -d --build` (or
   `docker pull` the new release, point `QUALOR_SERVER_IMAGE` at it, then `up -d --no-build`). The new server
   applies its migrations at start, before it listens; `/readyz` turns 200 once it has.
4. Upgrade the scanner image your CI uses. A newer CLI talks to an older v0 server as far as the
   API allows, but keep them on the same release.

Migrations only go forward. To go back, set `QUALOR_SERVER_IMAGE=qualor/server:previous` in
`deploy/.env`, restore the backup taken before the upgrade into an empty database exactly as
above (its last command, `up -d`, then starts the previous image; do not add `--build`, which
would rebuild the current checkout under that name). The old server then finds the schema and
the migration journal it knows.

Changing `POSTGRES_PASSWORD` later needs `ALTER USER qualor PASSWORD '…'` in PostgreSQL as well,
since the variable only sets it when the volume is created. Changing `QUALOR_SECRET_KEY` signs
everyone out and makes stored webhook secrets unreadable.

## The scanner image in CI

See the [README](../README.md) for the GitLab and GitHub one-liners. The image expects the
repository in its working directory with full history (`GIT_DEPTH: 0`, `fetch-depth: 0`),
`QUALOR_URL` and `QUALOR_TOKEN` in the environment, and exits with the codes listed in
[cli.md](../docs/guide/cli.md). It
trusts any checkout owner (git `safe.directory '*'`), so a runner's uid is fine. A private CA goes
in `QUALOR_CA_FILE`; proxies in `HTTPS_PROXY`/`NO_PROXY`. No Semgrep or OpenGrep rules are bundled
yet: name your own rule files in `analyzers.semgrep.configs`, or the analyzer is skipped.
ESLint runs from the project's own `node_modules` (install the dependencies first), and SpotBugs
needs compiled classes, so build Java projects before `qualor scan`.

**Trivy's vulnerability database.** The image carries a snapshot, pinned in
`tools/analyzers/install.sh` (`TRIVY_DB_DIGEST`, `TRIVY_DB_CREATED`); the scan never downloads one,
so its vulnerability data is as old as the image. Reports carry the database's date
(`engines[].database`) and a `VULNERABILITY_DB_STALE` warning past 14 days. Refresh it by moving
the pin and rebuilding the image: `pnpm trivy-db:pin` writes the newest snapshot's digest into
`install.sh` (upstream builds one every 6 hours and deletes old ones after a time it does not
document, so the pin must also move when a build reports it gone; the CIs cache the pinned layer,
which gives a grace period), then build and release as below; a weekly image rebuild keeps it
fresh enough. Or give a CI job its own database: fetch one in the scan job before `qualor scan`
(`trivy image --download-db-only --cache-dir /tmp/trivy`, from a mirror you choose with
`--db-repository`; Trivy is in the image) and set `QUALOR_TRIVY_CACHE_DIR=/tmp/trivy`. The CLI
refuses a directory inside the checkout, or one whose `db/` files resolve into it, and trusts
whatever database it finds: the directory must not be writable by jobs that run repository code.

On GitLab, `cache:paths` must lie inside `$CI_PROJECT_DIR` (the checkout), so a cached database
has to be copied out before the scan, after checking that the branch did not commit it:

```yaml
qualor:
  cache: { key: trivy-db, paths: [.trivy-db/], policy: pull }
  script:
    - test -z "$(git ls-files .trivy-db)"
    - rm -rf /tmp/trivy && cp -R .trivy-db /tmp/trivy && rm -rf .trivy-db
    - QUALOR_TRIVY_CACHE_DIR=/tmp/trivy qualor scan --gitlab-code-quality gl-code-quality-report.json
```

Push that cache only from a pipeline of a protected branch, and keep the project setting that
separates the caches of protected and unprotected branches (on by default): a cache that merge
request pipelines of unprotected branches can write can be poisoned by any of them, with a
database that knows none of their vulnerabilities. Merge request pipelines then read the
unprotected cache, which they can write themselves; for them, fetching in the job is the safe
choice.

Third-party licences are in `/opt/qualor/NOTICE.md` and `/opt/qualor/licenses/` inside the
image ([scanner/NOTICE.md](scanner/NOTICE.md)), with where the source of its copyleft components
is published (`/opt/qualor/SOURCES.md`). The server's are in `/app/NOTICE.md` and
`/app/SOURCES.md` ([server/NOTICE.md](server/NOTICE.md)).

## Helm chart

The chart is in `deploy/helm/qualor`; `values.schema.json` specifies its values (database modes,
security, render-time checks). The user documentation is the
Kubernetes section of [install-server.md](../docs/guide/install-server.md#kubernetes-helm), and
`tools/helm/guide.test.ts` and `guide.helm.test.ts` keep its commands and values in step with the
chart. Its version is the server's version (`pnpm release:version` sets both).

- `pnpm helm:test` runs the render tests (`helm lint --strict`, `helm template` of every mode and
  every failure) through the release toolbox image, so Helm is never installed on the host.
- `pnpm helm:smoke` installs the chart on k3s in one Docker container, in embedded mode (a pod
  restart, then a backup and a restore) and in bundled mode (2 replicas), and checks what the
  pods really run with. It needs a built `qualor/server:dev` (above), which it imports into
  k3s instead of pulling.

The chart is published only by `release.yml`, to
`oci://registry-1.docker.io/qualor`, signed and with the server pinned by digest. The first
release is `0.1.0`.

## Releasing the images

All three images contain copyleft software. The scanner: OpenGrep and SpotBugs (LGPL-2.1), Trove4J
(LGPL-2.1, inside detekt's jar), what OpenGrep's release binary links or bundles (GMP, GNU Readline,
certifi), the MPL-2.0 and CDDL-1.0 Java libraries of SpotBugs and PMD, eslint-plugin-sonarjs
(LGPL-3.0) and axe-core (MPL-2.0) in Qualor's own sonarjs pass, the MPL-2.0 Go modules compiled into
Trivy and Gitleaks, the three MPL-2.0 crates compiled into Ruff, the Temurin JRE (GPL-2.0 with the
Classpath Exception), the JavaScriptCore/WebKit and TinyCC that Bun links into the `qualor` binary,
and its Debian packages. `qualor/scanner-dotnet` adds one more, SonarAnalyzer.CSharp (LGPL-3.0), on
top of everything the scanner already carries. The server: its Debian packages (glibc, the GCC
runtime and others). Qualor publishes their complete corresponding source next to the images rather
than rely on written offers. So every release of `qualor/<image>:<tag>` also publishes
`qualor/<image>-sources:<tag>` for the server and the scanner (the scanner's also covers what
`qualor/scanner-dotnet` adds), same registry, same tag, and never one without the other:

1. `pnpm deploy:sources` downloads what `deploy/scanner/sources.json` and
   `deploy/<image>/debian-sources.json` pin into `.tmp/scanner-sources/` and
   `.tmp/server-sources/` (git-ignored; the Debian files go into `debian/`), over https only, and
   keeps a file only when its SHA-256 matches (a Debian file also has to match its `.dsc`); any
   mismatch deletes it and fails the command. It then writes `SOURCES.md` (the index, the same as
   the committed `deploy/<image>/SOURCES.md`), `SHA256SUMS`, `README.md` and the manifests there.
   It never runs what it downloads. About 1.9 GB for the scanner (the WebKit tar is 1.1 GB, the
   sonar-dotnet source about 120 MB, SonarJS about 20 MB, axe-core 4 MB and the three Ruff crate
   archives under 100 KB together, Trove4J 0.5 MB) and 120 MB for the server; a rerun keeps the files that still
   verify.
2. `pnpm deploy:release-images --tag <tag> [--also <tag>]…` checks those files again, builds the
   server and scanner images under a staging name (`qualor-release-staging/<image>:<tag>`, which
   no registry push can reach by accident), checks that the Debian packages in each are exactly
   those its `debian-sources.json` pins, and builds both sources images
   (`deploy/sources.Dockerfile`: `scratch` with the files in `/sources/`), also under staging
   names. It then builds `qualor/scanner-dotnet` from the staging scanner, only after the
   scanner's Debian check has passed (`SCANNER_IMAGE=qualor-release-staging/scanner:<tag>`; its
   added SonarAnalyzer.CSharp is already in the scanner's sources image, so it carries that one
   too, and builds no `-sources` image of its own). Only when every check has
   passed does it tag the five release names, `qualor/scanner-sources`, `qualor/scanner`,
   `qualor/scanner-dotnet`, `qualor/server-sources` and `qualor/server`, each with `<tag>` and
   every `--also <tag>` (the moving tags: `0.Y` in 0.x, `X.Y` and `X` from 1.0;
   `latest` and a floating `0` are refused), and drop the staging names; a failed check leaves no
   `qualor/<image>:<tag>` behind without its sources image. `--namespace <name>` replaces `qualor`
   (for a test registry). The Debian check matters: `apt-get` installs the current versions of
   `git`, `ca-certificates` and their dependencies, so a later build can contain other versions
   than the pinned ones. When it fails, run the
   `pnpm deploy:debian-sources <image> --image qualor-release-staging/<image>:<tag>` it prints,
   which regenerates the manifest from the image, then `pnpm deploy:sources` and
   `pnpm deploy:sources --index`, commit, and build again.
3. Publishing is `release.yml`, started by hand on the tag; do not push by
   hand. It pushes to Docker Hub (the `qualor` namespace) in this order (`RELEASE_ORDER`,
   `tools/deploy/release.ts`): `qualor/scanner-sources`, `qualor/scanner`,
   `qualor/scanner-dotnet`, `qualor/server-sources`, `qualor/server`. Each sources image goes
   before its image, and the scanner before `qualor/scanner-dotnet`. Each image goes up first
   under the non-moving tag `staging-<version>` only, is signed and verified by digest, and only
   then gets its version and moving tags, so no release tag is ever unsigned.
   The repository descriptions are in [dockerhub/](dockerhub/).
4. Attach every file of `.tmp/scanner-sources/` and `.tmp/server-sources/` to the release page of
   the tag (the archives, the `debian/` directory, `SOURCES.md`, `SHA256SUMS`,
   `README.md`, `sources.json` and `debian-sources.json`) as one tar per image,
   `qualor-<version>-scanner-sources.tar` and `qualor-<version>-server-sources.tar`, since the
   Debian and index file names repeat. `pnpm release:publish` writes them with the other release
   assets, lists them in the signed `SHA256SUMS`, and publishes the release only
   after a download of the draft verifies.

Keep the images and archives available for as long as those images are distributed.

`pnpm release:dry-run` runs all of this, pushes only to a registry on 127.0.0.1,
and signs with a throwaway key; publishing is `release.yml`, never by hand.
`pnpm release:verify <dir> [--key <cosign.pub> | --self-check]` checks a release
directory, or a download of a release: `SHA256SUMS` and its signature, and that no file is
changed, missing or unlisted. Without `--key` it uses the committed `cosign.pub`; the key inside
the directory only with `--self-check` (the dry run's own check), which proves nothing about who
made it. It prints the key it used. Verify a real release with `--key` and the published
`cosign.pub`. The directory has to be inside this checkout (for example under `.tmp/`),
because the toolbox container sees only the repository.

**What is not included, and why.** The WebKit archive leaves out WebKit's test suites, benchmarks
and website (`JSTests`, `LayoutTests`, `ManualTests`, `PerformanceTests`, `WebDriverTests`,
`Websites`, most of the repository's size). They are not needed to build JavaScriptCore or Bun;
whether the source is still "complete" without them is a judgement call, and the fallback is the full tree (drop `exclude` from the WebKit entry of
`sources.json`). OpenGrep's `tests/semgrep-rules` submodule (test data) is left out the same way.
The written offers in the NOTICE files remain, as a courtesy only.

**Updating the sources.** Bumping OpenGrep, SpotBugs, PMD, Trivy, Gitleaks, Ruff or detekt in
`tools/analyzers/install.sh`, Bun
in `cli/scripts/targets.ts`, or the Temurin base of `deploy/scanner/Dockerfile`, fails
`tools/deploy/sources.test.ts` until `sources.json` has the new sources. Every entry of the bumped
component has to be re-derived, not only its tag archive:

- OpenGrep: the tag's archive, one archive per git submodule at the commit the tag records
  (except `tests/semgrep-rules`), and what the new release binary contains. Run it once, look in
  `~/.cache/opengrep/<version>/`, and check the libraries it bundles (compare their ELF build IDs
  with the packages of the `manylinux` image of the release build) and the C libraries
  `opengrep-core` links (strings such as GMP's `GNU MP` messages; Alpine's `APKINDEX` of the
  release's Alpine version gives the package versions);
- SpotBugs and PMD: the release's `-source.zip`, and the source jars of the MPL, CDDL or EPL jars
  in their `lib/`. Saxon-HE, which both bundle, is pinned once, under SpotBugs: a PMD bump fails
  the test through Rhino and jsr250-api, but not through Saxon, so check which Saxon-HE the new
  PMD's `lib/` holds (and SpotBugs', on a SpotBugs bump) and re-derive that entry by hand;
- detekt: on a bump, re-derive the Trove4J version from `kotlin-compiler-embeddable`'s POM and the
  jar's licence notes (`DETEKT-THIRD-PARTY.txt`);
- Bun: its tag's archive and the WebKit and TinyCC commits in its `scripts/build/deps/webkit.ts`
  (`WEBKIT_VERSION`) and `scripts/build/deps/tinycc.ts` (`TINYCC_COMMIT`);
- Temurin: Adoptium's `OpenJDK17U-jdk-sources_<version>.tar.gz` of the release;
- Trivy: the copyleft Go modules the new release binary compiles in. List them with
  `go version -m trivy` (a `golang` container will do), look up each module's licence (its
  `LICENSE` in the module cache after `go mod download` of the tag), and pin the zip
  `https://proxy.golang.org/<module>/@v/<version>.zip` of every MPL, LGPL, GPL or EPL one. The
  same for Gitleaks, which `deploy/scanner/Dockerfile` builds from its tag: list the modules of the
  binary in the built image (`GITLEAKS_GO_UPGRADES` moves some of them off the tag's `go.sum`). The
  Trivy database pin (`TRIVY_DB_DIGEST`) is data, not a component, and moves on its own
  (`pnpm trivy-db:pin`, above);
- Ruff: `tools/analyzers/ruff-licences.mjs` regenerates `RUFF-DEPENDENCIES.txt` from the new
  release's `Cargo.lock` and fails on a licence outside its allowlist; re-derive the MPL-2.0 crate
  entries (`colored`, `option-ext`, `version-ranges`, unless the new `Cargo.lock` swaps one out) by
  their new `Cargo.lock` checksums.

Take each SHA-256 from a download you checked, then run `pnpm deploy:sources --index`. The Debian
`.dsc` files are checked against the SHA-256 in Debian's `Sources` index, which
`pnpm deploy:debian-sources` downloads from `deb.debian.org` over TLS and trusts as such: it does
not verify the index against the archive's signed `InRelease` file (no PGP check). A new base
image digest or a change to the apt packages changes the Debian sets instead: regenerate them
with `pnpm deploy:debian-sources <image>` from the new image (`tools/deploy/debian-sources.test.ts`
fails while the manifest names another base or other apt packages).

**How stable the digests are.** Release assets (SpotBugs' `-source.zip`, Adoptium's source
archive, PyPI and Maven Central files, GMP's tarball, AlmaLinux's source RPM) are stored once and
do not change. The GitHub archives (`archive/<ref>.tar.gz`, served by codeload.github.com) are
generated on request: the tar inside is stable, but GitHub has changed its gzip bytes once before
(January 2023, reverted) and only promises notice before it does so again. Those URLs therefore
pin a commit or a tag, and the published copy is the verified one in the sources image, not a
fresh download. GitHub refuses to generate archives of `oven-sh/WebKit` (HTTP 422), so its entry
is `git archive` of the commit (a shallow `git fetch` of about 1.7 GB, then an uncompressed tar),
which is byte-stable for a given tree. Debian files leave `deb.debian.org` once superseded; the
download then falls back to `snapshot.debian.org`, which keeps every file by its SHA-1. If a
digest ever stops matching, `pnpm deploy:sources` fails closed: compare the extracted trees before
you accept a new digest.

**The standalone `qualor` binary.** When the CLI binary is released on its own (Phase 4 release
automation), it is the same Bun runtime, so its release must carry the same Bun, WebKit and TinyCC
sources (the `bun` entries of `sources.json`) next to it.

## The dogfood job in GitLab CI

The `dogfood` job of `.gitlab-ci.yml` builds both images inside a Docker-in-Docker service, which
needs a runner with `privileged = true`. A privileged container is root on the runner's host, and
the job runs the merge request's own code (its Dockerfiles and scripts), so whoever can open a
merge request that runs it can take over that host. Mitigations, best first:

- a dedicated, ephemeral runner for this job only (one fresh VM per job, no other projects, no
  credentials on it), selected by a runner tag;
- run it for protected branches and for merge requests from trusted members only, and never for
  merge requests from forks;
- or avoid `privileged` altogether: rootless Docker-in-Docker, or the Sysbox runtime.

The GitHub job needs none of this: GitHub-hosted runners are throwaway VMs with Docker.

## Qualor on Qualor

Build both images first (`docker build … -t qualor/server:dev` and `-t qualor/scanner:dev`, as at
the top; the scripts never pull or build them). `pnpm deploy:exit-test` runs the Phase 1 exit test with both images: it scans this repository's
HEAD as main, then a merge request adding one `==` (the gate must fail) and a clean one (it must
pass). `pnpm dogfood --base <rev> [--head <rev>] [--mr <id> [--mr-target <branch>]] [--coverage <lcov>]` is what the
`dogfood` CI jobs run, and `pnpm deploy:screenshots` (`--keep` to leave the stack running) writes
screenshots of the dockerized server to `.tmp/screenshots-docker/`. `pnpm deploy:smoke --build` builds the server
image itself; `pnpm dogfood` and the exit test need the scanner image as well.
