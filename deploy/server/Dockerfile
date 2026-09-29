# syntax=docker/dockerfile:1
# The qualor/server image: the server bundle, its migrations and the built web UI on a
# distroless base, as a non-root user, plus the embedded PostgreSQL the server starts itself when
# no external database is configured, and the enterprise plugin, which the server loads only with
# a valid licence key. Build from the repository root:
#   docker build -f deploy/server/Dockerfile -t qualor/server:dev .
# Every base image is pinned by version and digest (multi-arch index); bump both together.

FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS build
WORKDIR /src
RUN corepack enable
# Manifests first, so the dependency layer is reused until the lockfile or a manifest changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/shared/package.json packages/shared/
COPY server/package.json server/
COPY cli/package.json cli/
COPY ui/package.json ui/
COPY enterprise/package.json enterprise/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm --filter @qualor/server build \
  && pnpm --filter @qualor/enterprise build \
  && install -d -m 0755 /enterprise \
  && install -m 0644 enterprise/dist/plugin.js enterprise/dist/plugin.js.map enterprise/LICENSE \
    enterprise/package.json /enterprise/ \
  && pnpm --filter @qualor/ui build \
  && pnpm --filter @qualor/server deploy --prod --legacy /out \
  && rm -rf /out/node_modules/@qualor /out/node_modules/.pnpm/@qualor+* \
    /out/node_modules/.pnpm/node_modules/@qualor /out/node_modules/.bin \
    /out/node_modules/@types /out/node_modules/.pnpm/@types+* /out/node_modules/.pnpm/undici-types@* \
  && find /out/node_modules -xtype l -delete \
  && if find /out/node_modules -xtype l | grep -q .; then echo 'dangling links left' >&2; exit 1; fi
# The bundle inlines the workspace packages, so their copies (sources, tests, SARIF samples) and
# the top-level command wrappers stay out of the image; so do type declarations (@types/pg is a
# dependency of the server package, @types/node and undici-types come with it), which no code
# loads at run time. The links that pointed at any of them are removed, and the build fails if
# one is left dangling.

# PostgreSQL from the release tarball, pinned by version and SHA-256,
# built without the libraries the distroless base lacks (ICU, readline, zlib, OpenSSL: the
# database listens on a Unix socket only), with the two extensions the migrations create. The
# base has no shell, and initdb needs one, so the cluster is made here as a template the server
# copies into its volume on first start.
FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS postgres
ARG PG_VERSION=18.6
ARG PG_SHA256=555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f
# bison and flex are build tools of this stage only (PostgreSQL 18 tarballs ship no generated parsers).
RUN apt-get update   && apt-get install -y --no-install-recommends bison flex   && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/postgresql.tar.bz2 "https://ftp.postgresql.org/pub/source/v${PG_VERSION}/postgresql-${PG_VERSION}.tar.bz2"   && echo "${PG_SHA256}  /tmp/postgresql.tar.bz2" | sha256sum -c -   && mkdir /tmp/pg   && tar -xjf /tmp/postgresql.tar.bz2 -C /tmp/pg --strip-components=1   && cd /tmp/pg   && ./configure --prefix=/opt/postgresql --without-icu --without-readline --without-zlib     --without-openssl --without-llvm --without-lz4 --without-zstd     --with-system-tzdata=/usr/share/zoneinfo   && make -j"$(nproc)"   && make install   && make -C contrib/citext install   && make -C contrib/pg_trgm install   && cp COPYRIGHT /opt/postgresql/COPYRIGHT   && echo "${PG_VERSION}" > /opt/postgresql/VERSION   && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin qualorpg   && mkdir /tmp/template /var/lib/qualor   && chown 65532:65532 /tmp/template /var/lib/qualor
USER 65532:65532
RUN /opt/postgresql/bin/initdb -D /tmp/template --username=qualor --encoding=UTF8 --locale=C     --auth-local=trust --auth-host=reject   && echo 'CREATE DATABASE qualor;' | /opt/postgresql/bin/postgres --single -D /tmp/template postgres
USER 0:0
# Only what the server runs (postgres) and what backups need (pg_dump, pg_restore, psql) stays;
# the template is readable by every user, as the server copies it with its own modes.
RUN mv /tmp/template /opt/postgresql/template   && rm -f /opt/postgresql/template/postmaster.opts /opt/postgresql/template/postmaster.pid   && chmod -R a+rX,go-w /opt/postgresql/template   && cd /opt/postgresql/bin   && find . -type f ! -name postgres ! -name pg_dump ! -name pg_restore ! -name psql -delete   && rm -rf /opt/postgresql/include /opt/postgresql/lib/pgxs /opt/postgresql/share/man     /opt/postgresql/share/doc   && find /opt/postgresql/lib -name '*.a' -delete   && strip --strip-unneeded /opt/postgresql/bin/* /opt/postgresql/lib/*.so* /opt/postgresql/lib/postgresql/*.so 2>/dev/null;   /opt/postgresql/bin/postgres --version

# Only the node binary is taken from here: the runtime is distroless (no shell, no package
# manager), and its own Node 22 lags the engines floor of package.json.
FROM node:22.23.3-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS node

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# Owned by root, read-only to the server; the data volume is the server's.
COPY --from=postgres /opt/postgresql /opt/postgresql
COPY --from=postgres --chown=65532:65532 /var/lib/qualor /var/lib/qualor
# The base runs as "nonroot"; create /app as root so the server's user cannot add files to it.
USER 0:0
WORKDIR /app
# Owned by root and read-only for the server's user: nothing under /app is ever written.
COPY --from=build /out/node_modules ./node_modules
COPY --from=build /src/server/package.json ./package.json
COPY --from=build /src/server/dist ./dist
COPY --from=build /src/server/drizzle ./drizzle
COPY --from=build /src/ui/dist ./ui
# The enterprise plugin, source-available under its own licence, not
# MIT. The server imports it only while a licence key is valid (active, or in its 14-day grace
# period); without one it never reads the file. Its manifest names the licence for SBOM tools.
# The build stage sets the modes (files 0644, the directory 0755) whatever its umask, as the
# loader refuses a group- or world-writable plugin or directory; COPY makes them root's. (A
# `COPY --chmod=0644` would give the directory it creates 0644 too, which nobody could enter.)
COPY --from=build /enterprise ./enterprise
COPY --chmod=0644 LICENSE ./LICENSE
# Third-party notices, and the index of the source published as qualor/server-sources:<same tag>.
COPY --chmod=0644 deploy/server/NOTICE.md ./NOTICE.md
COPY --chmod=0644 deploy/server/SOURCES.md ./SOURCES.md
COPY --chmod=0644 deploy/scanner/licenses/NODE-LICENSE.txt ./NODE-LICENSE.txt
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    QUALOR_UI_DIR=/app/ui \
    QUALOR_PLUGIN_PATHS=/app/enterprise/plugin.js
# The distroless "nonroot" user (65532).
USER 65532:65532
# The embedded PostgreSQL's cluster and socket; unused (and empty) with an external database.
VOLUME ["/var/lib/qualor"]
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/local/bin/node", "--enable-source-maps", "dist/main.js"]
