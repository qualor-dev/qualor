# syntax=docker/dockerfile:1
# The qualor/scanner image: the `qualor` CLI binary plus the pinned analyzer toolchain
# of tools/analyzers/install.sh (PMD, SpotBugs, OpenGrep, Gitleaks, Trivy with a snapshot of its
# vulnerability database in /opt/qualor/share/trivy, Ruff), Qualor's sonarjs pass in /opt/qualor/sonarjs
# (eslint-plugin-sonarjs 2.0.4 on its own ESLint 9, tools/analyzers/sonarjs) and what they need to run:
# Node.js (to run a project's own ESLint), an exact Temurin JRE 17 (PMD, SpotBugs) and git.
# Build from the repository root:
#   docker build -f deploy/scanner/Dockerfile -t qualor/scanner:dev .
# Every base image is pinned by version and digest (multi-arch index); bump both together.

FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS cli
ARG TARGETARCH
WORKDIR /src
RUN corepack enable && npm install -g bun@1.3.13
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/shared/package.json packages/shared/
COPY server/package.json server/
COPY cli/package.json cli/
COPY ui/package.json ui/
COPY enterprise/package.json enterprise/
RUN pnpm install --frozen-lockfile
COPY . .
RUN case "$TARGETARCH" in amd64) T=linux-x64 ;; arm64) T=linux-arm64 ;; *) exit 1 ;; esac \
  && pnpm --filter @qualor/cli build "$T" \
  && install -m 0755 "cli/dist/qualor-$T" /qualor
# The binary bundles the CLI's production npm packages: keep their licence files, as installed.
RUN pnpm --filter @qualor/cli licenses list --prod --json > /tmp/npm-licenses.json \
  && node -e 'const fs = require("fs"), path = require("path"); \
    for (const list of Object.values(JSON.parse(fs.readFileSync("/tmp/npm-licenses.json", "utf8")))) \
      for (const pkg of list) pkg.paths.forEach((dir, i) => { \
        const files = fs.readdirSync(dir).filter((f) => /^(licen[cs]e|copying|notice)/i.test(f)); \
        if (files.length === 0) return; \
        const out = path.join("/npm-licenses", `${pkg.name}@${pkg.versions[i]}`); \
        fs.mkdirSync(out, { recursive: true }); \
        for (const f of files) fs.copyFileSync(path.join(dir, f), path.join(out, f)); \
      });'

# Gitleaks' own release binaries of GITLEAKS_VERSION (the latest release) are built with Go 1.24.11
# and golang.org/x/crypto 0.35.0, both with known vulnerabilities fixed since. The image builds the
# same tag from its source archive (checked against its SHA-256) as the release does (tag
# gore2regex, no cgo, -s -w, the version stamped in), with a current Go and the vulnerable
# golang.org/x modules raised to fixed releases; every other module stays as the tag's go.sum pins
# it, and `go get` checks what it adds against the Go checksum database. Keep GITLEAKS_VERSION equal
# to tools/analyzers/install.sh's (tools/deploy/images.test.ts checks), and drop this stage for
# install.sh's release binary once a release is built with a fixed Go.
FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS gitleaks
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SOURCE_SHA256=e90fb266d75837e75894c778bf594ab8e2787f12dce5a62651f21b893eaf9abb
ARG GITLEAKS_GO_UPGRADES="golang.org/x/crypto@v0.57.0 golang.org/x/text@v0.42.0"
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
RUN curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/archive/refs/tags/v${GITLEAKS_VERSION}.tar.gz" \
  && echo "${GITLEAKS_SOURCE_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/gitleaks.tar.gz --strip-components=1 \
  && go get $GITLEAKS_GO_UPGRADES \
  && go build -tags gore2regex \
    -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
    -o /gitleaks . \
  && /gitleaks version

FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY tools/analyzers/install.sh tools/analyzers/install-sonarjs.sh /tmp/
RUN sh /tmp/install.sh
# The Gitleaks built above replaces install.sh's release binary of the same version.
COPY --from=gitleaks /gitleaks /opt/qualor/bin/gitleaks
# Qualor's sonarjs pass (config.md §6): install-sonarjs.sh installs eslint-plugin-sonarjs on
# Qualor's own ESLint 9 from its lockfile without install scripts, and builds categories.json from
# the RSPEC metadata of the SonarJS source archive at the plugin's commit (install.sh's SONARJS_*
# pins), checked against its SHA-256 before it is unpacked; only the rule metadata is unpacked, and
# the archive is deleted. The same script installs it in CI (tools/ci.test.ts checks that).
COPY --chmod=0644 tools/analyzers/sonarjs/package.json tools/analyzers/sonarjs/package-lock.json tools/analyzers/sonarjs/run.mjs tools/analyzers/sonarjs/categories.mjs /tmp/sonarjs/
RUN sh /tmp/install-sonarjs.sh && rm -rf /tmp/sonarjs /tmp/install-sonarjs.sh

FROM eclipse-temurin:17.0.20_8-jre-noble@sha256:39d618b8fda3408cfe792db2b666c0e3db8ea4ae263ab4d0c3805933e5355f45 AS jre

FROM node:22.23.3-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  # CI runners check out as another user than the image's; the scanner only reads the checkout.
  && git config --system --add safe.directory '*'
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
COPY --from=tools /opt/qualor /opt/qualor
COPY --from=cli /qualor /usr/local/bin/qualor
COPY deploy/scanner/NOTICE.md /opt/qualor/NOTICE.md
# The index of the corresponding source published as qualor/scanner-sources:<same tag>.
COPY deploy/scanner/SOURCES.md /opt/qualor/SOURCES.md
COPY deploy/scanner/licenses/ /opt/qualor/licenses/
COPY LICENSE /opt/qualor/licenses/qualor/LICENSE
COPY --from=cli /npm-licenses /opt/qualor/licenses/qualor/npm/
# No Semgrep rules are bundled yet, so `qualor-default` finds an empty directory and the
# Semgrep/OpenGrep analyzer is skipped under `enabled: auto` (bring your own rules in `configs`).
RUN install -d /opt/qualor/rules/semgrep \
  && find /opt/qualor/licenses -type d -exec chmod 0755 {} + \
  && find /opt/qualor/licenses /opt/qualor/NOTICE.md /opt/qualor/SOURCES.md -type f -exec chmod 0644 {} +
ENV JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/qualor/bin:/opt/java/openjdk/bin:$PATH
USER node
WORKDIR /src
ENTRYPOINT ["qualor"]
CMD ["scan"]
