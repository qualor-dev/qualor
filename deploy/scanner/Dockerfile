# syntax=docker/dockerfile:1
# The qualor/scanner image: the `qualor` CLI binary plus the pinned analyzer toolchain
# of tools/analyzers/install.sh (PMD, SpotBugs, OpenGrep, Gitleaks, Trivy with a snapshot of its
# vulnerability database in /opt/qualor/share/trivy) and what they need to run:
# Node.js (to run a project's own ESLint), an exact Temurin JRE 17 (PMD, SpotBugs) and git.
# Build from the repository root:
#   docker build -f deploy/scanner/Dockerfile -t qualor/scanner:dev .
# Every base image is pinned by version and digest (multi-arch index); bump both together.

FROM node:22.23.2-bookworm@sha256:dd5847a04b0deee391fa145f1f4c6d214196668b6bcc7988ebed67249f226844 AS cli
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

FROM node:22.23.2-bookworm@sha256:dd5847a04b0deee391fa145f1f4c6d214196668b6bcc7988ebed67249f226844 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY tools/analyzers/install.sh /tmp/install.sh
RUN sh /tmp/install.sh

FROM eclipse-temurin:17.0.20_8-jre-noble@sha256:39d618b8fda3408cfe792db2b666c0e3db8ea4ae263ab4d0c3805933e5355f45 AS jre

FROM node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9
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
