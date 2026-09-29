# A local Linux environment with the analyzer toolchain CI installs (plan 1D Task 2): Node 22,
# JDK 17 (PMD, SpotBugs, javac), PMD, SpotBugs, OpenGrep, Gitleaks and Trivy with its database
# from install.sh, and bun. Also the .NET 8 and 10 SDKs and Roslynator from install-dotnet.sh
# (plan 2D), and Qualor's sonarjs pass in /opt/qualor/sonarjs (plan 8A/8B).
#   docker build -t qualor-analyzers tools/analyzers
# Pinned by version and digest (multi-arch index); bump both together.
FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7
RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-17-jdk-headless unzip \
  && rm -rf /var/lib/apt/lists/*
COPY install.sh /tmp/install.sh
RUN sh /tmp/install.sh
ENV PATH=/opt/qualor/bin:$PATH
# Qualor's sonarjs pass into /opt/qualor/sonarjs, as deploy/scanner/Dockerfile installs it (plan 8A/8B).
COPY --chmod=0644 sonarjs/package.json sonarjs/package-lock.json sonarjs/run.mjs sonarjs/categories.mjs /opt/qualor/sonarjs/
RUN eval "$(grep -E '^SONARJS_[A-Z0-9_]+=' /tmp/install.sh)" \
  && cd /opt/qualor/sonarjs \
  && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
  && test "$(node -p 'require("eslint-plugin-sonarjs/package.json").version')" = "$SONARJS_VERSION" \
  && curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o /tmp/sonarjs.tar.gz \
    "https://github.com/SonarSource/SonarJS/archive/${SONARJS_COMMIT}.tar.gz" \
  && echo "${SONARJS_SOURCE_SHA256}  /tmp/sonarjs.tar.gz" | sha256sum -c - \
  && mkdir /tmp/sonarjs-rules \
  && tar -xzf /tmp/sonarjs.tar.gz -C /tmp/sonarjs-rules --no-same-owner --strip-components=12 --wildcards \
    '*/sonar-plugin/javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript/S*.json' \
  && node categories.mjs /tmp/sonarjs-rules \
  && rm -rf /tmp/sonarjs.tar.gz /tmp/sonarjs-rules /tmp/install.sh /root/.npm \
  && chmod -R a+rX /opt/qualor/sonarjs
COPY install-dotnet.sh /tmp/install-dotnet.sh
RUN sh /tmp/install-dotnet.sh && rm /tmp/install-dotnet.sh
ENV DOTNET_ROOT=/opt/qualor/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
RUN corepack enable && npm install -g bun@1.3.13
