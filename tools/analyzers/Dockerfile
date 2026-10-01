# A local Linux environment with the analyzer toolchain CI installs (plan 1D Task 2): Node 22,
# JDK 17 (PMD, SpotBugs, javac), PMD, SpotBugs, OpenGrep, Gitleaks, Trivy with its database,
# Ruff, detekt and SwiftLint (its static build) from install.sh, and bun. Also the .NET 8 and
# 10 SDKs and Roslynator from install-dotnet.sh (plan 2D), Qualor's sonarjs pass in
# /opt/qualor/sonarjs (plan 8A/8B) and Qualor's HTML and CSS linters in /opt/qualor/weblint
# (stylelint and HTMLHint, plan 8D), and Qualor's Ruby pass in /opt/qualor/rubocop (plan 9B).
#   docker build -t qualor-analyzers tools/analyzers
# Pinned by version and digest (multi-arch index); bump both together.
FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7
RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-17-jdk-headless unzip \
  && rm -rf /var/lib/apt/lists/*
COPY install.sh install-sonarjs.sh /tmp/
RUN sh /tmp/install.sh
ENV PATH=/opt/qualor/bin:$PATH
# Qualor's sonarjs pass into /opt/qualor/sonarjs, as deploy/scanner/Dockerfile and CI install it
# (plan 8A/8B; tools/analyzers/install-sonarjs.sh, tools/ci.test.ts).
COPY --chmod=0644 sonarjs/package.json sonarjs/package-lock.json sonarjs/run.mjs sonarjs/categories.mjs /tmp/sonarjs/
RUN sh /tmp/install-sonarjs.sh && rm -rf /tmp/sonarjs /tmp/install-sonarjs.sh /tmp/install.sh
# Qualor's HTML and CSS linters into /opt/qualor/weblint, as deploy/scanner/Dockerfile and CI
# install them (plan 8D; tools/analyzers/install-weblint.sh, tools/ci.test.ts).
COPY install-weblint.sh /tmp/
COPY --chmod=0644 weblint/package.json weblint/package-lock.json weblint/bundled.mjs weblint/files.mjs weblint/stylelint.mjs weblint/htmlhint.mjs /tmp/weblint/
RUN sh /tmp/install-weblint.sh && rm -rf /tmp/weblint /tmp/install-weblint.sh
# Qualor's Ruby pass into /opt/qualor/rubocop, as deploy/scanner/Dockerfile and CI install it
# (plan 9B; tools/analyzers/install-rubocop.sh, tools/ci.test.ts).
COPY install-rubocop.sh /tmp/
COPY --chmod=0644 rubocop/gems.lock rubocop/licence-gems.lock rubocop/run.rb /tmp/rubocop/
RUN QUALOR_RUBOCOP_SRC=/tmp/rubocop sh /tmp/install-rubocop.sh && rm -rf /tmp/rubocop /tmp/install-rubocop.sh
COPY install-dotnet.sh /tmp/install-dotnet.sh
RUN sh /tmp/install-dotnet.sh && rm /tmp/install-dotnet.sh
ENV DOTNET_ROOT=/opt/qualor/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
RUN corepack enable && npm install -g bun@1.3.13
