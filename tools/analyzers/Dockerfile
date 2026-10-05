# A local Linux environment with the analyzer toolchain CI installs (plan 1D Task 2): Node 22,
# JDK 17 (PMD, SpotBugs, javac), PMD, SpotBugs with FindSecBugs, OpenGrep, Gitleaks, Trivy with its database,
# Ruff, detekt, SwiftLint (its static build) and PHPStan (run by Debian's PHP 8.2 CLI, plan 9A)
# from install.sh, and bun. Also the .NET 8 and
# 10 SDKs and Roslynator from install-dotnet.sh (plan 2D), Qualor's sonarjs pass in
# /opt/qualor/sonarjs (plan 8A/8B) and Qualor's HTML and CSS linters in /opt/qualor/weblint
# (stylelint and HTMLHint, plan 8D), and Qualor's Ruby pass in /opt/qualor/rubocop (plan 9B).
# Also Go 1.27.1, staticcheck and gosec, and Qualor's Go runner from install-go.sh (plan 9C).
# And cppcheck built from source by install-cppcheck.sh (plan 9D), and clang-tidy 22.1.8 (tests
# only; never in qualor/scanner) from install-clang-tidy.sh (plan 9D), and Qualor's security rules
# pack (plan 6B-1).
#   docker build -t qualor-analyzers tools/analyzers
# Pinned by version and digest (multi-arch index); bump both together.
FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7
RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-17-jdk-headless unzip php8.2-cli \
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
COPY install-go.sh /tmp/
COPY --chmod=0644 golang/run.mjs /tmp/golang/
RUN QUALOR_GO_SRC=/tmp/golang sh /tmp/install-go.sh && rm -rf /tmp/golang /tmp/install-go.sh
# cppcheck, built from its pinned tag archive as deploy/scanner/Dockerfile and CI build it
# (plan 9D; tools/analyzers/install-cppcheck.sh, tools/ci.test.ts).
COPY install-cppcheck.sh /tmp/
RUN sh /tmp/install-cppcheck.sh && rm /tmp/install-cppcheck.sh
# clang-tidy 22.1.8 (tests only; never in qualor/scanner): the pinned PyPI wheel's static build
# (plan 9D, decision 2; tools/analyzers/install-clang-tidy.sh, tools/ci.test.ts).
COPY install-clang-tidy.sh /tmp/
RUN sh /tmp/install-clang-tidy.sh && rm /tmp/install-clang-tidy.sh
# Qualor's own security rules into /opt/qualor/rules/qualor, as deploy/scanner/Dockerfile and CI
# install them (plan 6B-1; tools/analyzers/install-qualor-rules.sh, tools/ci.test.ts): from
# tools/analyzers/qualor-rules/ when it holds the pinned tarball, otherwise downloaded.
COPY install.sh install-qualor-rules.sh /tmp/
COPY qualor-rules/ /tmp/qualor-rules/
RUN sh /tmp/install-qualor-rules.sh && rm -rf /tmp/qualor-rules /tmp/install-qualor-rules.sh /tmp/install.sh
COPY install-dotnet.sh /tmp/install-dotnet.sh
RUN sh /tmp/install-dotnet.sh && rm /tmp/install-dotnet.sh
ENV DOTNET_ROOT=/opt/qualor/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
RUN corepack enable && npm install -g bun@1.3.13
