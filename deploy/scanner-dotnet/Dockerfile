# syntax=docker/dockerfile:1
# The qualor/scanner-dotnet image: qualor/scanner plus the .NET 8 and .NET 10
# SDKs and the bundled Roslynator analyzers of tools/analyzers/install-dotnet.sh, for C# projects
# (qualor dotnet begin, the project's own dotnet build, qualor dotnet end).
#   docker build -f deploy/scanner/Dockerfile -t qualor/scanner:dev .
#   docker build -f deploy/scanner-dotnet/Dockerfile --build-arg SCANNER_IMAGE=qualor/scanner:dev -t qualor/scanner-dotnet:dev .
# buildkit's FROM only expands ${VAR:-default}, not the shell's ${VAR:?message}, so an unset
# SCANNER_IMAGE resolves to this deliberately-invalid (uppercase) reference, which fails the build
# at once, before any instruction runs, with "repository name … must be lowercase".
ARG SCANNER_IMAGE
FROM ${SCANNER_IMAGE:-SET_SCANNER_IMAGE_TO_A_BUILT_QUALOR_SCANNER_IMAGE}
USER root
COPY tools/analyzers/install-dotnet.sh /tmp/install-dotnet.sh
RUN sh /tmp/install-dotnet.sh && rm /tmp/install-dotnet.sh \
  && find /opt/qualor/dotnet -type d -exec chmod 0755 {} +
# The .NET SDK and Roslynator licence files already reached /opt/qualor/licenses/ through the base
# qualor/scanner image's own `COPY deploy/scanner/licenses/` (it copies the whole directory, so the
# notices ship in both images; deploy/scanner/NOTICE.md says so). No extra COPY needed here.
ENV DOTNET_ROOT=/opt/qualor/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    QUALOR_DOTNET_ANALYZERS=/opt/qualor/dotnet/analyzers
USER node
