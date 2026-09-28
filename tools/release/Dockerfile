# The release tools: Helm, cosign and Syft from install-tools.sh.
# A local image only, never pushed:
#   docker build -t qualor-release-tools:local tools/release
# Pinned by version and digest (multi-arch index), the same base as tools/analyzers/Dockerfile.
FROM node:22.23.2-bookworm@sha256:dd5847a04b0deee391fa145f1f4c6d214196668b6bcc7988ebed67249f226844
COPY install-tools.sh /tmp/install-tools.sh
RUN sh /tmp/install-tools.sh && rm /tmp/install-tools.sh
# The container runs with a read-only root and a tmpfs /tmp: every tool keeps its state there.
# Syft never checks for a newer version (the container has no network anyway).
ENV PATH=/opt/qualor-release/bin:$PATH \
    HOME=/tmp \
    HELM_CACHE_HOME=/tmp/helm/cache \
    HELM_CONFIG_HOME=/tmp/helm/config \
    HELM_DATA_HOME=/tmp/helm/data \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    DOCKER_CONFIG=/tmp/.docker
USER node
WORKDIR /work
