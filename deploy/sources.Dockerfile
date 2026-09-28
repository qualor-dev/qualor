# The qualor/scanner-sources and qualor/server-sources images: the
# complete corresponding source of the copyleft components of qualor/scanner and qualor/server,
# each published to the same registry with the same tag as its image. Nothing runs in them; they
# only carry files. The build context is the directory `pnpm deploy:sources` fills and verifies
# (every file against the SHA-256 its manifest pins):
#   pnpm deploy:sources
#   docker build -f deploy/sources.Dockerfile -t qualor/scanner-sources:dev .tmp/scanner-sources
#   docker build -f deploy/sources.Dockerfile -t qualor/server-sources:dev .tmp/server-sources
# or all four images with one tag: pnpm deploy:release-images --tag <tag>.
# Get the files out: docker create --name s qualor/scanner-sources:<tag> none && docker cp s:/sources . && docker rm s
FROM scratch
COPY . /sources/
LABEL org.opencontainers.image.title="Qualor corresponding source" \
      org.opencontainers.image.description="Corresponding source of the copyleft components of a Qualor image (see /sources/README.md)"
