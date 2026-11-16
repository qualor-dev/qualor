#!/bin/sh
# Makes the fixture Trivy database of the server's real re-check tests (0.16 SBOM, ruling R12):
# server/test/fixtures/trivy-db-os/db.tar.gz. It downloads the trivy-db layer that install.sh pins
# (TRIVY_DB_DIGEST), checks its SHA-256, and cuts its trivy.db down to what the fixture's
# allowlist.json names with trivy-db-filter's -fixture mode (tools/analyzers/go-tools/trivy-db-filter).
# The archive holds db/metadata.json as the layer has it and db/trivy.db, as the server's dataset
# reader takes them. Its tar and gzip headers carry the snapshot's TRIVY_DB_CREATED and no owner,
# name or time of this run, so the same layer, allowlist and filter give the same bytes. It runs
# where filter-trivy-db.sh runs, with install-go.sh's Go: the analyzers toolbox
# (tools/analyzers/Dockerfile) or deploy/scanner/Dockerfile's gotools stage.
#   sh tools/analyzers/make-trivy-db-fixture.sh
# QUALOR_TRIVY_DB_FIXTURE (default: server/test/fixtures/trivy-db-os of this repository) names the
# directory of allowlist.json and the archive. QUALOR_TRIVY_DB_LAYER names a layer downloaded before,
# checked like a download. QUALOR_TRIVY_DB_FILTER and QUALOR_TRIVY_DB_FILTER_SRC work as in
# filter-trivy-db.sh.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$(cd "${QUALOR_TRIVY_DB_FIXTURE:-$SELF_DIR/../../server/test/fixtures/trivy-db-os}" && pwd)"
SRC="${QUALOR_TRIVY_DB_FILTER_SRC:-$SELF_DIR/go-tools/trivy-db-filter}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DIGEST="$(sed -n 's/^TRIVY_DB_DIGEST=//p' "$SELF_DIR/install.sh")"
CREATED="$(sed -n 's/^TRIVY_DB_CREATED=//p' "$SELF_DIR/install.sh")"
[ -n "$DIGEST" ] && [ -n "$CREATED" ] || { echo "install.sh has no TRIVY_DB_DIGEST or TRIVY_DB_CREATED" >&2; exit 1; }
[ -f "$FIXTURE/allowlist.json" ] || { echo "no allowlist at $FIXTURE/allowlist.json" >&2; exit 1; }
FILTER="${QUALOR_TRIVY_DB_FILTER:-}"
GO="$PREFIX/lib/go/bin/go"
[ -n "$FILTER" ] || [ -x "$GO" ] || { echo "no Go at $GO: run install-go.sh first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LAYER="${QUALOR_TRIVY_DB_LAYER:-}"
if [ -z "$LAYER" ]; then
  # An anonymous pull token, then the layer by its digest, as install.sh downloads it.
  TOKEN="$(curl -fsSL --proto '=https' --tlsv1.2 --retry 7 --retry-connrefused \
    'https://ghcr.io/token?scope=repository:aquasecurity/trivy-db:pull' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$TOKEN" ] || { echo "no ghcr.io pull token for aquasecurity/trivy-db" >&2; exit 1; }
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 7 --retry-connrefused -H "Authorization: Bearer $TOKEN" \
    -o "$TMP/layer.tar.gz" "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/$DIGEST" \
    || { echo "the pinned Trivy database $DIGEST is gone from ghcr.io" >&2; exit 1; }
  LAYER="$TMP/layer.tar.gz"
fi
echo "${DIGEST#sha256:}  $LAYER" | sha256sum -c - >/dev/null 2>&1 || { echo "checksum mismatch: trivy-db $DIGEST ($LAYER)" >&2; exit 1; }
mkdir "$TMP/db"
tar -xzf "$LAYER" --no-same-owner -C "$TMP/db" trivy.db metadata.json

if [ -z "$FILTER" ]; then
  # The module and build caches live in $TMP too, so nothing of the build stays behind.
  (cd "$SRC" && CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -mod=readonly" \
    GOCACHE="$TMP/cache" GOMODCACHE="$TMP/mod" "$GO" build -modcacherw -o "$TMP/trivy-db-filter" .)
  FILTER="$TMP/trivy-db-filter"
fi
"$FILTER" -fixture "$FIXTURE/allowlist.json" "$TMP/db/trivy.db"
chmod 0644 "$TMP/db/trivy.db" "$TMP/db/metadata.json"

tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime="$CREATED" \
  -C "$TMP" -cf "$TMP/db.tar" db/metadata.json db/trivy.db
gzip -9n < "$TMP/db.tar" > "$TMP/db.tar.gz"
cp "$TMP/db.tar.gz" "$FIXTURE/db.tar.gz"
echo "wrote $FIXTURE/db.tar.gz ($(wc -c < "$FIXTURE/db.tar.gz") bytes) from trivy-db $DIGEST of $CREATED"
