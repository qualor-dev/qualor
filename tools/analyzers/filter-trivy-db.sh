#!/bin/sh
# Filters the Trivy vulnerability database that tools/analyzers/install.sh unpacked into
# $QUALOR_TOOLS/share/trivy/db (default /opt/qualor) down to its library sources (0.16 debts D31-1,
# rulings B2-a and B2-b): the operating-system and vendor sources go, with the vulnerability
# details only they reference (tools/analyzers/go-tools/trivy-db-filter; deploy/scanner/NOTICE.md
# lists what stays). Then it checks the result. metadata.json stays as extracted. It runs after
# install-go.sh wherever install.sh installs the database: the scanner images, the analyzers
# toolbox and CI. QUALOR_TRIVY_DB_FILTER names a built filter (deploy/scanner/Dockerfile's gotools
# stage); without it, the script builds the module with install-go.sh's Go from its hash-pinned
# go.sum and deletes the binary afterwards. A missing database, a missing Go or a failed check
# fails the script: the database is never left unfiltered.
#   sh tools/analyzers/filter-trivy-db.sh
# QUALOR_TRIVY_DB_FILTER_SRC (default: go-tools/trivy-db-filter next to this script) names the module.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${QUALOR_TRIVY_DB_FILTER_SRC:-$SELF_DIR/go-tools/trivy-db-filter}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DB="$PREFIX/share/trivy/db/trivy.db"
[ -f "$DB" ] || { echo "no Trivy database at $DB: run install.sh first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FILTER="${QUALOR_TRIVY_DB_FILTER:-}"
if [ -z "$FILTER" ]; then
  GO="$PREFIX/lib/go/bin/go"
  [ -x "$GO" ] || { echo "no Go at $GO: run install-go.sh first" >&2; exit 1; }
  # The module and build caches live in $TMP too, so nothing of the build stays behind.
  (cd "$SRC" && CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -mod=readonly" \
    GOCACHE="$TMP/cache" GOMODCACHE="$TMP/mod" "$GO" build -modcacherw -o "$TMP/trivy-db-filter" .)
  FILTER="$TMP/trivy-db-filter"
fi
"$FILTER" "$DB"
"$FILTER" -check "$DB"
chmod 0644 "$DB"
