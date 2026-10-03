#!/bin/sh
# Installs Qualor's own security rules (plan 6B-1, config.md §6): the qualor-rules pack, checked
# against QUALOR_RULES_SHA256 before it is unpacked into $QUALOR_TOOLS/rules/qualor (default
# /opt/qualor/rules/qualor), with its LICENSE and NOTICE also in $QUALOR_TOOLS/licenses/qualor-rules.
# The pack is source-available (PolyForm Shield 1.0.0), not MIT: it is never committed to this
# repository. The pins live in install.sh (QUALOR_INSTALL_SH, default: next to this script).
# Where the archive comes from, in order:
#   1. QUALOR_RULES_SRC/qualor-rules-<version>.tar.gz (default: the qualor-rules/ directory next to
#      this script; git-ignored, for builds before the pack is published);
#   2. QUALOR_RULES_URL, once install.sh sets it (a failed download fails the install).
# Neither: the pack is skipped with a message (the qualor engine then reports that its rules are
# not installed), unless QUALOR_RULES_REQUIRED=1, which fails instead. `pnpm deploy:release-images`
# sets it only once the pack is published, so a release is never blocked before then.
#   sh tools/analyzers/install-qualor-rules.sh
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="${QUALOR_INSTALL_SH:-$SELF_DIR/install.sh}"
SRC="${QUALOR_RULES_SRC:-$SELF_DIR/qualor-rules}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DEST="$PREFIX/rules/qualor"
REQUIRED="${QUALOR_RULES_REQUIRED:-0}"

eval "$(grep -E '^QUALOR_RULES_(VERSION|SHA256|URL)=' "$INSTALL_SH")"
NAME="qualor-rules-$QUALOR_RULES_VERSION.tar.gz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -f "$SRC/$NAME" ]; then
  FROM="$SRC/$NAME"
  cp "$FROM" "$TMP/pack.tar.gz"
elif [ -n "$QUALOR_RULES_URL" ]; then
  FROM="$QUALOR_RULES_URL"
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 7 --retry-connrefused -o "$TMP/pack.tar.gz" "$FROM"
else
  MESSAGE="install-qualor-rules.sh: the Qualor rules pack $QUALOR_RULES_VERSION is not published yet and $SRC/$NAME is not there"
  if [ "$REQUIRED" = 1 ]; then
    echo "$MESSAGE (QUALOR_RULES_REQUIRED=1)" >&2
    exit 1
  fi
  echo "$MESSAGE: skipped; the qualor engine will report that its rules are not installed"
  exit 0
fi
echo "$QUALOR_RULES_SHA256  $TMP/pack.tar.gz" | sha256sum -c - >/dev/null \
  || { echo "install-qualor-rules.sh: checksum mismatch: $FROM" >&2; exit 1; }

mkdir "$TMP/pack"
tar -xzf "$TMP/pack.tar.gz" -C "$TMP/pack" --no-same-owner --no-same-permissions
for f in manifest.json LICENSE NOTICE; do
  [ -f "$TMP/pack/$f" ] || { echo "install-qualor-rules.sh: $NAME has no $f" >&2; exit 1; }
done
[ -d "$TMP/pack/rules" ] || { echo "install-qualor-rules.sh: $NAME has no rules/" >&2; exit 1; }
grep -q "^  \"version\": \"$QUALOR_RULES_VERSION\",\$" "$TMP/pack/manifest.json" \
  || { echo "install-qualor-rules.sh: $NAME is not version $QUALOR_RULES_VERSION" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST" "$PREFIX/licenses/qualor-rules"
cp -R "$TMP/pack/." "$DEST/"
find "$DEST" -type d -exec chmod 0755 {} +
find "$DEST" -type f -exec chmod 0644 {} +
install -m 0644 "$DEST/LICENSE" "$DEST/NOTICE" "$PREFIX/licenses/qualor-rules/"
echo "installed the Qualor rules pack $QUALOR_RULES_VERSION (from $FROM) into $DEST"
