#!/bin/sh
# Installs Qualor's sonarjs pass (plan 8A/8B, config.md §6) into $QUALOR_TOOLS/sonarjs (default
# /opt/qualor/sonarjs): eslint-plugin-sonarjs on Qualor's own ESLint 9, installed from
# tools/analyzers/sonarjs's lockfile without install scripts, and categories.json built from the
# RSPEC metadata of the SonarJS source archive at the plugin's commit, checked against its SHA-256
# before it is unpacked; only the rule metadata is unpacked (never committed, .gitignore), and the
# archive is deleted afterwards. The pins (SONARJS_VERSION, SONARJS_COMMIT, SONARJS_SOURCE_SHA256)
# live in tools/analyzers/install.sh, which this script does not duplicate (tools/ci.test.ts checks
# them there); it reads them with the same `grep`+`eval` this recipe has always used.
#   sh tools/analyzers/install-sonarjs.sh
# QUALOR_SONARJS_SRC (default: the sonarjs/ directory next to this script) names the directory that
# holds sonarjs/package.json, package-lock.json, run.mjs and categories.mjs — the only four files
# installed; the image and CI never carry run.test.ts or the dev-only *.mjs scripts (keys.mjs,
# licences.mjs, decorated-pairs.mjs) this script leaves untouched in the checkout.
# QUALOR_INSTALL_SH (default: install.sh next to this script) names the file the SONARJS_* pins are
# read from.
# node and npm (>= 10) must already be on PATH: the ambient npm installs the committed lockfile
# (the pinned node base images ship npm 10, which reads it cleanly). Nothing else is fetched to run
# npm itself. Regenerating the lockfile needs npm >= 11, for the package.json `minimatch@10.0.1`
# override (a lockfile npm 10 writes fails its own `npm ci` on it); that is a maintainer step on a
# workstation, never part of this script.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="${QUALOR_INSTALL_SH:-$SELF_DIR/install.sh}"
SRC="${QUALOR_SONARJS_SRC:-$SELF_DIR/sonarjs}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DEST="$PREFIX/sonarjs"

eval "$(grep -E '^SONARJS_[A-Z0-9_]+=' "$INSTALL_SH")"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SRC/package.json" "$SRC/package-lock.json" "$SRC/run.mjs" "$SRC/categories.mjs" "$DEST/"
chmod 0644 "$DEST/package.json" "$DEST/package-lock.json" "$DEST/run.mjs" "$DEST/categories.mjs"

npm_major="$(npm --version 2>/dev/null | cut -d. -f1)"
[ "${npm_major:-0}" -ge 10 ] 2>/dev/null || {
  echo "install-sonarjs.sh: npm >= 10 is required, found $(npm --version 2>/dev/null || echo 'none')" >&2
  exit 1
}
(cd "$DEST" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --cache "$TMP/npm-cache")

installed="$(node -p 'require("'"$DEST"'/node_modules/eslint-plugin-sonarjs/package.json").version')"
[ "$installed" = "$SONARJS_VERSION" ] || {
  echo "install-sonarjs.sh: eslint-plugin-sonarjs installed as $installed, expected $SONARJS_VERSION" >&2
  exit 1
}

curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 7 --retry-connrefused -o "$TMP/sonarjs.tar.gz" \
  "https://github.com/SonarSource/SonarJS/archive/${SONARJS_COMMIT}.tar.gz"
echo "${SONARJS_SOURCE_SHA256}  $TMP/sonarjs.tar.gz" | sha256sum -c - >/dev/null \
  || { echo "install-sonarjs.sh: checksum mismatch: SonarJS ${SONARJS_COMMIT}" >&2; exit 1; }
mkdir "$TMP/rules"
tar -xzf "$TMP/sonarjs.tar.gz" -C "$TMP/rules" --no-same-owner --strip-components=12 --wildcards \
  '*/sonar-plugin/javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript/S*.json'
node "$DEST/categories.mjs" "$TMP/rules"
rm -rf "$TMP/sonarjs.tar.gz" "$TMP/rules"

chmod -R a+rX "$DEST"
echo "installed eslint-plugin-sonarjs $SONARJS_VERSION and its categories.json into $DEST"
