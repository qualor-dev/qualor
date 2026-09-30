#!/bin/sh
# Installs Qualor's HTML and CSS linters (plan 8D, config.md §6) into $QUALOR_TOOLS/weblint
# (default /opt/qualor/weblint): stylelint with the configs Qualor bundles, and HTMLHint, from
# tools/analyzers/weblint's lockfile (npm ci checks every package against its sha512 before
# unpacking it) without install scripts, and the runner scripts next to them. Nothing else is
# downloaded. The same script runs in deploy/scanner/Dockerfile, tools/analyzers/Dockerfile and
# every CI job that sets QUALOR_REQUIRE_ANALYZERS=1 (tools/ci.test.ts checks).
#   sh tools/analyzers/install-weblint.sh
# QUALOR_WEBLINT_SRC (default: the weblint/ directory next to this script) names the directory
# holding the runtime files; only those are installed, never the pass's own tests or dev-only scripts.
# node and npm (>= 10) must already be on PATH.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${QUALOR_WEBLINT_SRC:-$SELF_DIR/weblint}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DEST="$PREFIX/weblint"
FILES="package.json package-lock.json bundled.mjs files.mjs stylelint.mjs htmlhint.mjs"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rm -rf "$DEST"
mkdir -p "$DEST"
for f in $FILES; do
  cp "$SRC/$f" "$DEST/$f"
  chmod 0644 "$DEST/$f"
done

npm_major="$(npm --version 2>/dev/null | cut -d. -f1)"
[ "${npm_major:-0}" -ge 10 ] 2>/dev/null || {
  echo "install-weblint.sh: npm >= 10 is required, found $(npm --version 2>/dev/null || echo 'none')" >&2
  exit 1
}
(cd "$DEST" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --cache "$TMP/npm-cache")

# Every direct dependency is installed at exactly the version package.json pins.
node --input-type=module -e '
import { readFileSync } from "node:fs";
const dest = process.argv[1];
const pkg = JSON.parse(readFileSync(`${dest}/package.json`, "utf8"));
for (const [name, want] of Object.entries(pkg.dependencies)) {
  const got = JSON.parse(readFileSync(`${dest}/node_modules/${name}/package.json`, "utf8")).version;
  if (got !== want) {
    console.error(`install-weblint.sh: ${name} installed as ${got}, expected ${want}`);
    process.exit(1);
  }
}' "$DEST"

chmod -R a+rX "$DEST"
echo "installed stylelint and HTMLHint (tools/analyzers/weblint/package.json) into $DEST"
