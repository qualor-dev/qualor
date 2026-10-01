#!/bin/sh
# Builds cppcheck (plan 9D, config.md §6.2) from its tag archive into $QUALOR_TOOLS (default
# /opt/qualor): $PREFIX/bin/cppcheck, and its library files (cfg/, platforms/) in
# $PREFIX/share/cppcheck, which is compiled in as FILESDIR. Nothing else: no addons (Python), no
# rules (PCRE), no HTML report script. The archive is checked against CPPCHECK_SHA256 before it is
# unpacked, and deploy/scanner/sources.json ships it as the corresponding source (GPL-3.0-or-later).
# There is no Linux release binary (fact F1). The same script runs in deploy/scanner/Dockerfile,
# tools/analyzers/Dockerfile and every CI job that sets QUALOR_REQUIRE_ANALYZERS=1
# (tools/ci.test.ts checks). It needs g++, GNU make and python3 (cppcheck's match compiler).
# CPPCHECK_VERSION must equal CPPCHECK_VERSION in packages/shared/src/rules/cfamily.ts; a bump
# re-checks deploy/scanner/licenses/CPPCHECK-LICENSE.txt and the sources.json entry.
#   sh tools/analyzers/install-cppcheck.sh
set -eu

CPPCHECK_VERSION=2.22.0
CPPCHECK_SHA256=d74945deb2d50393430e07596b766f8a779512c7f60dac2a30ea64e059ece57b

PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
FILESDIR="$PREFIX/share/cppcheck"
for tool in g++ make python3 sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install-cppcheck.sh: $tool is required" >&2; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/cppcheck.tar.gz" \
  "https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/$CPPCHECK_VERSION.tar.gz"
echo "$CPPCHECK_SHA256  $TMP/cppcheck.tar.gz" | sha256sum -c - >/dev/null \
  || { echo "checksum mismatch: cppcheck $CPPCHECK_VERSION" >&2; exit 1; }
mkdir "$TMP/src"
tar -xzf "$TMP/cppcheck.tar.gz" -C "$TMP/src" --strip-components=1

# Only the cppcheck target (not testrunner); `make install` would rebuild without MATCHCOMPILER.
JOBS="$(nproc 2>/dev/null || echo 2)"
make -C "$TMP/src" -j"$JOBS" MATCHCOMPILER=yes FILESDIR="$FILESDIR" CXXFLAGS="-O2 -DNDEBUG -w" cppcheck >/dev/null

mkdir -p "$PREFIX/bin"
rm -rf "$FILESDIR"
mkdir -p "$FILESDIR"
install -m 0755 "$TMP/src/cppcheck" "$PREFIX/bin/cppcheck"
strip "$PREFIX/bin/cppcheck" 2>/dev/null || true
cp -R "$TMP/src/cfg" "$TMP/src/platforms" "$FILESDIR/"
find "$FILESDIR" -type d -exec chmod 0755 {} +
find "$FILESDIR" -type f -exec chmod 0644 {} +

# Some .0 releases print `Cppcheck X.Y`: compare major.minor, as cppcheckVersionSupported does.
PRINTED="$("$PREFIX/bin/cppcheck" --version)"
case "$PRINTED" in
  "Cppcheck ${CPPCHECK_VERSION%.*}" | "Cppcheck ${CPPCHECK_VERSION%.*}."*) ;;
  *) echo "install-cppcheck.sh: the built cppcheck prints '$PRINTED', not $CPPCHECK_VERSION" >&2; exit 1 ;;
esac
echo "installed cppcheck $CPPCHECK_VERSION into $PREFIX/bin, its library files into $FILESDIR"
