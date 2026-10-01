#!/bin/sh
# Records cppcheck's xmlv2 output of fixtures/c-basic (plan 9D) for cppcheck-xml.test.ts
# (cli/test/analyzer-output/cppcheck/basic.xml), with the cppcheck engine's default groups and
# output format. Run it from the repository root in the analyzers toolbox (tools/analyzers/
# Dockerfile), whose cppcheck is the pinned one (install-cppcheck.sh). The fixture is copied first,
# so the checkout is only read.
#   sh tools/analyzers/record-cppcheck-xml.sh /absolute/path/basic.xml
set -eu

OUT="${1:-}"
case "$OUT" in
  /*) ;;
  *) echo "usage: sh tools/analyzers/record-cppcheck-xml.sh <absolute output path>" >&2; exit 2 ;;
esac
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp -R fixtures/c-basic/src "$TMP/src"
cd "$TMP"
find src -type f \( -name '*.c' -o -name '*.h' \) | LC_ALL=C sort > files.txt
cppcheck --version
cppcheck -q --enable=warning,performance,portability --inline-suppr --output-format=xmlv2 \
  --output-file="$OUT" --relative-paths="$TMP" --file-list=files.txt
