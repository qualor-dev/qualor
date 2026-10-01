#!/bin/sh
# Installs clang-tidy (plan 9D) for Qualor's own tests only: the analyzers toolbox
# (tools/analyzers/Dockerfile) and the CI jobs that set QUALOR_REQUIRE_ANALYZERS=1. The
# qualor/scanner image never ships it (decision 2): users run the clang-tidy of the job that built
# their project. It is the static build of the PyPI wheel `clang-tidy` (ssciwr/clang-tidy-wheel,
# Apache-2.0; LLVM is Apache-2.0 WITH LLVM-exception), checked against its SHA-256 before it is
# unpacked, without pip: only clang_tidy/data/bin/clang-tidy and its builtin headers
# (clang_tidy/data/lib/clang/<major>/include) go to $QUALOR_TOOLS/lib/clang-tidy, with a link in
# $QUALOR_TOOLS/bin. CLANG_TIDY_VERSION must have a major >= CLANG_TIDY_MIN_MAJOR in
# packages/shared/src/rules/cfamily.ts. A bump changes all five pins together: the version, and
# each wheel's SHA-256 and full file URL from https://pypi.org/pypi/clang-tidy/<version>/json
# (tools/ci.test.ts checks that each URL names CLANG_TIDY_VERSION); the real-binary tests'
# expectations are this major's (cli/test/analyzers.ts pinnedClangTidyMajor).
#   sh tools/analyzers/install-clang-tidy.sh
set -eu

CLANG_TIDY_VERSION=22.1.8
CLANG_TIDY_SHA256_X64=1a3de07ba82d4403d8b692ae63a5520d4db5c606014c92c24bbcef9259057bf1
CLANG_TIDY_URL_X64=https://files.pythonhosted.org/packages/82/19/0f2668f8f5e2452b096a2b898f2b6bcecbceb6dd0c7f75d1755ce1f18d8b/clang_tidy-22.1.8-py2.py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
CLANG_TIDY_SHA256_ARM64=1eaddaa7415e8c5e39aeefbfd15174f1ab2a671c86f7ebb200eb523cf9465559
CLANG_TIDY_URL_ARM64=https://files.pythonhosted.org/packages/ac/b7/61ed8c319f2d9ddb9762a550a6fee434bdef7bdc46d5a4b50929f1c90ec0/clang_tidy-22.1.8-py2.py3-none-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl

PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
case "$(uname -m)" in
  x86_64 | amd64) CT_SHA=$CLANG_TIDY_SHA256_X64; CT_URL=$CLANG_TIDY_URL_X64 ;;
  aarch64 | arm64) CT_SHA=$CLANG_TIDY_SHA256_ARM64; CT_URL=$CLANG_TIDY_URL_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/clang-tidy.whl" "$CT_URL"
echo "$CT_SHA  $TMP/clang-tidy.whl" | sha256sum -c - >/dev/null \
  || { echo "checksum mismatch: clang-tidy $CLANG_TIDY_VERSION" >&2; exit 1; }
unzip -q "$TMP/clang-tidy.whl" 'clang_tidy/data/bin/clang-tidy' 'clang_tidy/data/lib/*' -d "$TMP/w"
DEST="$PREFIX/lib/clang-tidy"
rm -rf "$DEST"
mkdir -p "$DEST" "$PREFIX/bin"
cp -R "$TMP/w/clang_tidy/data/bin" "$TMP/w/clang_tidy/data/lib" "$DEST/"
chmod 0755 "$DEST/bin/clang-tidy"
ln -sf "$DEST/bin/clang-tidy" "$PREFIX/bin/clang-tidy"
"$PREFIX/bin/clang-tidy" --version | grep -q "LLVM version $CLANG_TIDY_VERSION" \
  || { echo "install-clang-tidy.sh: the installed clang-tidy does not report $CLANG_TIDY_VERSION" >&2; exit 1; }
echo "installed clang-tidy $CLANG_TIDY_VERSION into $DEST (linked from $PREFIX/bin) for Qualor's tests"
