#!/bin/sh
# Installs Qualor's Go toolchain (plan 9C, config.md §6) into $QUALOR_TOOLS (default /opt/qualor):
# - the Go distribution GO_VERSION into $PREFIX/lib/go, trimmed of what analysis never reads (api/,
#   doc/, misc/, test/, lib/wasm/, every testdata/ and *_test.go of the standard library; pkg/ and
#   src/cmd stay: staticcheck needs the linker, and go builds some tools on demand), with go and
#   gofmt linked into $PREFIX/bin;
# - the staticcheck and gosec release binaries into $PREFIX/bin;
# - Qualor's Go runner (tools/analyzers/golang/run.mjs) into $PREFIX/go.
# Every download is checked against its SHA-256 before it is unpacked; nothing else is fetched.
# deploy/scanner/Dockerfile replaces staticcheck and gosec with builds of the same tags from source
# (see its gotools stage); CI and the analyzers toolbox run these release binaries. The versions
# must equal packages/shared/src/rules/golang.ts (tools/ci.test.ts checks); a bump regenerates
# packages/shared/rules/go-rules.json (tools/analyzers/go-rules.mjs) and
# deploy/scanner/licenses/GOSEC-THIRD-PARTY.txt (tools/analyzers/go-licences.mjs).
#   sh tools/analyzers/install-go.sh
# QUALOR_GO_SRC (default: the golang/ directory next to this script) names the runner's directory.
set -eu

GO_VERSION=1.27.1
GO_SHA256_X64=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
GO_SHA256_ARM64=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
STATICCHECK_VERSION=2026.2.1
STATICCHECK_SHA256_X64=91186205a78db3f2d40efb3c102749aef66f85c2204793de7488d163b655aa7c
STATICCHECK_SHA256_ARM64=594421f28ba620ea14b98377cb84a309cf73cc420ba0f52f30c7fa4d92fd2b0e
GOSEC_VERSION=2.29.0
GOSEC_SHA256_X64=6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095
GOSEC_SHA256_ARM64=c71244ec8d37488fd479d0d26990968fee03ece48b305d8224ac0c1ebd66e87c

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${QUALOR_GO_SRC:-$SELF_DIR/golang}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
GH=https://github.com
case "$(uname -m)" in
  x86_64 | amd64) GO_ARCH=amd64; GO_SHA=$GO_SHA256_X64; SC_SHA=$STATICCHECK_SHA256_X64; GS_SHA=$GOSEC_SHA256_X64 ;;
  aarch64 | arm64) GO_ARCH=arm64; GO_SHA=$GO_SHA256_ARM64; SC_SHA=$STATICCHECK_SHA256_ARM64; GS_SHA=$GOSEC_SHA256_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/go"

fetch() { # url sha256 file
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/$3" "$1"
  echo "$2  $TMP/$3" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
}

fetch "https://go.dev/dl/go$GO_VERSION.linux-$GO_ARCH.tar.gz" "$GO_SHA" go.tgz
rm -rf "$PREFIX/lib/go"
tar -xzf "$TMP/go.tgz" -C "$PREFIX/lib"
(
  cd "$PREFIX/lib/go"
  rm -rf api doc misc test lib/wasm
  find src -type d -name testdata -prune -exec rm -rf {} +
  find src -type f -name '*_test.go' -delete
)
ln -sf ../lib/go/bin/go "$PREFIX/bin/go"
ln -sf ../lib/go/bin/gofmt "$PREFIX/bin/gofmt"

fetch "$GH/dominikh/go-tools/releases/download/$STATICCHECK_VERSION/staticcheck_linux_$GO_ARCH.tar.gz" "$SC_SHA" staticcheck.tgz
tar -xzf "$TMP/staticcheck.tgz" -C "$TMP" staticcheck/staticcheck
install -m 0755 "$TMP/staticcheck/staticcheck" "$PREFIX/bin/staticcheck"

fetch "$GH/securego/gosec/releases/download/v$GOSEC_VERSION/gosec_${GOSEC_VERSION}_linux_$GO_ARCH.tar.gz" "$GS_SHA" gosec.tgz
tar -xzf "$TMP/gosec.tgz" -C "$TMP" gosec
install -m 0755 "$TMP/gosec" "$PREFIX/bin/gosec"

install -m 0644 "$SRC/run.mjs" "$PREFIX/go/run.mjs"
chmod -R a+rX "$PREFIX/lib/go" "$PREFIX/go"
GOTOOLCHAIN=local GOFLAGS= "$PREFIX/lib/go/bin/go" version >/dev/null

echo "installed Go $GO_VERSION into $PREFIX/lib/go, staticcheck $STATICCHECK_VERSION and gosec $GOSEC_VERSION into $PREFIX/bin, and Qualor's Go runner into $PREFIX/go"
