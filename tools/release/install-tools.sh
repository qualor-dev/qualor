#!/bin/sh
# Installs the pinned release tools (plan 4A Task 2, release.md §9) into $QUALOR_RELEASE_TOOLS
# (default /opt/qualor-release): Helm, cosign and Syft, each checked against its SHA-256 before it
# is unpacked, over https only. The same pins build the local image qualor-release-tools:local
# (tools/release/Dockerfile) and the CI job containers that cannot run Docker (direct mode).
# Bump a version here only, with the SHA-256 of both architectures from the release's checksums
# file, then run tools/release/check-pins.sh (release.md §9). It checks, in a throwaway python
# container and never with the toolbox's own cosign: cosign_checksums.txt with sigstore-python and
# its .sigstore.json bundle, identity keyless@projectsigstore.iam.gserviceaccount.com (a Google
# service account, not a GitHub workflow), issuer https://accounts.google.com; Syft's
# syft_<v>_checksums.txt with its .sig and .pem, identity exactly
# https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main, issuer
# https://token.actions.githubusercontent.com; Helm's helm-v<v>-linux-<arch>.tar.gz.sha256sum with
# gpg and the GitHub release asset ….sha256sum.asc against the Helm KEYS file (key 208D D36E D5BB
# 3745 A167 43A4 C7C6 FBB5 B91C 1155); and each cosign and Syft pin against GitHub's asset digest.
# tools/release/toolbox.test.ts checks the pins.
set -eu

HELM_VERSION=4.3.0
HELM_SHA256_X64=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
HELM_SHA256_ARM64=31c5794dd55c66a51e6b7d2e2ac7a114ae8b1de41ff1d9ba51748ac973b06a08
COSIGN_VERSION=3.1.3
COSIGN_SHA256_X64=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
COSIGN_SHA256_ARM64=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a
SYFT_VERSION=1.52.0
SYFT_SHA256_X64=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d
SYFT_SHA256_ARM64=c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706

PREFIX="${QUALOR_RELEASE_TOOLS:-/opt/qualor-release}"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64; HELM_SHA=$HELM_SHA256_X64; COSIGN_SHA=$COSIGN_SHA256_X64; SYFT_SHA=$SYFT_SHA256_X64 ;;
  aarch64 | arm64) ARCH=arm64; HELM_SHA=$HELM_SHA256_ARM64; COSIGN_SHA=$COSIGN_SHA256_ARM64; SYFT_SHA=$SYFT_SHA256_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$PREFIX/bin"

fetch() { # url sha256 file
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/$3" "$1"
  echo "$2  $TMP/$3" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
}

fetch "https://get.helm.sh/helm-v$HELM_VERSION-linux-$ARCH.tar.gz" "$HELM_SHA" helm.tgz
tar -xzf "$TMP/helm.tgz" -C "$TMP" "linux-$ARCH/helm"
install -m 0755 "$TMP/linux-$ARCH/helm" "$PREFIX/bin/helm"

fetch "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-linux-$ARCH" "$COSIGN_SHA" cosign
install -m 0755 "$TMP/cosign" "$PREFIX/bin/cosign"

fetch "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION/syft_${SYFT_VERSION}_linux_$ARCH.tar.gz" "$SYFT_SHA" syft.tgz
tar -xzf "$TMP/syft.tgz" -C "$TMP" syft
install -m 0755 "$TMP/syft" "$PREFIX/bin/syft"

"$PREFIX/bin/helm" version --short
"$PREFIX/bin/cosign" version >/dev/null
"$PREFIX/bin/syft" version >/dev/null
