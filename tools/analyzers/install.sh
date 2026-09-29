#!/bin/sh
# Installs the pinned analyzer toolchain (plan 1D, Task 2) into $QUALOR_TOOLS (default
# /opt/qualor): PMD, SpotBugs, OpenGrep, Gitleaks and Trivy, each checked against its SHA-256
# before it is unpacked, and Trivy's vulnerability database (plan 2B), a snapshot pinned by the
# digest of its OCI layer, into $QUALOR_TOOLS/share/trivy/db. Java (>= 17) must already be on
# PATH for PMD and SpotBugs. The same versions are what the qualor/scanner image ships; bump them
# here only (tools/ci.test.ts checks the pins). `pnpm trivy-db:pin` moves the database pin to
# the newest snapshot (upstream builds one every 6 hours; how long it keeps an old one is not
# documented). QUALOR_DOWNLOAD_CACHE (optional, CI) names a directory that keeps Trivy's
# release archive and database layer between runs, each named by its SHA-256 and checked on every
# use like a download; it holds only the current pins, so a CI cache of it keeps the pinned
# database installable for as long as the cache lives, whatever upstream deletes.
set -eu

PMD_VERSION=7.27.0
PMD_SHA256=4ae396ffaf2b0d3ef0b73a10b2925e77066f73d57a4ce9078c60e7302bcddec9
SPOTBUGS_VERSION=4.10.4
SPOTBUGS_SHA256=72bc0d4edd686e462c0f71f42a049b27bf4da6708797ff7b2b56dd202714b4e5
OPENGREP_VERSION=1.30.0
OPENGREP_SHA256_X64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
OPENGREP_SHA256_ARM64=a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256_X64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
# Trivy's checksums file was checked with cosign against the release workflow's identity
# (https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.74.0).
TRIVY_VERSION=0.74.0
TRIVY_SHA256_X64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
# ghcr.io/aquasecurity/trivy-db:2, the db.tar.gz layer (schema 2) of the snapshot built at
# TRIVY_DB_CREATED; architecture-independent.
TRIVY_DB_DIGEST=sha256:7d0ae3ee84ece1ecae274d9ac146c7241ae483c981f68aeb3f4953f6c2fbc6b0
TRIVY_DB_CREATED=2026-09-25T06:43:29Z
# Qualor's sonarjs pass (tools/analyzers/sonarjs, plan 8A/8B), which this script does not install:
# the qualor/scanner and tools/analyzers Dockerfiles run `npm ci` from its package-lock.json and
# read these pins. SONARJS_VERSION must equal that package.json's eslint-plugin-sonarjs (the last
# LGPL-3.0 release; never a later one). SONARJS_COMMIT is that release's npm gitHead in
# SonarSource/SonarJS; its source archive, checked against SONARJS_SOURCE_SHA256, holds the RSPEC
# metadata that categories.mjs turns into categories.json at image build.
# Regenerate tools/analyzers/sonarjs/package-lock.json with npm >= 11 only: a lockfile written by
# npm 10 fails its own `npm ci` with package.json's minimatch override.
SONARJS_VERSION=2.0.4
SONARJS_COMMIT=273825f98b35b29b409fbf4f89efce075c651d96
SONARJS_SOURCE_SHA256=17af65bcc0c8b631da9f135afb0a9ef1da82eb31049e9ce7d90dc40e04e83dc1

PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
GH=https://github.com
case "$(uname -m)" in
  x86_64 | amd64) OG_ARCH=x86; OG_SHA=$OPENGREP_SHA256_X64; GL_ARCH=x64; GL_SHA=$GITLEAKS_SHA256_X64; TV_ARCH=64bit; TV_SHA=$TRIVY_SHA256_X64 ;;
  aarch64 | arm64) OG_ARCH=aarch64; OG_SHA=$OPENGREP_SHA256_ARM64; GL_ARCH=arm64; GL_SHA=$GITLEAKS_SHA256_ARM64; TV_ARCH=ARM64; TV_SHA=$TRIVY_SHA256_ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$PREFIX/bin" "$PREFIX/lib"

fetch() { # url sha256 file
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/$3" "$1"
  echo "$2  $TMP/$3" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
}

CACHE="${QUALOR_DOWNLOAD_CACHE:-}"
from_cache() { # sha256 file: the cached copy into $TMP, when there is one with that checksum
  [ -n "$CACHE" ] && [ -f "$CACHE/$1" ] || return 1
  cp "$CACHE/$1" "$TMP/$2"
  if echo "$1  $TMP/$2" | sha256sum -c - >/dev/null 2>&1; then echo "cached: $2"; return 0; fi
  rm -f "$TMP/$2" "$CACHE/$1"
  return 1
}
to_cache() { # sha256 file: a checked download into the cache
  [ -n "$CACHE" ] || return 0
  mkdir -p "$CACHE"
  cp "$TMP/$2" "$CACHE/$1.part" && mv "$CACHE/$1.part" "$CACHE/$1"
}

fetch "$GH/pmd/pmd/releases/download/pmd_releases/$PMD_VERSION/pmd-dist-$PMD_VERSION-bin.zip" "$PMD_SHA256" pmd.zip
rm -rf "$PREFIX/lib/pmd-bin-$PMD_VERSION"
unzip -q "$TMP/pmd.zip" -d "$PREFIX/lib"
ln -sf "$PREFIX/lib/pmd-bin-$PMD_VERSION/bin/pmd" "$PREFIX/bin/pmd"

fetch "$GH/spotbugs/spotbugs/releases/download/$SPOTBUGS_VERSION/spotbugs-$SPOTBUGS_VERSION.tgz" "$SPOTBUGS_SHA256" spotbugs.tgz
rm -rf "$PREFIX/lib/spotbugs-$SPOTBUGS_VERSION"
tar -xzf "$TMP/spotbugs.tgz" -C "$PREFIX/lib"
chmod +x "$PREFIX/lib/spotbugs-$SPOTBUGS_VERSION/bin/spotbugs"
ln -sf "$PREFIX/lib/spotbugs-$SPOTBUGS_VERSION/bin/spotbugs" "$PREFIX/bin/spotbugs"

fetch "$GH/opengrep/opengrep/releases/download/v$OPENGREP_VERSION/opengrep_manylinux_$OG_ARCH" "$OG_SHA" opengrep
install -m 0755 "$TMP/opengrep" "$PREFIX/bin/opengrep"

fetch "$GH/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_$GL_ARCH.tar.gz" "$GL_SHA" gitleaks.tgz
tar -xzf "$TMP/gitleaks.tgz" -C "$TMP" gitleaks
install -m 0755 "$TMP/gitleaks" "$PREFIX/bin/gitleaks"

from_cache "$TV_SHA" trivy.tgz || {
  fetch "$GH/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_Linux-$TV_ARCH.tar.gz" "$TV_SHA" trivy.tgz
  to_cache "$TV_SHA" trivy.tgz
}
tar -xzf "$TMP/trivy.tgz" -C "$TMP" trivy
install -m 0755 "$TMP/trivy" "$PREFIX/bin/trivy"

# The database is an OCI artifact: an anonymous pull token, then the layer by its digest (the
# registry redirects to its blob storage, https only), checked like every download.
if ! from_cache "${TRIVY_DB_DIGEST#sha256:}" trivy-db.tar.gz; then
  TOKEN="$(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
    'https://ghcr.io/token?scope=repository:aquasecurity/trivy-db:pull' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$TOKEN" ] || { echo "no ghcr.io pull token for aquasecurity/trivy-db" >&2; exit 1; }
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -H "Authorization: Bearer $TOKEN" \
    -o "$TMP/trivy-db.tar.gz" "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/$TRIVY_DB_DIGEST" \
    || { echo "the pinned Trivy database $TRIVY_DB_DIGEST is gone from ghcr.io: run pnpm trivy-db:pin" >&2; exit 1; }
fi
echo "${TRIVY_DB_DIGEST#sha256:}  $TMP/trivy-db.tar.gz" | sha256sum -c - >/dev/null || { echo "checksum mismatch: trivy-db $TRIVY_DB_DIGEST" >&2; exit 1; }
to_cache "${TRIVY_DB_DIGEST#sha256:}" trivy-db.tar.gz
rm -rf "$PREFIX/share/trivy"
mkdir -p "$PREFIX/share/trivy/db"
tar -xzf "$TMP/trivy-db.tar.gz" --no-same-owner -C "$PREFIX/share/trivy/db" trivy.db metadata.json
chmod 0644 "$PREFIX/share/trivy/db/trivy.db" "$PREFIX/share/trivy/db/metadata.json"
# Only the current pins stay in the cache.
[ -z "$CACHE" ] || find "$CACHE" -maxdepth 1 -type f ! -name "$TV_SHA" ! -name "${TRIVY_DB_DIGEST#sha256:}" -delete

echo "installed PMD $PMD_VERSION, SpotBugs $SPOTBUGS_VERSION, OpenGrep $OPENGREP_VERSION, Gitleaks $GITLEAKS_VERSION, Trivy $TRIVY_VERSION into $PREFIX/bin, and the Trivy database of $TRIVY_DB_CREATED into $PREFIX/share/trivy"
