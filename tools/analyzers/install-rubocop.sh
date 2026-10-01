#!/bin/sh
# Installs Qualor's RuboCop pass (plan 9B, config.md §6) into $QUALOR_TOOLS/rubocop (default
# /opt/qualor/rubocop):
#   ruby/      Ruby RUBY_VERSION, built here from its release source (checked against RUBY_SHA256
#              before it is unpacked); of Ruby's bundled gems only racc stays, and Ruby's default
#              json (2.18.0, CVE-2026-33210) is replaced by gems.lock's;
#   gems/      RuboCop and the gems it runs on, each .gem checked against its SHA-256 in
#              rubocop/gems.lock and installed with `gem install --local --ignore-dependencies`;
#   run.rb     Qualor's runner, and VERSION, its `--version` line;
#   licenses/  Ruby's COPYING, BSDL and LEGAL from the same source, and in gems/ the licence
#              files of its MIT default gems (rubocop/licence-gems.lock).
# The same script runs in deploy/scanner/Dockerfile, tools/analyzers/Dockerfile and every CI job
# that sets QUALOR_REQUIRE_ANALYZERS=1 (tools/ci.test.ts checks). It needs a C compiler, make,
# curl and the libyaml and zlib headers (Debian: build-essential curl libyaml-dev zlib1g-dev; all
# present in node:22-bookworm). QUALOR_RUBOCOP_SRC (default: the rubocop/ directory next to this
# script) holds gems.lock, licence-gems.lock and run.rb.
#   sh tools/analyzers/install-rubocop.sh
set -eu

RUBY_VERSION=4.0.7
RUBY_SHA256=911ace20f90d068ca0e4dda6d0e4f0f81e52e52f2dd4f4004c721e253412e82d
# Must equal RUBOCOP_VERSION in packages/shared/src/rules/rubocop.ts and gems.lock's rubocop line
# (tools/ci.test.ts checks both); a bump regenerates packages/shared/rules/rubocop-*.json
# (tools/analyzers/rubocop-cops.ts) and deploy/scanner/licenses/RUBOCOP-DEPENDENCIES.txt
# (tools/analyzers/rubocop/licences.mjs).
RUBOCOP_VERSION=1.91.0

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${QUALOR_RUBOCOP_SRC:-$SELF_DIR/rubocop}"
PREFIX="${QUALOR_TOOLS:-/opt/qualor}"
DEST="$PREFIX/rubocop"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

die() {
  echo "install-rubocop.sh: $*" >&2
  exit 1
}

# fetch <url> <sha256> <file in $TMP>
fetch() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$TMP/$3" "$1"
  echo "$2  $TMP/$3" | sha256sum -c - >/dev/null 2>&1 || die "SHA-256 mismatch for $1"
}

for tool in cc make curl sha256sum nproc; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required (Debian: build-essential curl)"
done
printf '#include <yaml.h>\n#include <zlib.h>\n' | cc -E -x c - >/dev/null 2>&1 ||
  die 'the libyaml and zlib headers are required (Debian: libyaml-dev zlib1g-dev)'

rm -rf "$DEST"
mkdir -p "$DEST/licenses/gems"

# Ruby, from its release source.
fetch "https://cache.ruby-lang.org/pub/ruby/${RUBY_VERSION%.*}/ruby-$RUBY_VERSION.tar.gz" "$RUBY_SHA256" ruby.tar.gz
mkdir "$TMP/ruby"
tar -xzf "$TMP/ruby.tar.gz" -C "$TMP/ruby" --strip-components=1
(
  cd "$TMP/ruby"
  # libruby-static.a stays installed until the gems below are built (mkmf links its test programs
  # with -lruby-static); it goes with the headers further down.
  ./configure --prefix="$DEST/ruby" --enable-load-relative --disable-install-doc >"$TMP/configure.log" 2>&1 || {
    tail -n 40 "$TMP/configure.log" >&2
    exit 1
  }
  make -j"$(nproc)" >"$TMP/make.log" 2>&1 || {
    tail -n 40 "$TMP/make.log" >&2
    exit 1
  }
  make install >"$TMP/install.log" 2>&1 || {
    tail -n 40 "$TMP/install.log" >&2
    exit 1
  }
)
cp "$TMP/ruby/COPYING" "$TMP/ruby/BSDL" "$TMP/ruby/LEGAL" "$DEST/licenses/"
RUBY="$DEST/ruby/bin/ruby"
GEM="$DEST/ruby/bin/gem"
"$RUBY" -e 'require "psych"; require "zlib"; require "prism"' ||
  die "Ruby $RUBY_VERSION was built without psych, zlib or prism"

# RuboCop and its gems, each checked against gems.lock before it is installed.
while read -r name version sha; do
  case "$name" in '' | '#'*) continue ;; esac
  fetch "https://rubygems.org/downloads/$name-$version.gem" "$sha" "$name-$version.gem"
done <"$SRC/gems.lock"
"$RUBY" "$GEM" install --local --ignore-dependencies --no-document --install-dir "$DEST/gems" "$TMP"/*.gem >/dev/null

# Of Ruby's bundled gems RuboCop needs racc only (parser's runtime). Ruby's default json goes too:
# gems.lock's json replaces it.
DEFAULT_DIR="$("$RUBY" -e 'print Gem.default_dir')"
for spec in "$DEFAULT_DIR"/specifications/*.gemspec; do
  [ -e "$spec" ] || continue
  full="$(basename "$spec" .gemspec)"
  gem_name="${full%-*}"
  [ "$gem_name" = racc ] && continue
  "$RUBY" "$GEM" uninstall --install-dir "$DEFAULT_DIR" --all --executables --ignore-dependencies --force "$gem_name" >/dev/null
done
rm -f "$DEFAULT_DIR"/specifications/default/json-*.gemspec
LIB_DIR="$("$RUBY" -e 'print RbConfig::CONFIG["rubylibdir"]')"
ARCH_DIR="$("$RUBY" -e 'print RbConfig::CONFIG["archdir"]')"
rm -rf "$LIB_DIR/json" "$LIB_DIR/json.rb" "$ARCH_DIR/json"

# The licence files of Ruby's MIT default gems, which the built Ruby does not keep: from each
# release .gem of rubocop/licence-gems.lock (checked against its SHA-256, at the version this Ruby
# ships), into licenses/gems/<name>-<version>/. Nothing else of those .gem files is installed.
mkdir -p "$TMP/licence"
while read -r name version sha; do
  case "$name" in '' | '#'*) continue ;; esac
  [ -e "$DEFAULT_DIR/specifications/default/$name-$version.gemspec" ] ||
    die "licence-gems.lock names $name $version, not a default gem of Ruby $RUBY_VERSION"
  fetch "https://rubygems.org/downloads/$name-$version.gem" "$sha" "licence/$name-$version.gem"
  mkdir "$TMP/licence/$name-$version" "$DEST/licenses/gems/$name-$version"
  tar -xOf "$TMP/licence/$name-$version.gem" data.tar.gz | tar -xzf - -C "$TMP/licence/$name-$version"
  found=0
  for file in "$TMP/licence/$name-$version"/*; do
    base="$(basename "$file")"
    if [ -f "$file" ] && printf '%s\n' "$base" | grep -Eiq '^(licen[cs]e|copying|bsdl|legal|mit-licen[cs]e)'; then
      cp "$file" "$DEST/licenses/gems/$name-$version/$base"
      found=1
    fi
  done
  [ "$found" = 1 ] || die "$name-$version.gem has no licence file"
done <"$SRC/licence-gems.lock"

# Nothing a scan needs: headers, the static libruby, pkg-config files, gem caches, extension
# sources, debug symbols.
rm -rf "$DEST/ruby/include" "$DEST/ruby/lib/libruby-static.a" "$DEST/ruby/lib/pkgconfig" "$DEFAULT_DIR/cache" "$DEST/gems/cache" "$DEST/gems/doc"
find "$DEST/gems/gems" -mindepth 2 -maxdepth 2 -name ext -type d -exec rm -rf {} +
if command -v strip >/dev/null 2>&1; then
  strip "$RUBY"
  find "$DEST" -name '*.so' -exec strip --strip-unneeded {} +
fi

install -m 0644 "$SRC/run.rb" "$DEST/run.rb"
"$RUBY" "$DEST/run.rb" --version >"$DEST/VERSION"
[ "$(cat "$DEST/VERSION")" = "rubocop $RUBOCOP_VERSION ruby $RUBY_VERSION" ] ||
  die "run.rb reports '$(cat "$DEST/VERSION")', expected 'rubocop $RUBOCOP_VERSION ruby $RUBY_VERSION'"
chmod -R a+rX "$DEST"
echo "installed Ruby $RUBY_VERSION and RuboCop $RUBOCOP_VERSION into $DEST"
