# qualor/scanner-sources

Short description: Corresponding source of the copyleft components of qualor/scanner, same tag.

## Overview

This image holds files only: the complete corresponding source of every copyleft component of
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) with the **same tag**. Every release
of `qualor/scanner:<tag>` publishes `qualor/scanner-sources:<tag>` next to it, and the same files
are attached to the release of that tag at <https://github.com/qualor-dev/qualor>. It is a
`scratch` image with the files in `/sources/`, about 1.7 GB (most of it WebKit).

### Contents

- **OpenGrep** 1.30.0 (LGPL-2.1): the source tree of its release tag and one archive per git
  submodule at the commit the tag records (the `tests/semgrep-rules` test data is left out); and
  what its release binary links or bundles: **GMP** 6.3.0 (LGPL-3.0-or-later or
  GPL-2.0-or-later: the upstream tarball and Alpine's build recipe), **GNU Readline** 7.0
  (GPL-3.0-or-later: the AlmaLinux source RPM `readline-7.0-10.el8`) and **certifi** 2026.7.22
  (MPL-2.0: its PyPI sdist).
- **SpotBugs** 4.10.4 (LGPL-2.1): the source archive of its release.
- The Java libraries SpotBugs and PMD bundle unmodified, as `-sources.jar` from Maven Central:
  **Saxon-HE** 12.10 (MPL-2.0), **Rhino** 1.7.15.1 (MPL-2.0) and **jsr250-api** 1.0 (CDDL-1.0).
- The **Eclipse Temurin JRE** 17.0.20+8 (GPL-2.0 with the Classpath Exception): Adoptium's
  `OpenJDK17U-jdk-sources_17.0.20_8.tar.gz`.
- Inside the `qualor` binary (the Bun runtime with the CLI's bundle appended):
  **JavaScriptCore/WebKit** (LGPL-2.0 and BSD) from Bun's fork `oven-sh/WebKit` at the commit Bun
  1.3.13 pins, without its test suites, benchmarks and website; **TinyCC** (LGPL-2.1) from Bun's
  fork `oven-sh/tinycc` at the commit Bun pins; and **Bun** 1.3.13 itself (MIT), whose build
  scripts pin, patch and build both.
- **Debian** (`/sources/debian/`): the source package of every Debian package installed in the
  image (the base system, git, ca-certificates and their dependencies, among them glibc, bash,
  coreutils, perl and gnutls) at the installed version: the `.dsc` and the files it lists.

`SOURCES.md` lists every file with its version, licence, SHA-256, upstream location and why it is
included; `sources.json` and `debian-sources.json` are the manifests the repository pins. Check
the files with `sha256sum -c SHA256SUMS`.

### Get the files

The image has no shell and nothing to run; copy the files out:

```sh
docker create --name qualor-sources qualor/scanner-sources:<tag> none
docker cp qualor-sources:/sources ./qualor-scanner-sources
docker rm qualor-sources
```
