# qualor/scanner-sources

This image holds files only: the complete corresponding source of the copyleft components of the
`qualor/scanner` image with the **same tag**, published next to it. The same files are attached to the Qualor release page of that tag.

- **OpenGrep** (LGPL-2.1): the source tree of its release tag, plus one archive per git
  submodule at the commit the tag records (GitHub's tag archive leaves submodules out; the
  `tests/semgrep-rules` submodule is test data and is not included). Its release binary also
  contains, and so this image carries the source of:
  - **GMP** 6.3.0 (LGPL-3.0-or-later or GPL-2.0-or-later), linked statically into
    `opengrep-core` from Alpine 3.22's `gmp-static` 6.3.0-r3: the upstream tarball and Alpine's
    build recipe (`APKBUILD`, no patches);
  - **GNU Readline** 7.0 (GPL-3.0-or-later), the AlmaLinux 8 `libreadline.so.7` that the
    Python launcher bundles: the source RPM `readline-7.0-10.el8.src.rpm`;
  - **certifi** 2026.7.22 (MPL-2.0), a Python package of the launcher: its PyPI sdist.
- **SpotBugs** (LGPL-2.1): the source archive SpotBugs attaches to its release.
- The MPL-2.0 and CDDL-1.0 Java libraries that SpotBugs and PMD bundle unmodified in their
  `lib/`, each as its `-sources.jar` from Maven Central: **Saxon-HE** 12.10 (MPL-2.0, in both),
  **Rhino** 1.7.15.1 (MPL-2.0, PMD) and **jsr250-api** 1.0 (CDDL-1.0, PMD).
- **Eclipse Temurin JRE** 17 (GPL-2.0 with the Classpath Exception): the source archive
  Adoptium publishes with that release.
- Inside the `qualor` binary, which is the Bun runtime with the Qualor CLI's JavaScript bundle
  appended (`bun build --compile`):
  - **JavaScriptCore/WebKit** (LGPL-2.0 and BSD), from Bun's fork `oven-sh/WebKit` at the commit
    that Bun's release pins. GitHub generates no archive of that repository, so this is the
    `git archive` tar of the commit without its test suites, benchmarks and website
    (`JSTests`, `LayoutTests`, `ManualTests`, `PerformanceTests`, `WebDriverTests`, `Websites`).
    They are not needed to build; whether leaving them out is still "complete" is a judgement
    call, and the full tree is the fallback (ask for it).
  - **TinyCC** (LGPL-2.1), from Bun's fork `oven-sh/tinycc` at the commit Bun's release pins.
    Bun applies `patches/tinycc/tcc.h.patch`, which is in the Bun archive.
  - **Bun** (MIT) at its release tag: the build scripts that pin both commits and build the
    runtime.
- **Debian** (`debian/`): every source package of every Debian package installed in the image,
  at the installed version: the `.dsc` and the files it lists.

`SOURCES.md` lists every file with its version, licence, SHA-256, upstream location and why it
is here; `sources.json` and `debian-sources.json` are the same lists as the Qualor repository
pins them. Check the files with `sha256sum -c SHA256SUMS`.

Get them out of the image (it has no shell and nothing to run):

```sh
docker create --name qualor-sources qualor/scanner-sources:<tag> none
docker cp qualor-sources:/sources ./qualor-scanner-sources
docker rm qualor-sources
```
