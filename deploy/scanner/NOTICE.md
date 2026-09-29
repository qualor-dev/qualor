# qualor/scanner: third-party notices

The `qualor/scanner` image bundles the Qualor CLI (MIT, `/opt/qualor/licenses/qualor/LICENSE`)
with third-party programs, each under its own licence. They are unmodified upstream releases,
installed by `tools/analyzers/install.sh` (pinned versions, SHA-256 checked; Trivy's
vulnerability database pinned by digest), compiled into the
`qualor` binary from the pinned lockfile, or copied from the pinned base images named in
`deploy/scanner/Dockerfile`. The licence texts are in `/opt/qualor/licenses/` of the image
(`deploy/scanner/licenses/` in the repository) unless the table names another place.

| Component                                                       | Version                                        | Licence                                                                                                                                                                              | Source                                                                               |
| --------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| OpenGrep                                                        | 1.30.0                                         | LGPL-2.1 (`OPENGREP-LICENSE.txt`)                                                                                                                                                    | https://github.com/opengrep/opengrep/tree/v1.30.0                                    |
| SpotBugs                                                        | 4.10.4                                         | LGPL-2.1 (`SPOTBUGS-LICENSE.txt`; its libraries: `/opt/qualor/lib/spotbugs-4.10.4/LICENSE-*.txt`)                                                                                    | https://github.com/spotbugs/spotbugs/tree/4.10.4                                     |
| PMD                                                             | 7.27.0                                         | BSD-style, with Apache-2.0 parts (`PMD-LICENSE.txt`); its bundled libraries: see below                                                                                               | https://github.com/pmd/pmd/tree/pmd_releases/7.27.0                                  |
| Gitleaks                                                        | 8.30.1                                         | MIT (`GITLEAKS-LICENSE.txt`); its MPL-2.0 Go modules: see below                                                                                                                      | https://github.com/gitleaks/gitleaks/tree/v8.30.1                                    |
| Trivy                                                           | 0.74.0                                         | Apache-2.0 (`TRIVY-LICENSE.txt`, `TRIVY-NOTICE.txt`); its MPL-2.0 Go modules: see below                                                                                              | https://github.com/aquasecurity/trivy/tree/v0.74.0                                   |
| Trivy vulnerability database (a snapshot)                       | see `/opt/qualor/share/trivy/db/metadata.json` | the advisories' own terms: see below                                                                                                                                                 | https://github.com/aquasecurity/trivy-db                                             |
| eslint-plugin-sonarjs (Qualor's own `sonarjs` pass)             | 2.0.4                                          | LGPL-3.0 (`ESLINT-PLUGIN-SONARJS-LICENSE.txt`); its npm dependency tree, axe-core (MPL-2.0) included: see below (`SONARJS-DEPENDENCIES.txt`)                                         | https://github.com/SonarSource/SonarJS/tree/273825f98b35b29b409fbf4f89efce075c651d96 |
| Eclipse Temurin JRE                                             | 17.0.20+8                                      | GPL-2.0 with the Classpath Exception (`/opt/java/openjdk/legal/`)                                                                                                                    | `qualor/scanner-sources`                                                             |
| Node.js                                                         | 22.23.3                                        | MIT and bundled licences (`NODE-LICENSE.txt`)                                                                                                                                        | https://github.com/nodejs/node/tree/v22.23.3                                         |
| npm, Corepack and Yarn (from the Node.js image)                 | 10.9.9, 0.36.0, 1.22.22                        | Artistic-2.0, MIT, BSD-2-Clause (the `LICENSE` in each package's directory)                                                                                                          | https://github.com/nodejs/docker-node                                                |
| Bun runtime (inside the `qualor` binary)                        | 1.3.13                                         | MIT; it links JavaScriptCore/WebKit (LGPL-2), tinycc (LGPL-2.1) and others (`BUN-LICENSE.txt`)                                                                                       | https://github.com/oven-sh/bun/tree/bun-v1.3.13                                      |
| npm packages inside the `qualor` binary (below)                 | as locked                                      | MIT or ISC (`qualor/npm/<package>@<version>/`; saxes: `SAXES-LICENSE.txt`; tree-sitter-c-sharp: `TREE-SITTER-C-SHARP-LICENSE.txt`)                                                   | https://www.npmjs.com/                                                               |
| Debian packages (git, ca-certificates, base system)             | bookworm                                       | per package, `/usr/share/doc/*/copyright`                                                                                                                                            | `qualor/scanner-sources` (`debian/`)                                                 |
| .NET SDK (software only in `qualor/scanner-dotnet`)             | 8.0.425 and 10.0.401                           | MIT (`DOTNET-LICENSE.txt`, identical for both versions); their own third-party notices, per version: `DOTNET-8.0.425-ThirdPartyNotices.txt`, `DOTNET-10.0.401-ThirdPartyNotices.txt` | https://github.com/dotnet/sdk                                                        |
| Roslynator.Analyzers (software only in `qualor/scanner-dotnet`) | 5.0.0                                          | Apache-2.0, Josef Pihrt and contributors (`ROSLYNATOR-LICENSE.txt`)                                                                                                                  | https://github.com/dotnet/roslynator/tree/v5.0.0                                     |
| SonarAnalyzer.CSharp (software only in `qualor/scanner-dotnet`) | 9.32.0.97167                                   | LGPL-3.0 (`SONARANALYZER-CSHARP-LICENSE.txt`)                                                                                                                                        | https://github.com/SonarSource/sonar-dotnet/tree/9.32.0.97167                        |

`deploy/scanner/Dockerfile` copies the whole `deploy/scanner/licenses/` directory, so the .NET SDK
and Roslynator licence files above ship in the plain `qualor/scanner` image too, unused; only
`qualor/scanner-dotnet` (`deploy/scanner-dotnet/Dockerfile`) actually adds the SDKs and Roslynator
themselves.

PMD's distribution bundles third-party Java libraries under their own licences. Its CycloneDX
SBOM, `/opt/qualor/lib/pmd-bin-7.27.0/sbom/pmd-7.27.0-cyclonedx.json` (and `.xml`), lists every one
with its version and licence. Besides Apache-2.0, MIT and BSD-2/3-Clause libraries these are:
Saxon-HE 12.10 and Rhino 1.7.15.1 (MPL-2.0), jsr250-api 1.0 (CDDL-1.0), jline 3.21.0 and the
Scalameta parsers 4.17.3 (`parsers`, `trees`, `common`, `io`; BSD-4-Clause), and JNA 5.12.1
(LGPL-2.1-or-later or Apache-2.0, at the recipient's choice). They are PMD's unmodified jars in
`/opt/qualor/lib/pmd-bin-7.27.0/lib/`. The source code of the MPL-2.0 and CDDL-1.0 libraries is
available from Maven Central, as the `-sources.jar` next to each jar:
https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE/12.10/,
https://repo1.maven.org/maven2/org/mozilla/rhino/1.7.15.1/ and
https://repo1.maven.org/maven2/javax/annotation/jsr250-api/1.0/ (also
https://github.com/Saxonica/Saxon-HE and https://github.com/mozilla/rhino).

The Gitleaks binary is built in the image from the source of its release tag with Go 1.27, statically
linked with the Go standard library and 65 Go modules (`go version -m /opt/qualor/bin/gitleaks`
lists them; `golang.org/x/crypto` and `golang.org/x/text` are raised to fixed releases). Five are
under MPL-2.0 and have their source in `qualor/scanner-sources`: hashicorp's `errwrap` 1.1.0,
`go-multierror` 1.1.1, `go-version` 1.7.0, `golang-lru/v2` 2.0.7 and `hcl` 1.0.0; the rest is MIT,
BSD, Apache-2.0 or CC0-1.0.

The Trivy binary is a statically linked upstream build (Go 1.26). Of the 375 Go modules it
compiles in (`go version -m /opt/qualor/bin/trivy` lists them), eleven are under MPL-2.0 and have
their source in `qualor/scanner-sources`: hashicorp's `aws-sdk-go-base/v2` v2.0.0-beta.72,
`errwrap` 1.1.0, `go-cleanhttp` 0.5.2, `go-getter` 1.8.6, `go-multierror` 1.1.1,
`go-retryablehttp` 0.7.8, `go-uuid` 1.0.3, `go-version` 1.9.0, `golang-lru/v2` 2.0.7 and
`hcl/v2` 2.24.0, and `cyphar/filepath-securejoin` 0.6.1 (BSD-3-Clause with MPL-2.0 files).
`spdx/tools-golang` is Apache-2.0 or GPL-2.0-or-later at the recipient's choice, taken as
Apache-2.0; the rest is Apache-2.0, MIT, BSD or ISC.

Trivy's vulnerability database (`/opt/qualor/share/trivy/db/`) is a snapshot of
`ghcr.io/aquasecurity/trivy-db:2`, built by Aqua Security from public advisories (the `trivy-db`
code is Apache-2.0; its repository states no licence for the database content). Qualor ships the
database unmodified. Its sources keep their own terms. Where a source states them: the
GitHub Advisory Database (CC-BY-4.0, https://github.com/github/advisory-database), the NVD (public
domain, with NIST's terms of use, https://nvd.nist.gov/), Red Hat security data (CC-BY-4.0,
https://access.redhat.com/security/data) and the Go vulnerability database (CC-BY-4.0, per
https://github.com/google/osv.dev/blob/master/docs/data.md). Canonical's Ubuntu security data
(the Ubuntu CVE Tracker) is possibly CC-BY-SA-4.0: OSV lists its Ubuntu data under that licence
(https://github.com/google/osv.dev/blob/master/docs/data.md), after Launchpad bug 1962128
("Clarify data license", https://bugs.launchpad.net/bugs/1962128). Other sources, stated here
without a licence: the Debian Security Tracker (https://security-tracker.debian.org/), OSV, the
Ruby Advisory Database, the PHP Security Advisories Database, the Node.js security working group
and the GitLab Advisory Database community edition. Aqua Security lists the database's sources
(not their licences) at https://trivy.dev/docs/latest/guide/scanner/vulnerability/. Whether any
of these terms binds the distribution of the snapshot is an open legal question. When it was
built:
`/opt/qualor/share/trivy/db/metadata.json` (`UpdatedAt`), also recorded in every report
(`engines[].database`).

The OpenGrep release binary is a Nuitka one-file Python program. When it runs it unpacks, into
`~/.cache/opengrep/<version>/`, CPython 3.13 (PSF-2.0) and its extension modules, the Python
packages OpenGrep needs, some AlmaLinux 8 libraries, and `opengrep-core`, a static musl binary.
Their copyleft parts, all with source in `qualor/scanner-sources`:

- GMP 6.3.0 (LGPL-3.0-or-later or GPL-2.0-or-later), linked statically into `opengrep-core`
  from Alpine 3.22's `gmp-static` 6.3.0-r3;
- GNU Readline 7.0 (GPL-3.0-or-later): `libreadline.so.7` from AlmaLinux 8's
  `readline-7.0-10.el8`, loaded by CPython's `readline` module;
- certifi 2026.7.22 (MPL-2.0).

The rest is permissive: the OCaml runtime and OpenGrep's OCaml libraries (their LGPL parts carry
the OCaml static-linking exception), tree-sitter and its grammars, PCRE2, libev (BSD option),
OpenSSL, zlib and zstd, musl, the GCC runtime (GCC Runtime Library Exception), and from AlmaLinux
8 `libtinfo` (ncurses), `libffi`, `libuuid`, `libbz2`, `liblzma`, OpenSSL 1.1.1k, SQLite and
mpdecimal. The Python packages are MIT, BSD, Apache-2.0, PSF or 0BSD (chardet 7).

The npm packages compiled into the `qualor` binary are ignore, picomatch, saxes, xmlchars, yaml,
zod, web-tree-sitter and the tree-sitter grammars for Java, JavaScript, TypeScript and C#
(`tree-sitter-c-sharp` 0.23.5, MIT, `TREE-SITTER-C-SHARP-LICENSE.txt`), in the
versions `pnpm-lock.yaml` locks. The `qualor` binary, and so this grammar, is the same in
`qualor/scanner` and `qualor/scanner-dotnet`: the image only adds the .NET SDKs and
Roslynator around it. The image keeps the licence files of every production dependency
of the CLI, as installed, in `/opt/qualor/licenses/qualor/npm/`.

Qualor's own `sonarjs` pass (`/opt/qualor/sonarjs`) runs eslint-plugin-sonarjs 2.0.4 (LGPL-3.0, the
last release before the SONAR Source-Available License) on its own ESLint 9, installed at image
build with `npm ci --omit=dev` from `tools/analyzers/sonarjs/package-lock.json`. Its installed npm
tree is otherwise permissively licensed (MIT, ISC, BSD, Apache-2.0 and others,
`SONARJS-DEPENDENCIES.txt`) except axe-core 4.13.0 (MPL-2.0), a dependency of
eslint-plugin-jsx-a11y, which eslint-plugin-sonarjs itself depends on; its source is in
`qualor/scanner-sources`, same as eslint-plugin-sonarjs's own.

## The .NET SDK, Roslynator and SonarAnalyzer.CSharp (software only in `qualor/scanner-dotnet`)

`qualor/scanner-dotnet` (`deploy/scanner-dotnet/Dockerfile`) is `qualor/scanner` plus the
.NET SDKs and analyzers `tools/analyzers/install-dotnet.sh` installs into `/opt/qualor`, for C#
projects (`qualor dotnet begin` and `end`). Their licence files ship in both images (see above); the SDKs,
Roslynator and SonarAnalyzer.CSharp themselves only in `qualor/scanner-dotnet`:

| Component            | Version              | Licence                                                                                                                                                                                                                                                                                                                              | Source                                                        |
| -------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| .NET SDK             | 8.0.425 and 10.0.401 | MIT (`DOTNET-LICENSE.txt`, Microsoft, identical for both versions); their own third-party notices, per version (see below): `DOTNET-8.0.425-ThirdPartyNotices.txt`, `DOTNET-10.0.401-ThirdPartyNotices.txt`                                                                                                                          | https://github.com/dotnet/sdk                                 |
| Roslynator.Analyzers | 5.0.0                | Apache-2.0, Josef Pihrt and contributors (`ROSLYNATOR-LICENSE.txt`)                                                                                                                                                                                                                                                                  | https://github.com/dotnet/roslynator/tree/v5.0.0              |
| SonarAnalyzer.CSharp | 9.32.0.97167         | LGPL-3.0 (`SONARANALYZER-CSHARP-LICENSE.txt`), the last release before the SONAR Source-Available License; its bundled third-party code (Google.Protobuf, BSD-3-Clause; StyleCop Lightup, MIT; Roslyn, Apache-2.0) under the package's own notices, `SONARANALYZER-CSHARP-THIRD-PARTY-NOTICES.txt` (only in `qualor/scanner-dotnet`) | https://github.com/SonarSource/sonar-dotnet/tree/9.32.0.97167 |

All three are unmodified upstream releases, pinned by hash in `tools/analyzers/install-dotnet.sh`; a
project that already references SonarAnalyzer.CSharp itself builds with its own version only, so
this adds no duplicate analyzer. Both
SDKs share one `DOTNET_ROOT` (`/opt/qualor/share/dotnet`), so the second tarball's
top-level `LICENSE.txt`/`ThirdPartyNotices.txt` would silently overwrite the first's; the install
script now keeps a per-version copy of each (`LICENSE-<version>.txt`,
`ThirdPartyNotices-<version>.txt`) before that happens, and `deploy/scanner/licenses/` carries the
per-version notices (the two SDKs' `LICENSE.txt` were checked and are byte-identical, so only one
`DOTNET-LICENSE.txt` is kept). **Each SDK's own `ThirdPartyNotices.txt` was checked separately**
for a copyleft licence (`GPL`, `LGPL`, `MPL`, `EPL`, `CDDL`, `EUPL`) naming a bundled component:
neither names one (`grep -niE "\b(L?GPL|MPL|EPL|CDDL|EUPL|copyleft)\b"` finds nothing in either),
so neither component's source is published in `qualor/scanner-sources`.

Semgrep (LGPL-2.1) is **not** bundled. The CLI uses a Semgrep you install yourself only when no
OpenGrep is present; its licence then applies to that copy.

No Semgrep or OpenGrep rules are bundled: `/opt/qualor/rules/semgrep` is
empty, so `configs: [qualor-default]` runs no rules and the analyzer is skipped unless the
repository names its own rule files.

## Source code

The complete corresponding source of every copyleft component of `qualor/scanner`, and of what
`qualor/scanner-dotnet` adds on top of it, is published next to them, in the same registry, as the
one image `qualor/scanner-sources:<same tag>` (the files are in its `/sources/` directory), and as
files attached to the Qualor release page of the same tag:

- OpenGrep 1.30.0 (LGPL-2.1): its tag's source tree and each of its git submodules at the commit
  the tag records; and what its release binary links or bundles: GMP 6.3.0 (the upstream tarball
  and Alpine's build recipe), GNU Readline (the AlmaLinux source RPM `readline-7.0-10.el8`) and
  certifi 2026.7.22 (its PyPI sdist);
- SpotBugs 4.10.4 (LGPL-2.1): the source archive of its release;
- eslint-plugin-sonarjs 2.0.4 (LGPL-3.0), Qualor's own sonarjs pass: the source tree of the commit
  its release was published from, without its integration-test project sources; and axe-core 4.13.0
  (MPL-2.0), the one copyleft package its installed npm tree carries (a dependency of
  eslint-plugin-jsx-a11y): its source on GitHub's own release tag archive;
- SonarAnalyzer.CSharp 9.32.0.97167 (LGPL-3.0), software only in `qualor/scanner-dotnet`: the
  source tree of its tag's commit, without its integration-test harness;
- the eleven MPL-2.0 Go modules compiled into Trivy 0.74.0 and the five compiled into Gitleaks
  8.30.1: each module's source zip from the Go module proxy (`proxy.golang.org`) at the version the
  binary names;
- the MPL-2.0 and CDDL-1.0 Java libraries SpotBugs and PMD bundle: Saxon-HE 12.10, Rhino 1.7.15.1
  and jsr250-api 1.0 (their `-sources.jar` from Maven Central);
- the Eclipse Temurin JRE 17.0.20+8 (GPL-2.0 with the Classpath Exception): the source archive
  Adoptium publishes with that release, `OpenJDK17U-jdk-sources_17.0.20_8.tar.gz`;
- JavaScriptCore/WebKit (LGPL-2.0 and BSD) inside the Bun runtime of the `qualor` binary: Bun's
  fork `oven-sh/WebKit` at commit `4d5e75ebd84a14edbc7ae264245dcd77fe597c10`, the one Bun 1.3.13
  pins (`WEBKIT_VERSION` in its `scripts/build/deps/webkit.ts`), without its test suites,
  benchmarks and website;
- TinyCC (LGPL-2.1) inside the Bun runtime: Bun's fork `oven-sh/tinycc` at commit
  `12882eee073cfe5c7621bcfadf679e1372d4537b` (`TINYCC_COMMIT` in `scripts/build/deps/tinycc.ts`),
  with the patch Bun applies;
- Bun 1.3.13 itself (MIT), whose build scripts pin, patch and build the two above;
- every Debian package of the image (the base system, git, ca-certificates and their
  dependencies, among them glibc, bash, coreutils, perl and gnutls): the source package at the
  installed version, the `.dsc` and the files it lists, in `debian/`.

`/opt/qualor/SOURCES.md` in this image lists every file with its version, licence, SHA-256 and
upstream location; the files in `qualor/scanner-sources` have exactly those SHA-256 digests.

You may replace any of these components with a modified version of your own, for example by
building a derived image. The `qualor` binary is the unmodified Bun runtime with the Qualor CLI's
JavaScript bundle appended (`bun build --compile`); the CLI's source is MIT and public, so you can
build the same binary on a Bun that you have modified or relinked with a modified JavaScriptCore
or TinyCC (`pnpm --filter @qualor/cli build`, `cli/scripts/build.ts`).

As a courtesy, and not as the way we meet the licences: for at least three years after we last
distribute this image, we will also give any third party a complete machine-readable copy of that
source on request, for no more than the cost of physically performing the distribution: open an
issue in the Qualor repository (https://github.com/qualor-dev/qualor) or write to the maintainers
listed there. Upstream copies:
https://github.com/opengrep/opengrep/tree/v1.30.0, https://github.com/spotbugs/spotbugs/tree/4.10.4,
https://github.com/oven-sh/bun/tree/bun-v1.3.13, https://github.com/adoptium/jdk17u (tag
`jdk-17.0.20+8`), https://sources.debian.org/ and https://snapshot.debian.org/.
