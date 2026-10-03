# Changelog

All notable changes to Qualor are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Qualor's own security rules: a new built-in engine, `qualor`, runs a pack of OpenGrep taint
  rules (source-available under PolyForm Shield 1.0.0, not MIT). The first rules find SQL built
  from HTTP request data in JavaScript/TypeScript (Express with `pg`/`mysql2`), Python (Flask,
  DB-API), Java (Servlets, Spring MVC, JDBC) and Go (`net/http`, `database/sql`). Rule keys look
  like `qualor:java/sql-injection`; the UI shows the engine as "Qualor". Configure it with
  `analyzers.qualor`; `QUALOR_RULES_DIR` points at another copy of the rules. `nosemgrep`
  comments do not hide its findings; mark them as false positives instead. The pack is not
  published yet, so `qualor/scanner` images do not include it: until then the engine is skipped
  with the message "Qualor's security rules are not installed".
- Where Qualor's rules and another analyzer report the same problem on a line, Qualor's issue is
  primary; if you had marked the other issue as a false positive or won't fix, the new issue
  starts with that status, once.
- Java security analysis: `qualor/scanner` bundles FindSecBugs 1.14.0 (LGPL-3.0) in SpotBugs. Its
  144 patterns report injections (SQL, command, path, LDAP, XPath, XSS, SSRF, expression languages),
  XXE, unsafe deserialisation configuration, weak cryptography and hard-coded passwords as
  `spotbugs:` rules. Taint findings and definite misuse are issues; review findings (weak random
  numbers, cookie flags, CORS, weak hashes, request parameters, endpoints) are security hotspots,
  which the gate never counts. The engine's version names the plugin
  (`4.10.4 + FindSecBugs 1.14.0`). `qualor import sonarqube` maps 24 SonarQube Java security rules
  to them (three activate profile rules, the rest import statuses).

### Changed

- `SEMGREP_*` and `OPENGREP_*` environment variables no longer reach OpenGrep or Semgrep:
  `SEMGREP_BASELINE_REF` and `SEMGREP_BASELINE_COMMIT` silently hid every finding older than
  that commit.
- Where a SpotBugs security rule and FindSecBugs report the same problem on one line (SQL from a
  non-constant string, a constant or empty database password, a request parameter in a header,
  cookie, file path or servlet response), the FindSecBugs issue is a duplicate of SpotBugs' own, so issues you
  already triaged stay as they are.
- `findsecbugs*` environment variables are dropped from SpotBugs' environment, so a custom
  FindSecBugs configuration named there is not read.

## [0.4.1] - 2026-10-02

### Added

- A public, read-only demo: `QUALOR_DEMO_USER` names a user anyone may sign in as from the
  sign-in page's **Explore the demo**, without a password (`POST /api/v0/auth/demo`). Every change
  made as that user is refused with 403 `DEMO_READ_ONLY`, whatever its role; the button shows only
  while the user is active, no instance admin, needs no password change and holds no role above
  Viewer. Demo sessions last at most 24 hours. `GET /auth/methods` and `GET /auth/me` say `demo`.

## [0.4.0] - 2026-10-02

### Added

- **Project → Settings** in the UI: the new-code definition (last N days, since the previous
  version, or a fixed analysis, with the current baseline), the quality gate and the quality
  profile of each language, the main branch, project analysis tokens, the project's webhooks, and
  deleting the project (type its key). Each panel shows only to those who may change it.
- Webhooks in the UI: a webhook applies to every project or to one project, a delivery can be
  sent again, the deliveries list has **Refresh**, and **Rotate secret** issues a new secret shown
  once.
- An issue's **Related locations** (the secondary locations an analyzer reports) on its page,
  numbered and marked in the code snippet, each linking to its file.
- The **Code** tab: a branch's directories and files with lines of code, complexity, coverage,
  duplication and open issues, and a page per file with a line map of coverage, new code,
  duplicated blocks and issues. Source code is not stored or shown.
- PHP: `.php` files are a language of their own (`php`) with metrics, duplication and a `php`
  quality profile, and a new `phpstan` engine runs PHPStan 2.2 (MIT) from `qualor/scanner` on
  Debian's PHP 8.2, at level 2 (`analyzers.phpstan.level`, 0-10 or `max`), with Qualor's own
  configuration. It never loads the project's `phpstan.neon`, its bootstrap files, PHPStan
  extensions or Composer's autoloader, and runs on a copy of the sources; installed dependencies
  in `vendor/` are read as symbols, never run. Unknown classes, methods and functions are not
  reported. `qualor import sonarqube` imports PHP profiles where a PHPStan rule is the same rule.
  `QUALOR_PHPSTAN_PHAR` names another phar.
- Ruby: `.rb`, `.rake`, `.gemspec`, `.ru`, `Gemfile` and `Rakefile` are a language of their own
  (`ruby`) with metrics and duplication, and a new `rubocop` engine
  runs RuboCop 1.91 (MIT) on Ruby 4.0.7 from `qualor/scanner` with Qualor's own selection
  (`qualor-default`: RuboCop's Lint and Security cops, minus a few that misfire in a Qualor
  scan; the guide lists them). It never reads the project's `.rubocop.yml`;
  choose cops with `analyzers.rubocop.select` and `ignore`, and the parsed Ruby version with
  `targetRubyVersion`. A `ruby` quality profile is created for every organisation.
  `qualor import sonarqube` imports Ruby profiles where a RuboCop cop checks the same thing (two
  rules are equivalent and activate their cop; the others are overlaps that only import issue
  statuses), and keeps the statuses of issues SonarQube imported from RuboCop.
- Go: `.go` files are language `go`, with metrics, duplication and a `go` quality profile, and three
  engines run from `qualor/scanner`: `staticcheck` (staticcheck 2026.2.1), `govet` (go vet of Go
  1.27.1) and `gosec` (gosec 2.29.0, security; G104, G115 and G304 left out by default). They
  analyse each Go module offline: run `go mod download` (or vendor your dependencies) before
  `qualor scan`; a package whose dependencies are missing is not analysed and the log says so.
  Nothing the repository asks for is run (no `go generate`, no other toolchain, no cgo), and a
  module that replaces a dependency with an outside directory or links out of the repository is
  skipped. Go coverage profiles (`go test -coverprofile`) import as the new `gocover` format.
  `qualor import sonarqube` maps the statuses of issues SonarQube imported from go vet, and 18
  curated `go:` rules (statuses only until reviewed).
- C and C++: `qualor/scanner` runs cppcheck 2.22.0 (GPL-3.0-or-later, built from source; its
  source ships in `qualor/scanner-sources`) as the `cppcheck` engine, on by default, with no build
  needed. A clang-tidy (LLVM 14+) on `PATH` runs as the `clang-tidy` engine when the job also has a
  `compile_commands.json`; no image bundles it. Qualor reads compile databases and `.clang-tidy`
  itself and never passes plugins, response files or compiler wrappers. C and C++ files get metrics
  and duplication (tree-sitter-c 0.24.1, tree-sitter-cpp 0.23.4), built-in C and C++ quality
  profiles, and `qualor import sonarqube` maps common C/C++ rules (pending review). gcovr and
  llvm-cov coverage reports already work.

### Changed

- A report that holds PHP, Ruby, Go, C or C++ files, or findings of the `phpstan`, `rubocop`,
  `staticcheck`, `govet`, `gosec`, `cppcheck` or `clang-tidy` engine, is refused (422) by a Qualor
  server older than this release: upgrade the server before the scanner.
- `.php` files were language `other`; they now count in lines of code, complexity and
  duplication, and `*Test.php` files are test files by default.
- PHPStan is skipped when `composer.json` requires packages but `vendor/` is not installed: run
  `composer install` (scripts and plugins are not needed) before the scan.
- `phpstan` is now a built-in engine id: a `sarif:` entry with `engine: phpstan` no longer
  validates, and your own PHPStan SARIF import is reported as `ext-phpstan` and counted once.
- `.rb`, `.rake`, `.gemspec`, `.ru`, `Gemfile` and `Rakefile` were language `other`; they now count
  in lines of code, complexity and duplication, which can move the new-code duplication condition.
  `*_spec.rb`, `*_test.rb` and Ruby files below `spec/` and `test/` are test files by default.
- New built-in excludes: `.bundle` directories and `db/schema.rb`.
- `rubocop` is now a built-in engine id: a `sarif:` entry with `engine: rubocop` no longer
  validates. Qualor runs RuboCop itself: remove your own RuboCop SARIF import; one you keep is
  reported as `ext-rubocop` and counts once with the built-in finding.
- `**/testdata/**` and `**/*.pb.go` are built-in excludes (Trivy's `--skip-dirs` included); the
  `testdata/` exclude applies to every language, so secret and dependency scanning skip it too, and
  `**/*_test.go` files are tests by default. `.go` files were `other` and now count in lines of
  code and duplication.
- `staticcheck`, `govet` and `gosec` are reserved engine ids: a `qualor.yml` `sarif:` entry with one
  of them fails validation. A SARIF of your own from staticcheck or gosec becomes `ext-staticcheck`
  or `ext-gosec` and is counted once with the built-in finding; remove it, Qualor runs these tools
  itself.
- `.c`, `.cpp`, `.h` and the other C/C++ files were `other`; they now count as `c` or `cpp` in
  lines of code and duplication. `CMakeFiles/`, `cmake-build-*/` and `_deps/` are built-in
  excludes. `cppcheck` and `clang-tidy` are reserved engine ids (`ext-cppcheck` and
  `ext-clang-tidy` are the names of your own imported SARIF of these tools, and count once).
- `qualor/scanner` is about 115 MB larger compressed (about 4.1 GB unpacked, was 3.5 GB) with
  PHP 8.2 and PHPStan, Ruby and RuboCop, the Go toolchain and cppcheck; `qualor/scanner-dotnet`
  is about 100 MB larger compressed (about 5.8 GB unpacked, was 5.3 GB).

## [0.3.2] - 2026-10-01

### Changed

- The summary comment on GitLab merge requests and GitHub pull requests is easier to read: a status
  icon in the headline, the gate name, the commit and the number of new issues on one line, a table
  of every gate condition (passed ones too) with its value and the value it requires, the conditions
  the gate skipped and why, severity markers, a numbered list of the most severe new issues with
  their quality, rule and a link to each in Qualor, and an **Open in Qualor** link.

### Fixed

- sonarjs: S2430 no longer reports calls to HTTP-verb methods such as `client.GET()` or
  `client.POST()` (openapi-fetch style clients) as constructors called without `new`.

## [0.3.1] - 2026-10-01

### Added

- The user guide is built into the server: **Docs** in the top bar opens `/docs`, the guide of the
  server's own release, for signed-in users, with the page list, the sections of each page and
  Copy buttons on code blocks and AI prompts.
- The user menu shows the server's version and edition.
- `GET /api/v0/system/version` returns the server's version to any token, project analysis tokens
  included.
- `qualor scan` logs its own version when it starts and, with a server configured, the server's
  version; it warns when the scanner and the server are different releases. The check never fails
  a scan.
- The server logs its version when it starts.

## [0.3.0] - 2026-10-01

### Added

- Python: `.py` files are a language of their own (`python`) with metrics and duplication, and a
  new `ruff` engine runs Ruff 0.16 (MIT) from `qualor/scanner` with Qualor's own rule selection
  (`qualor-default`: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors and
  flake8-bandit's security rules). It never reads the project's Ruff configuration; choose rules
  with `analyzers.ruff.select` and `analyzers.ruff.ignore`. A `python` quality profile is created
  for every organisation. `qualor import sonarqube` imports Python profiles where a Ruff rule is
  the same rule, and keeps the statuses of issues SonarQube imported from Ruff. The curated
  SonarQube-rule-to-Ruff-rule mappings (88 rules) are reviewed: each was compared against both
  rules' public documentation, and an imported Python profile now activates the mapped Ruff rule
  where the two are equivalent. A mapping marked overlap (partial counterpart) only imports issue
  statuses and does not activate the rule.
- HTML and CSS: `.html`/`.htm` files are language `html`, `.css` and `.scss` files language `css`,
  with their own quality profiles, and HTML and CSS get line, comment and duplication metrics.
  `qualor/scanner` runs HTMLHint 1.9.2 (`htmlhint` engine) and stylelint 17.15 (`stylelint`
  engine) with the project's `.htmlhintrc` or JSON/YAML stylelint configuration, or Qualor's own
  (HTMLHint rules that suit templates; `stylelint-config-recommended`). A stylelint configuration
  written in JavaScript or TypeScript is never run: stylelint is skipped with the reason, and
  `analyzers.stylelint.configFile: qualor-default` uses Qualor's configuration instead.
- Kotlin: `.kt` and `.kts` files are a language of their own (`kotlin`), with complexity, size and
  duplication metrics and a "Qualor way" Kotlin quality profile. `qualor/scanner` runs detekt 1.23.8
  (Apache-2.0) on them as a new `detekt` engine (rule keys such as `detekt:MagicNumber`), with the
  repository's own detekt config (`config/detekt/detekt.yml`, `config/detekt.yml`, `detekt.yml` or
  `.detekt.yml`) on top of detekt's defaults, or detekt's default rule set with the settings
  detekt recommends for Jetpack Compose. Rules that need the project's classpath do not run, and
  plugins and baselines from the checkout are never loaded. A detekt config Qualor cannot use
  makes detekt skip (fail under `analyzers.detekt.enabled: true`); an
  `analyzers.detekt.configFile` outside the repository stops the scan with exit 2. Turn it off
  with `analyzers.detekt.enabled: false`.
- Swift: `.swift` files are a language of their own (`swift`), with complexity, size and
  duplication metrics (tree-sitter-swift 0.7.3) and a "Qualor way" Swift quality profile.
  `qualor/scanner` runs SwiftLint 0.65.1 (MIT), its static Linux build with no Swift toolchain, on
  them as a new `swiftlint` engine (rule keys such as `swiftlint:force_cast`). It uses the
  repository's own `.swiftlint.yml`, read and filtered by Qualor (settings that write files, fetch
  URLs or change the exit code are ignored), or, without one, SwiftLint's default rules with
  adjustments for code that Xcode, SwiftPM and the common formatters write (`todo`,
  `multiple_closures_with_trailing_closure`, `trailing_comma` and `comment_spacing` off,
  `trailing_whitespace` ignoring empty lines, `identifier_name` excluding `i`, `j`, `k`, `x`, `y`,
  `z` and `id`, `line_length` ignoring URLs and comments, `opening_brace` accepting `{` on its own
  line after a wrapped condition, type header or signature, and `nesting` allowing types two
  deep). The rules that need SourceKit, and custom rules, do not run; Swift files over 1 MiB are
  not passed to SwiftLint, and files with CRLF line ends are passed with LF ends, so SwiftLint's
  line numbers are right. Rule ids SwiftLint does not know and rule settings it cannot read (it
  then uses the rule's defaults) are warned about in the scan log. A `.swiftlint.yml` Qualor
  cannot use (`parent_config` or `child_config`, `only_rules` combined with `disabled_rules`,
  `opt_in_rules` or `enabled_rules`, invalid YAML, larger than 1 MiB) makes SwiftLint skip (fail
  under `analyzers.swiftlint.enabled: true`); `analyzers.swiftlint.configFile: qualor-default`
  uses the defaults instead, and a `configFile` that is a URL or outside the repository stops the
  scan with exit 2. Turn it off with `analyzers.swiftlint.enabled: false`.
  `qualor import sonarqube` carries over the statuses of SwiftLint issues SonarQube imported
  (`external_swiftlint`).

### Changed

- A report that holds Python files is refused (422) by a Qualor server older than this release:
  upgrade the server before the scanner.
- `.py` files were language `other`; they now count in lines of code, complexity and duplication,
  and `test_*.py`, `*_test.py` and `conftest.py` are test files by default.
- New built-in excludes: `.venv`, `venv`, `.tox`, `.nox`, `__pycache__`, `__pypackages__`,
  `.eggs` and `site-packages` directories.
- Qualor now runs Ruff itself. If you imported your own Ruff SARIF to cover Python, remove that
  import (the `--sarif` flag, or the `qualor.yml` `sarif:` entry) and run Ruff with
  `analyzers.ruff` instead. `ruff` is now a reserved engine id: a `sarif:` entry with
  `engine: ruff` is a config error. A Ruff SARIF you still import is reported as `ext-ruff`, and
  each of its findings counts once with the built-in `ruff` finding of the same code on the same
  line (the built-in one is shown).
- `stylelint` and `htmlhint` are reserved engine ids: a `qualor.yml` `sarif:` entry with
  `engine: stylelint` or `engine: htmlhint` no longer validates, and a SARIF tool with that name
  becomes `ext-stylelint` / `ext-htmlhint`, so issues imported that way before get new rule keys.
- `.html`, `.htm` and `.css` files were language `other`; they now count in lines of code and
  duplication, which can move a new-code duplication condition. `.scss` files, `other` before too,
  are now language `css` (linted by stylelint, without metrics).
- Qualor now runs stylelint and HTMLHint itself. If you imported your own stylelint or HTMLHint
  SARIF, remove that import (the `--sarif` flag, or the `qualor.yml` `sarif:` entry). A stylelint
  or HTMLHint SARIF you still import is reported as `ext-stylelint` / `ext-htmlhint`, and each of
  its findings counts once with the built-in finding of the same code on the same line.
- `**/*.min.css` is a built-in exclude, like `**/*.min.js`.
- A report with `html` or `css` files needs a server of this version; upgrade the server with the
  scanner.
- Qualor now runs detekt itself. If you imported your own detekt SARIF to cover Kotlin, remove
  that import (the `--sarif` flag, or the `qualor.yml` `sarif:` entry). `detekt` is now a reserved
  engine id: a `sarif:` entry with `engine: detekt` is a config error. A detekt SARIF you still
  import is reported as `ext-detekt`, and each of its findings counts once with the built-in
  `detekt` finding of the same rule on the same line.
- A report that holds Kotlin files or the `detekt` engine is refused (422) by a Qualor server older
  than this release: upgrade the server before the scanner.
- `.kt` and `.kts` files were language `other`; they now count in lines of code, complexity and
  duplication, which can move a new-code duplication condition.
- `**/src/androidTest/**` and `**/src/*Test/**` are test sources by default. `**/src/*Test/**`
  covers Kotlin Multiplatform's test source sets, but applies to every language: Gradle's
  `src/integrationTest` or `src/functionalTest`, for example, become test files too, which leave
  lines of code, complexity, duplication and coverage.
- Qualor now runs SwiftLint itself. If you imported your own SwiftLint SARIF to cover Swift,
  remove that import (the `--sarif` flag, or the `qualor.yml` `sarif:` entry). `swiftlint` is now a
  reserved engine id: a `sarif:` entry with `engine: swiftlint` is a config error. A SwiftLint SARIF
  you still import is reported as `ext-swiftlint`, and each of its findings counts once with the
  built-in `swiftlint` finding of the same rule on the same line.
- A report that holds Swift files or the `swiftlint` engine is refused (422) by a Qualor server
  older than this release: upgrade the server before the scanner.
- `.swift` files were language `other`; they now count in lines of code, complexity and
  duplication, which can move a new-code duplication condition.
- `Pods/`, `Carthage/` and `.build/` are built-in excludes. Trivy skips them too, so a dependency
  lockfile that lives only inside one of them is no longer scanned; the lockfiles at the repository
  root (`Podfile.lock`, `Package.resolved`, `Cartfile.resolved`) still are.
- A directory whose name holds a line break (LF, CR, U+0085, U+2028 or U+2029) is skipped with a
  `PATH_UNSUPPORTED` report warning. The files below one were left out without a warning before,
  except below a U+0085 name, which were scanned.

## [0.2.0] - 2026-09-30

### Added

- SonarQube-compatible rules: `qualor/scanner-dotnet` adds SonarAnalyzer.CSharp 9.32 to the .NET
  build (rule keys `roslyn:S####`), and `qualor/scanner` runs eslint-plugin-sonarjs 2.0.4 with its
  recommended rules as a new `sonarjs` engine for JavaScript and TypeScript (`sonarjs:S####`). Both
  are the last LGPL-3.0 releases and do not change. `qualor import sonarqube` maps `csharpsquid:`,
  `javascript:` and `typescript:` rules one to one where the bundled versions have them. A project's
  own SonarAnalyzer reference replaces the bundled one; an ESLint issue and the sonarjs rule that
  decorates it count once. Turn them off with `analyzers.roslyn.sonarAnalyzer: false` and
  `analyzers.sonarjs.enabled: false`.
- **Settings → Organizations**: an instance admin sees every organisation and creates one with
  **New organization**.
- The **Branches** tab of a project deletes a branch or merge request, after a confirmation.

### Changed

- The web UI is redesigned, in the light and dark themes, and every page fits a phone and a
  tablet. A project's overview shows the quality gate's verdict with the condition that failed,
  the measures on new code, coverage, issues, duplication and size with their trends, and the
  history of open issues. The issues list has a filter bar and collapsible facets, and an issue
  shows its code, the AI assistant and its history beside its details. A quality gate's
  conditions are changed in their own rows. Settings are grouped as **Your account**,
  **Organization** and **Instance**, and creating or deleting something asks in a dialog. The
  account, **Change password** and **Sign out** are in a menu on the top bar.
- Projects are mapped to their GitLab and GitHub repositories on a page of their own, **Settings →
  Repositories**, instead of the **Projects** table of **Settings → GitLab**.
- `sonarjs` is now a built-in engine id. A `qualor.yml` `sarif:` entry with `engine: sonarjs` no
  longer validates (pick another id), and an imported tool whose name becomes `sonarjs` is reported
  as `ext-sonarjs`.
- `qualor dotnet begin` writes a new version of its MSBuild hook. The `qualor dotnet begin` of an
  older CLI treats that hook as not its own and stops with exit 2, so on a self-hosted runner whose
  builds share one MSBuild user directory, upgrade every `qualor` CLI on it together.

## [0.1.1] - 2026-09-29

### Fixed

- `restore` (the embedded database) no longer drops the database before the dump has loaded. It
  loads the dump into a new database and replaces the old one only on success; a truncated, empty or
  wrong file now fails with "the existing database was not changed" and the data stays as it was.
- `qualor import sonarqube` no longer fails the issue-status import with HTTP 500 on SonarQube
  Server 9.9 and Community Build: only rules the server has are queried, so rules from plugins it
  lacks (PMD) or newer than its analyzers no longer break the query. Reviewed security hotspots are
  counted on 9.9–10.1 too, and the SonarQube reads reuse one connection.
- `--help` and `-h` print the usage and exit 0 after any command or subcommand, instead of
  "Unknown option".
- GitLab: a 403 is no longer reported as "GitLab refused the token". The log and the connection
  test say the token lacks a permission; a commit status on a protected branch needs Maintainer.
- GitLab: after the decoration token is replaced by one of another user, the old summary comment
  is deleted instead of staying beside the new one (needs a Maintainer token).
- Connection tests and webhooks: a host name whose lookup does not finish in time, such as a
  single-label name, is reported as unresolved instead of a timeout.
- SSO: **Read metadata** on a SAML connection says why the metadata URL could not be read (host not
  public, name not resolved, timeout, TLS certificate, HTTP status, not SAML metadata) and logs a
  warning with the host and the reason. The connection **Test** reports a failed TLS certificate
  as `fetch.tls`.
- Signing in with single sign-on no longer asks for a new password when an admin set the user's
  password; the next password sign-in still does.
- AI assistant: a key the provider refuses names the provider's HTTP status (401: wrong key; 403:
  no access to the model or no credit), in the provider **Test** (`problem.providerStatus`) and the
  `AI request finished` log line. The error code stays `PROVIDER_REFUSED_KEY`.
- AI assistant: a request that failed without using tokens, because the provider refused the key
  or nothing was sent, no longer counts against the organisation's daily budgets. The hourly bound
  per person still counts every request.
- `qualor/scanner`: the notices name the five MPL-2.0 Go modules compiled into Gitleaks, and
  `qualor/scanner-sources` carries their source.

### Changed

- GitLab: the connection test reports the token's access level in the project, and the settings
  page warns when it is below Maintainer. The guide now asks for a Maintainer token.
- Docs: the GitLab guide covers self-managed GitLab (a one-time import of the component, included
  by its full version); the SonarQube migration guide says what the import moves today and when
  the scanner image needs `--allow-insecure-http`; troubleshooting covers a project reused across
  git histories.

### Security

- `qualor/scanner` and `qualor/scanner-dotnet`: Gitleaks 8.30.1 is built from its release source
  with Go 1.27.1 and current `golang.org/x/crypto` and `golang.org/x/text`, instead of the upstream
  binary built with Go 1.24.11 (CVE-2025-68121 and others).
- Node.js 22.23.3 (was 22.23.2) in all images; its npm bundles tar 7.5.22 (CVE-2026-59873,
  CVE-2026-59874, CVE-2026-73566).
- The HIGH and CRITICAL image vulnerabilities that no release fixes yet are listed with reasons
  and a review date in `deploy/scanner/.trivyignore.yaml`.

## [0.1.0] - 2026-09-28

The first public release.

### Added

- The server, `qualor/server`: the API, the web UI and the analysis worker in one image, with its
  own PostgreSQL 18 on a volume, or an external PostgreSQL 16 or later through `DATABASE_URL`.
  Docker Compose and a Helm chart (`docs/guide/install-server.md`).
- The scanner, `qualor/scanner`, and the `qualor` CLI: ESLint from the project's own
  configuration, PMD, SpotBugs, OpenGrep, Gitleaks and Trivy, any SARIF file, coverage import,
  duplication and metrics. `qualor/scanner-dotnet` adds C# with the .NET 8 and .NET 10 SDKs,
  the SDK's analyzers and Roslynator, hooked into the project's own build
  (`qualor dotnet begin`, the build, `qualor dotnet end`).
- Quality gates on new code, issue tracking across commits and branches, and quality profiles.
- GitLab: merge request comments, inline discussions and a commit status, the CI/CD component
  `gitlab.com/qualor/qualor`, and GitLab's Code Quality, SAST and Dependency Scanning reports.
- GitHub: a GitHub App with check runs and pull request comments, and GitHub Actions workflows
  in `integrations/github/`.
- `qualor import sonarqube`: quality profiles, gates and issue statuses from SonarQube Server or
  SonarQube Cloud.
- The AI assistant with your own model: explain an issue, suggest a triage, suggest a fix.
- Roles and project access in every edition: Organization admin, Project admin, Maintainer and
  Viewer, and roles on a single project.
- Webhooks and a documented HTTP API (`server/openapi.json`).
- The enterprise edition, with an offline licence key (`docs/guide/enterprise.md`): single sign-on
  with OIDC and SAML, SCIM 2.0 for Entra ID and Okta, a tamper-evident audit log with export and
  SIEM streaming, and a higher AI fix suggestion limit. The enterprise code is source-available
  under the Qualor Enterprise Licence (`enterprise/LICENSE`); everything else is MIT.
- Signed releases: cosign signatures and SPDX SBOMs for every image and the chart, and a signed
  `SHA256SUMS` for the release files (`SECURITY.md`).
