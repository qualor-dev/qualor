# Changelog

All notable changes to Qualor are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Python: `.py` files are a language of their own (`python`) with metrics and duplication, and a
  new `ruff` engine runs Ruff 0.16 (MIT) from `qualor/scanner` with Qualor's own rule selection
  (`qualor-default`: Pyflakes, pycodestyle errors, flake8-bugbear, Pylint errors and
  flake8-bandit's security rules). It never reads the project's Ruff configuration; choose rules
  with `analyzers.ruff.select` and `analyzers.ruff.ignore`. A `python` quality profile is created
  for every organisation. `qualor import sonarqube` imports Python profiles where a Ruff rule is
  the same rule, and keeps the statuses of issues SonarQube imported from Ruff. The curated
  SonarQube-rule-to-Ruff-rule mappings ship pending review: until a maintainer reviews a mapping,
  it still imports issue statuses, but does not yet activate the rule in a `python` profile.
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
