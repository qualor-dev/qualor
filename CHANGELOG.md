# Changelog

All notable changes to Qualor are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
