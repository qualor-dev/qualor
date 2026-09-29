# Changelog

All notable changes to Qualor are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `restore` (the embedded database) no longer drops the database before the dump has loaded. It
  loads the dump into a new database and replaces the old one only on success; a truncated, empty or
  wrong file now fails with "the existing database was not changed" and the data stays as it was.

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
