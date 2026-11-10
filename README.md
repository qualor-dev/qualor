# Qualor

**Code quality, AI code review and dependency vulnerability tracking in one self-hosted server.**
One install, one UI and one set of users instead of SonarQube, an AI reviewer and Dependency-Track.
It is free, with no lines-of-code licence.

[Documentation](https://qualor.dev/docs) · [Live demo](https://review.qualor.dev) ·
[Docker Hub](https://hub.docker.com/u/qualor) ·
[GitLab CI/CD component](https://gitlab.com/qualor/qualor) ·
[GitHub Action](https://github.com/qualor-dev/scan-action)

<p align="center">
  <img src="docs/screenshots/overview.png" width="100%" alt="A project's overview in Qualor's dark theme: the quality gate that failed and the condition that failed it, the new-code measures, coverage, issues, duplication, lines of code and ratings with their trends, the history of open issues by severity, and the open issues by severity and software quality">
</p>

<table>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/screenshots/review-thread.png" alt="An AI review thread on a GitHub pull request: the finding that the last page of invoices is never exported, with a suggested change from page < pages to page <= pages">
      <br><sub><b>AI review</b> on a pull request, with a suggested change</sub>
    </td>
    <td width="50%" valign="top">
      <img src="docs/screenshots/issue-ai-review.png" alt="The same AI finding in Qualor: the flagged code, the review's explanation and its suggested change, marked as never counting in the quality gate">
      <br><sub><b>The finding in Qualor</b>, beside the analyzers' issues</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/screenshots/vulnerabilities-by-version.png" alt="A project's Vulnerabilities tab by version: the main branch and three released versions, each with its Critical, High and Medium counts, and the exploited vulnerabilities in v2.1.0 and v2.2.0">
      <br><sub><b>Vulnerabilities</b> of each branch and released version</sub>
    </td>
    <td width="50%" valign="top">
      <img src="docs/screenshots/vulnerabilities-by-vulnerability.png" alt="The same tab by vulnerability: Log4Shell and Spring4Shell first, as Critical and exploited, each with its fixed versions, exploit probability, the versions it is in and a Change status button">
      <br><sub><b>By vulnerability</b>, exploited ones first, with fixed versions</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/screenshots/issues.png" alt="A project's issues: filters by severity and status with counts, the severity distribution, and each issue with its rule, file and line">
      <br><sub><b>Issues</b>, filtered by severity, status, quality and rule</sub>
    </td>
    <td width="50%" valign="top">
      <img src="docs/screenshots/gate.png" alt="A quality gate's conditions, each edited in its row, and the form to add one">
      <br><sub><b>A quality gate</b> and its conditions</sub>
    </td>
  </tr>
</table>

The live demo is Qualor analysing its own code. Click **Explore the demo** on the sign-in page: no
account needed.

## What you get

| Part                                                      | What it does                                                                                                                        | Edition                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [Code quality and security](#code-quality-and-security)   | open-source analyzers and Qualor's own security rules, a quality gate on new code, coverage and duplication, merge request comments | Community                                                                   |
| [AI code review](#ai-review)                              | reviews of merge requests on your own model, with suggested changes; an AI assistant and an MCP server                              | Community; automatic fix suggestions: Enterprise                            |
| [Dependency vulnerabilities](#dependency-vulnerabilities) | main, chosen branches and releases re-checked against a fresh vulnerability database, with no new scan; triage with VEX reasons     | Community; exploited vulnerabilities, alerts, SBOM and VEX export: Business |

What each edition adds: [Editions](#editions).

## Quick start

You need Docker with Compose v2. Save the compose file from
[Install the server](docs/guide/install-server.md#the-compose-file) as `compose.yml` in an empty
directory, then:

```sh
umask 077
cat > .env <<EOF
QUALOR_VERSION=0.14
QUALOR_SECRET_KEY=$(openssl rand -hex 32)
QUALOR_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 16)
EOF
docker compose up -d
docker compose ps          # wait until the server is "healthy"
```

Open <http://127.0.0.1:8080>, sign in as `admin` with the password from `.env`, and change it. The
server is one container with its own PostgreSQL. For TLS, backups, upgrades and Kubernetes, see
[Install the server](docs/guide/install-server.md).

Then create a project and a CI token: see [Quick start](docs/guide/quick-start.md).

## Scan in CI

Set `QUALOR_URL` and `QUALOR_TOKEN` (masked) as CI variables. The scanner image is
`qualor/scanner:<tag>`, for example `0.14` or `0.14.1`.

**GitLab**, with the CI/CD component:

```yaml
include:
  - component: gitlab.com/qualor/qualor/qualor@<version>
    inputs: { image-tag: <tag> }
```

The job runs in merge request pipelines, on the default branch and on tags. On a tag it records a
[version](docs/guide/releases.md) of the release. It also writes GitLab's Code Quality report, which
works on every tier, and the SAST and Dependency Scanning reports, which GitLab shows on GitLab
Ultimate only. A self-managed GitLab needs its own copy of the component. See
[GitLab](docs/guide/gitlab.md).

**GitHub Actions**, with the Qualor Action:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
    persist-credentials: false
    ref: '${{ github.event.pull_request.head.sha || github.sha }}'
- uses: qualor-dev/scan-action@v0.14
  with:
    server-url: '${{ vars.QUALOR_URL }}'
    token: '${{ secrets.QUALOR_TOKEN }}'
```

See [GitHub](docs/guide/github.md) for the whole workflow and the GitHub App that posts check runs
and review comments.

**Other CI systems** run the scanner image with `qualor scan`: see
[Other CI systems](docs/guide/other-ci.md).

Run the scan from the repository root, in a full clone. An optional `qualor.yml` there configures
it; see the [configuration reference](docs/guide/configuration.md).

## Code quality and security

- **A quality gate on new code.** Issues, coverage, duplication and complexity are tracked across
  commits. The gate judges only what a change adds, and a failed gate fails the CI job.
- **The analyzers you already know**, pinned in one scanner image (see [Languages](#languages)).
- **Qualor's own security rules** for JavaScript, TypeScript, Python, Java, Go and C#. They follow
  request data into SQL, shell commands, file paths, templates, redirects and outgoing requests.
- **Merge request comments** on GitLab and GitHub: a summary, a thread on each new issue, and a
  commit status or check run.
- **SonarQube import**: quality gates, profiles and issue statuses
  ([Migrating from SonarQube](#migrating-from-sonarqube)).

See [Quality gates, profiles and issues](docs/guide/quality-gates.md).

### Languages

| Language               | Analyzers                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| JavaScript, TypeScript | ESLint, SonarQube-compatible rules (eslint-plugin-sonarjs), Qualor security rules            |
| Java                   | PMD, SpotBugs with FindSecBugs, Qualor security rules                                        |
| Kotlin                 | detekt                                                                                       |
| Swift                  | SwiftLint                                                                                    |
| C#                     | Roslyn, Roslynator, SonarQube-compatible rules (SonarAnalyzer.CSharp), Qualor security rules |
| Python                 | Ruff, Qualor security rules                                                                  |
| PHP                    | PHPStan                                                                                      |
| Ruby                   | RuboCop                                                                                      |
| Go                     | staticcheck, go vet, gosec, Qualor security rules                                            |
| C, C++                 | cppcheck; clang-tidy when your job has it                                                    |
| CSS, HTML              | stylelint, HTMLHint                                                                          |
| Every language         | OpenGrep, Gitleaks for secrets, Trivy for dependencies, any SARIF file                       |

Some analyzers need the project prepared first: installed `node_modules` for ESLint, compiled
classes for SpotBugs, downloaded Go modules. C# runs inside your own build with the
`qualor/scanner-dotnet` image. See [Languages and analyzers](docs/guide/languages-and-analyzers.md).

## AI review

A model reviews GitLab merge requests and GitHub pull requests on the projects you choose. It reads
the change and any file of the repository it needs, and it is told what the analyzers already
found.

- It comments in threads on the changed lines, with suggested changes a person applies in one
  click.
- It answers replies in its threads. A `qualor review` comment asks for a review.
- After a push, only new changes get new findings, and fixed findings close.
- AI findings never count in the quality gate. The model never approves and never commits.

Use any OpenAI-compatible endpoint, OpenAI's Responses API or the Anthropic Messages API, hosted
with your key or running locally. Secrets are masked before anything is sent, and with a local
model nothing leaves your network. See [AI review](docs/guide/ai-review.md).

The same model powers the [AI assistant](docs/guide/ai-assistant.md): it explains an issue,
suggests triage or suggests a fix, on a person's click. The [MCP server](docs/guide/mcp.md) lets
agents such as Claude Code and Cursor read the gate and the issues.

## Dependency vulnerabilities

Qualor keeps the dependency list of the main branch, chosen branches and released versions. The
server keeps its own copy of the Trivy vulnerability database up to date and re-checks those lists
against it. A vulnerability published after your last scan shows up without a new scan.

- **Releases.** A scan on a tag records a [version](docs/guide/releases.md) with its dependency
  list. By default the newest version of each of the last 5 major.minor lines is tracked.
- **The Vulnerabilities tab** shows each branch and version with its Critical, High and Medium
  counts and what is new, or one row per vulnerability with its fixed version.
- **Triage once.** **Change status** marks a vulnerability Not affected, with one of the five VEX
  reasons, or Affected, won't fix. The decision covers every branch and version of the project, and
  the matching Trivy issues.
- **Offline too.** The database comes from the official source, your mirror or an uploaded file.
  Scanners take it from the server.
- **Licences.** The **Dependencies** tab lists every package with its licences.

Business adds exploited vulnerabilities (CISA KEV) and exploit probability (FIRST EPSS), alerts by
email, webhook, Slack and Teams, SBOM and VEX export, and a licence policy that fails the gate. See
[Dependency vulnerabilities](docs/guide/dependency-vulnerabilities.md),
[The vulnerability database](docs/guide/vulnerability-database.md) and
[Dependency licences](docs/guide/dependency-licenses.md).

## Migrating from SonarQube

`qualor import sonarqube` copies the quality gates, quality profiles and issue statuses of a
SonarQube Server or SonarQube Cloud organisation. It only reads from SonarQube, and `--dry-run`
shows what would change. See [Migrating from SonarQube](docs/guide/migrate-from-sonarqube.md).

## Editions

The community edition is free, with no limit on lines of code, users or projects. The code is
MIT-licensed, and Qualor's security rules are source-available.

| Plan       | Adds                                                                                                                                                                         |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Business   | single sign-on, the audit log, the support bundle, exploited vulnerabilities and exploit probability, vulnerability alerts, SBOM and VEX export, a dependency licence policy |
| Enterprise | everything in Business, plus SCIM, audit log streaming, several identity providers, compliance and portfolio reports, automatic fix suggestions                              |

The code of the paid features lives in `enterprise/`, under the source-available Qualor Enterprise
Licence, and does nothing without a key. See [Enterprise](docs/guide/enterprise.md) and
[qualor.dev/enterprise](https://qualor.dev/enterprise).

## Documentation

The guide is in [docs/guide/](docs/guide/README.md), on [qualor.dev/docs](https://qualor.dev/docs),
and under **Docs** on every Qualor server. It also has [ready-made prompts](docs/guide/ai-prompts.md)
that let an AI agent roll Qualor out for you.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, commands and the DCO sign-off every commit needs.
Report vulnerabilities privately to security@qualor.dev, never in a public issue: see
[SECURITY.md](SECURITY.md).

## Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
