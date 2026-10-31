# Qualor documentation

Qualor is static analysis and AI code review in one self-hosted server. It runs open-source
analyzers in your CI, tracks their issues across commits, measures coverage, duplication and
complexity, and applies a quality gate to **new code**. It comments on GitLab merge requests and
GitHub pull requests. There is no lines-of-code licence.

The analyzers are tools you already know, such as ESLint, PMD, SpotBugs, Ruff, staticcheck,
Gitleaks and Trivy, plus Qualor's own security rules and any tool that writes SARIF:
[Languages and analyzers](./languages-and-analyzers.md) lists them for each language.

A model of your choice, hosted or local, can review the same merge requests, in threads with
suggested changes. AI review is off by default in every edition, and its findings never count in the
quality gate.

This guide is in [`docs/guide/`](https://github.com/qualor-dev/qualor/tree/main/docs/guide) of the
repository and on [qualor.dev/docs](https://qualor.dev/docs). Every Qualor server also carries the
guide of its own release, under **Docs** in the top bar (`/docs`, for signed-in users).

## Pages

1. [Quick start](./quick-start.md): a server, a project and a first scan in about 15 minutes.
2. [Install the server](./install-server.md): Docker Compose or Helm, TLS, backups, upgrades and
   server settings.
3. [Users, projects and tokens](./users-projects-tokens.md): organisations, roles, projects and the
   tokens CI uses.
4. [GitLab](./gitlab.md): the CI/CD component, merge request comments and replies.
5. [GitHub](./github.md): the Actions workflow and the GitHub App for check runs and comments.
6. [Other CI systems and local scans](./other-ci.md): Jenkins, Bitbucket, any other CI, or a
   laptop.
7. [Languages and analyzers](./languages-and-analyzers.md): what runs for each language, plus
   secrets, dependencies, SARIF files and coverage.
8. [Dependency licences](./dependency-licenses.md): each project's dependencies and their licences,
   and a licence policy (Business and Enterprise).
9. [Releases and versions](./releases.md): a version for each release tag, with its dependencies,
   and which versions are tracked.
10. [Configuration reference](./configuration.md): `qualor.yml` and environment variables.
11. [Quality gates, profiles and issues](./quality-gates.md): metrics, new code, gates, profiles and
    issue statuses.
12. [AI assistant](./ai-assistant.md): explain an issue, suggest triage or a fix, with your own
    model.
13. [AI review](./ai-review.md): a model reviews merge requests and answers replies.
14. [Email](./email.md): the SMTP server, account emails, notifications and alerts.
15. [CLI reference](./cli.md): commands, options and exit codes.
16. [Migrating from SonarQube](./migrate-from-sonarqube.md): `qualor import sonarqube`.
17. [Webhooks and REST API](./webhooks-and-api.md): events, signatures and the main endpoints.
18. [Enterprise](./enterprise.md): what a licence key adds, and how to apply it.
19. [Roles and the audit log](./roles-and-audit.md): roles, project access and the audit log.
20. [Single sign-on and SCIM](./sso-and-scim.md): OIDC, SAML, group mapping and SCIM.
21. [Compliance reports](./compliance-reports.md): OWASP Top 10, CWE Top 25, OWASP ASVS and PCI DSS
    reports.
22. [Portfolio reports](./portfolio.md): every project's quality and trends in one view.
23. [Troubleshooting](./troubleshooting.md): common errors and their fixes.
24. [AI prompts](./ai-prompts.md): prompts that let an AI agent roll Qualor out.
25. [Telemetry](./telemetry.md): what the server sends, and how to turn it off.
26. [The support bundle](./support-bundle.md): one zip of diagnostics, without secrets, for a
    support request.
27. [MCP server for AI agents](./mcp.md): Claude Code, Cursor and other agents read the gate and
    the issues.
28. [Slack and Microsoft Teams](./chat-notifications.md): gate failures and a weekly security
    digest in a channel.
29. [The vulnerability database](./vulnerability-database.md): the server's copy of Trivy's
    database, its source, states and re-checks.
30. [Dependency vulnerabilities](./dependency-vulnerabilities.md): the Vulnerabilities tab, what is
    new, and triage with reasons.

## How Qualor works

```text
 CI job (qualor/scanner image)                         Qualor server (+ PostgreSQL)
 ┌──────────────────────────────────┐   gzip report    ┌────────────────────────────────┐
 │ qualor scan                      │ ───────────────▶ │ tracks issues across commits   │
 │  • runs the analyzers → SARIF    │                  │ classifies new vs. old code    │
 │  • metrics, duplication, coverage│ ◀─────────────── │ evaluates the quality gate     │
 │  • git diff against the baseline │   gate verdict   │ comments on the MR / PR        │
 └──────────────────────────────────┘   (exit code)    └────────────────────────────────┘
```

- The **scanner**, the `qualor` CLI in the `qualor/scanner` image, runs in your CI job. It runs the
  analyzers, computes metrics and works out which lines are new against the baseline. It uploads one
  compressed report and waits for the gate verdict. It exits with code 1 when the gate fails, which
  fails the pipeline.
- The **server**, the `qualor/server` image, stores the history in its own PostgreSQL or an external
  one. It applies your quality profiles and gates, serves the web UI and the REST API, sends
  webhooks, and comments on merge requests and pull requests.

## Where to get it

The images are on Docker Hub: [`qualor/server`](https://hub.docker.com/r/qualor/server),
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) and
[`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet). The GitLab CI/CD
component is [`gitlab.com/qualor/qualor`](https://gitlab.com/qualor/qualor), and the GitHub Action
is [`qualor-dev/scan-action`](https://github.com/qualor-dev/scan-action). You need nothing else from
the repository to run Qualor.

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project. It is
not affiliated with, sponsored by or endorsed by SonarSource. The names are used only to describe
compatibility and to compare features.
