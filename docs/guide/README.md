# Qualor documentation

Qualor is an open-source, self-hosted code quality platform. It is an alternative to SonarQube with
no lines-of-code licence. It runs open-source analyzers you already know: ESLint, PMD, SpotBugs,
Roslyn and Roslynator for C#, OpenGrep, Gitleaks and Trivy, plus SonarQube-compatible rules
(SonarAnalyzer.CSharp 9.32, eslint-plugin-sonarjs 2.0.4, LGPL-3.0) for C#, JavaScript and
TypeScript, or any tool that writes SARIF. It tracks their issues across commits and measures
coverage, duplication and complexity. It applies a quality gate to **new code**, and it comments on
GitLab merge requests and GitHub pull requests.

These pages cover installation, setup and day-to-day use. They are the same Markdown files that live in
[`docs/guide/`](https://github.com/qualor-dev/qualor/tree/main/docs/guide) of the repository and on
[qualor.dev/docs](https://qualor.dev/docs).

## Pages

1. [Quick start](./quick-start.md): a server, a project and a first scan in about 15 minutes.
2. [Install the server](./install-server.md): Docker Compose or Helm on Kubernetes, secrets, TLS,
   backups, upgrades and server settings.
3. [Users, projects and tokens](./users-projects-tokens.md): organisations, roles, projects, and the
   tokens CI uses.
4. [GitLab](./gitlab.md): the CI job or CI/CD component, and merge request comments with a commit
   status.
5. [GitHub](./github.md): the Actions workflow and a GitHub App for check runs, annotations and
   comments.
6. [Other CI systems and local scans](./other-ci.md): Jenkins, Bitbucket, TeamCity or a laptop.
7. [Languages and analyzers](./languages-and-analyzers.md): JavaScript, TypeScript, Java, C#,
   secrets, dependencies, external SARIF files and coverage.
8. [Configuration reference](./configuration.md): `qualor.yml`, environment variables and
   precedence.
9. [Quality gates, profiles and issues](./quality-gates.md): metrics, new code, gates, rule
   profiles and issue statuses.
10. [AI assistant](./ai-assistant.md): explain issues, suggest triage and fixes with your own
    model; off by default.
11. [CLI reference](./cli.md): commands, options and exit codes.
12. [Migrating from SonarQube](./migrate-from-sonarqube.md): `qualor import sonarqube`.
13. [Webhooks and REST API](./webhooks-and-api.md): events, signatures and the most useful
    endpoints.
14. [Enterprise](./enterprise.md): what a licence key adds, how to apply it, and what happens when
    it expires.
15. [Roles and the audit log](./roles-and-audit.md): the four roles and project-level access (every
    edition), and the security audit log with its export, verification and SIEM stream.
16. [Single sign-on and SCIM](./sso-and-scim.md): OIDC and SAML sign-in, group mapping,
    break-glass admins, and SCIM provisioning.
17. [Troubleshooting](./troubleshooting.md): what common errors mean and how to fix them.
18. [AI prompts](./ai-prompts.md): ready-made prompts that let an AI agent roll Qualor out in your
    company.

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

- The **scanner** (`qualor` CLI, shipped in the `qualor/scanner` image) runs in your CI job. It runs the
  analyzers, computes metrics, and works out which lines are new against the baseline. It uploads one
  compressed report, then waits for the gate verdict. It exits with code 1 when the gate fails, and
  that fails the pipeline.
- The **server** (`qualor/server` image: one container with its own PostgreSQL, or an external one)
  stores the history. It
  applies your quality profiles and gates, serves the web UI and the REST API, sends webhooks, and
  decorates merge requests and pull requests.
- Nothing calls home. Neither part sends telemetry. The server calls only the GitLab or GitHub you
  connect, the webhook URLs you configure and, if an instance admin configures them, the model
  provider of the [AI assistant](./ai-assistant.md) and the identity provider of
  [single sign-on](./sso-and-scim.md). The scanner calls only your server. The analyzers run
  offline.

## Where to get it

The images are on Docker Hub: [`qualor/server`](https://hub.docker.com/r/qualor/server),
[`qualor/scanner`](https://hub.docker.com/r/qualor/scanner) and
[`qualor/scanner-dotnet`](https://hub.docker.com/r/qualor/scanner-dotnet). The GitLab CI/CD component
is [`gitlab.com/qualor/qualor`](https://gitlab.com/qualor/qualor). You need nothing else from the
repository to run Qualor.

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project. It is not
affiliated with, sponsored by or endorsed by SonarSource. The names are used only to describe
compatibility and to compare features.
