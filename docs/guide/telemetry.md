# Telemetry

The Qualor server sends anonymous usage statistics to the Qualor project once a day: how many
servers run, which versions, and which languages and features they use. They tell us what to work
on. While telemetry is on, the server also checks Docker Hub daily for a newer release. The scanner
(`qualor scan`) sends nothing.

## Turn it off

Set `QUALOR_TELEMETRY=false` and restart the server. This also turns off the
[update check](#update-check).

| Install | Where to set it |
| --- | --- |
| Docker Compose | `QUALOR_TELEMETRY=false` in `.env`, or in `environment` |
| `docker run` | `-e QUALOR_TELEMETRY=false` |
| Helm | `config.telemetry: false` |

At every start the server logs whether telemetry is on. When it is off, the line is:

```text
Telemetry: disabled
```

## When and where

About a minute after the server starts, and then every 24 hours, it sends one HTTPS `POST` to
`https://qualor.dev/api/telemetry`. It waits 5 seconds at most and never retries. If qualor.dev
cannot be reached (an offline network, a proxy), nothing else is affected.

## What is sent

The whole report, as an example:

```json
{
  "schema": 3,
  "installationId": "3f0c9a52-6d1e-4c8b-9f0a-2b7d1e5c4a91",
  "version": "0.13.0",
  "edition": "community",
  "platform": { "os": "linux", "arch": "x64", "node": "22.11.0", "runtime": "docker" },
  "database": "embedded",
  "counts": {
    "organizations": 1, "users": 4, "projects": 12, "branches": 30,
    "analyses30d": 310, "qualityGates": 2, "qualityProfiles": 5, "webhooks": 1
  },
  "languages": ["java", "typescript"],
  "engines": ["qualor", "semgrep"],
  "scm": ["gitlab"],
  "features": {
    "sso": false, "scim": false, "aiAssistant": true, "aiReview": true,
    "autoFix": true, "mcp": true, "chat": true, "email": true, "licensePolicy": true
  },
  "aiReview": {
    "organizations": 1, "projects": 3, "provider": "anthropic",
    "tiers": { "strong": true, "fast": false },
    "reviews30d": { "done": 41, "skipped": 6, "failed": 1, "superseded": 3 },
    "findings30d": 57, "inline30d": 38, "suggestions30d": 12,
    "replies30d": { "answered": 9, "statusChanges": 2 },
    "commands30d": { "review": 2, "fix": 0, "stop": 0 }
  },
  "assistant30d": { "explain": 14, "triage": 3, "fix": 5 },
  "autoFix30d": { "made": 21, "posted": 18 },
  "integrations": {
    "mcp": { "clients30d": 2, "users30d": 3 },
    "chat": { "slack": 2, "teams": 0, "withDigest": 1 },
    "email": {
      "sent30d": 40,
      "byKind": {
        "test": 1, "license.expiry": 0, "webhook.failed": 0,
        "account.password-reset": 2, "account.invitation": 3, "account.password-changed": 1,
        "notify.gate-failed": 25, "notify.gate-recovered": 6, "notify.analysis-failed": 2,
        "other": 0
      }
    }
  },
  "reports30d": { "complianceReady": 4, "complianceFailed": 0, "sonarImport": 1 },
  "licensePolicyOrgs": 1,
  "mergeRequests30d": { "gitlab": 120, "github": 0 },
  "ci": { "gitlab": 300, "github": 0, "other": 10 }
}
```

| Field | Meaning |
| --- | --- |
| `installationId` | a random id the server creates on its first report and keeps. It is not derived from your licence, organisations or host |
| `version` | the server's version |
| `edition` | `community` or `enterprise` |
| `platform` | the operating system, CPU architecture and Node.js version, and whether the server runs from the Docker image, on Kubernetes or as plain Node.js |
| `database` | `embedded` (the image's own PostgreSQL) or `external` (`DATABASE_URL`) |
| `counts` | how many organisations, users, projects, branches, quality gates, quality profiles and webhooks exist, and the analyses of the last 30 days |
| `languages` | the languages of the analysed files |
| `engines` | the built-in analyzers that ran successfully in the last 30 days, and `external` when a SARIF report from another tool was imported |
| `scm` | `gitlab` and/or `github`, when a connection exists |
| `features` | whether single sign-on, SCIM, the AI assistant, AI review, automatic fix suggestions, MCP, chat notifications, e-mail and a dependency licence policy are set up or in use |
| `aiReview` | how AI review is used, in counts and flags only: see the next table |
| `autoFix30d` | the automatic fix suggestions made in the last 30 days, and those posted to the merge request |
| `integrations` | MCP, chat and e-mail use: see the next table |
| `reports30d` | the compliance exports that finished (`complianceReady`) or failed in the last 30 days, and the SonarQube status imports (counted from audit events, so it reads low once old events are purged) |
| `licensePolicyOrgs` | how many organisations have a dependency licence policy. Never the licences in it |
| `mergeRequests30d` | the analyses of merge requests (GitLab) and pull requests (GitHub) in the last 30 days |
| `ci` | the analyses of the last 30 days that ran in GitLab CI, in GitHub Actions or elsewhere |
| `assistant30d` | the Explain, Suggest triage and Suggest a fix requests people made in the last 30 days. Automatic fix suggestions are not counted |

| `aiReview` field | Meaning |
| --- | --- |
| `organizations`, `projects` | the organisations that have AI review on, and the projects it reviews |
| `provider` | the kind of model provider: `anthropic`, `openai_chat_completions`, `openai_responses` or `none`. Never its address or its models |
| `tiers` | whether a strong and a fast model are set |
| `reviews30d` | the reviews of the last 30 days by how they ended: done, skipped, failed, or superseded by a newer push |
| `findings30d`, `inline30d`, `suggestions30d` | the findings raised in the last 30 days, those placed on a changed line, and those with a suggestion |
| `replies30d` | the replies answered in the last 30 days, and the status changes they made |
| `commands30d` | the `qualor review`, `qualor fix` and `qualor stop` commands handled in the last 30 days |

| `integrations` field | Meaning |
| --- | --- |
| `mcp` | the MCP clients with an active grant that were used in the last 30 days, and the people behind them. Never a client's name or address |
| `chat` | the active Slack and Teams notifications, and how many of them got a weekly digest in the last 4 weeks. Never a webhook address or time zone |
| `email` | the mails sent in the last 30 days, in total and by kind (`other` for any kind not listed). Never an address, subject or text |

Servers before 0.13.0 send `schema` 1 or 2, without the fields of the last two tables. Servers
before 0.12.0 send `schema` 1, without `aiReview`, `assistant30d` and the `aiReview` flag of
`features`. A newer server also sends `schema` 2 on a day it cannot count its feature use, and
`schema` 1 on a day it cannot count its AI use. It leaves the fields out and never sends a zero in
their place.

## What is never sent

Names of users, organisations, projects, repositories or branches, email addresses, URLs and host
names, model names, the AI provider's address, MCP client names, mail addresses, subjects and
texts, webhook addresses, the digest time zone, licence policy lists, source code, file paths,
issues, prompts, model answers and review text, tokens, secrets and the licence key.

## Update check

While telemetry is on, the server asks Docker Hub (`hub.docker.com`) for the list of
`qualor/server` tags, about a minute after it starts and then every 24 hours. The request carries
nothing about your installation. Docker Hub sees the address it comes from, as for any request.

When a newer release exists, the server:

- logs `Qualor 0.9.0 is available (this server runs 0.8.0)` with a link to the release notes;
- shows instance admins a banner, which they can dismiss until the next release;
- shows the new version next to the current one in the user menu;
- tells the scanner, which logs it at the start of a scan ([`qualor scan`](./cli.md#qualor-scan)).

Behind a firewall or with your own registry mirror, the check fails quietly and nothing is shown.

## What happens on our side

qualor.dev stores one report per installation id and day, and keeps it for 24 months. The stored
report has no IP address. Like every request to qualor.dev, the address appears in the load
balancer's logs, which are deleted after 30 days. Only the Qualor project sees the data. See the
[privacy policy](https://qualor.dev/privacy).
