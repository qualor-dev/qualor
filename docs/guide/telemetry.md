# Telemetry

The Qualor server sends anonymous usage statistics to the Qualor project once a day. They tell us
how many servers run, which versions, and which languages and features people use, so we know
what to work on. The scanner (`qualor scan`) sends nothing.

## Turn it off

Set `QUALOR_TELEMETRY=false` and restart the server.

- Docker Compose: add `QUALOR_TELEMETRY=false` to the server's `environment` (or `.env`).
- `docker run`: `-e QUALOR_TELEMETRY=false`.
- Helm: `config.telemetry: false`.

At every start the server logs one line that says which it is:

```
Telemetry: disabled
```

## When and where

About a minute after the server starts, and then every 24 hours, the server sends one HTTPS
`POST` to `https://qualor.dev/api/telemetry`. It waits 5 seconds at most and never retries. When
it cannot reach qualor.dev (an offline network, a proxy), nothing else changes.

## What is sent

The whole report, as an example:

```json
{
  "schema": 1,
  "installationId": "3f0c9a52-6d1e-4c8b-9f0a-2b7d1e5c4a91",
  "version": "0.6.0",
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
  "features": { "sso": false, "scim": false, "aiAssistant": true }
}
```

| Field | Meaning |
|---|---|
| `installationId` | a random id the server creates on its first report and keeps. It is not derived from your licence, organisations or host |
| `version`, `edition` | the server's version, and `community` or `enterprise` |
| `platform` | operating system, CPU architecture, Node.js version, and whether it runs from the Docker image, on Kubernetes or as a plain Node.js process |
| `database` | `embedded` (the image's own PostgreSQL) or `external` (`DATABASE_URL`) |
| `counts` | how many organisations, users, projects, branches, quality gates, quality profiles and webhooks exist, and how many analyses ran in the last 30 days |
| `languages` | the languages of the analysed files |
| `engines` | the built-in analyzers that ran successfully in the last 30 days, and `external` when a SARIF report from another tool was imported |
| `scm` | `gitlab` and/or `github`, when a connection exists |
| `features` | whether single sign-on, SCIM and the AI assistant are set up |

## What is never sent

Names of users, organisations, projects, repositories or branches, email addresses, URLs and
host names, source code, file paths, issues, tokens, secrets and the licence key.

## What happens on our side

qualor.dev stores the report under the installation id, one per day, and keeps it for 24 months.
It keeps the report without the IP address it came from; like every request to qualor.dev, the
address appears in the load balancer's logs, which are deleted after 30 days. Only the Qualor
project sees the data. See also the [privacy policy](https://qualor.dev/privacy).
