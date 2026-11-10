# Webhooks and REST API

Webhooks tell your own systems when an analysis ends, a quality gate changes or new vulnerabilities
are found, for example to open a ticket or feed a dashboard. The REST API lets scripts read and
change what Qualor holds.

## Webhooks

Org admins create a webhook in **Settings → Webhooks** with **New webhook**. Its **Applies to**
field is **All projects** or one project. A webhook for one project is also listed under **Project →
Settings → Webhooks**, where **New webhook** creates one for that project. Through the API, send
`projectId` to `POST /api/v0/webhooks`. An organisation has at most 50 webhooks, counting project,
Slack and Teams webhooks.

The type **Generic (signed JSON)** posts JSON to a receiver of your own, as described below. The
types **Slack** and **Microsoft Teams** send formatted messages about the main branch's quality
gate, exploited vulnerabilities and a weekly security digest
([Slack and Microsoft Teams](./chat-notifications.md)). They have no secret and send no
`X-Qualor-*` headers.

A generic webhook sends the events you choose:

| Event | Sent when |
|---|---|
| `analysis.completed` | an analysis succeeded |
| `gate.status_changed` | a branch's gate status differs from its previous analysis. This includes the first analysis, and a change caused by an issue status change |
| `vulnerabilities.found` | once a day at 06:00 UTC, for each project with new High or Critical vulnerabilities in a tracked branch or version. Business and Enterprise (`vuln.alerts`) |

The payload of `analysis.completed` and `gate.status_changed` is the analysis as
`GET /api/v0/analyses/{id}` returns it: status, revision, gate status and result, engines and
warnings. It also carries `project` (`id`, `key`, `name`) and `branch` (`id`, `kind`, `name`,
`isMain`). For `gate.status_changed` it adds `previousGateStatus`. A tag scan sends no webhook, so
the payload's `version` is always `null` ([Releases and versions](./releases.md#the-api)).

The payload of `vulnerabilities.found` lists what the project's
[digest](./email.md#vulnerability-emails) lists, worst first:

```json
{
  "project": {
    "id": "0190f6b0-7a4e-7c3a-9b1d-2f6e8a1c4d55",
    "key": "acme/payments",
    "name": "Payments",
    "url": "https://qualor.example.com/projects/0190f6b0-7a4e-7c3a-9b1d-2f6e8a1c4d55/vulnerabilities"
  },
  "database": { "builtAt": "2026-11-09T18:12:04.000Z" },
  "vulnerabilities": [
    {
      "vulnerabilityId": "CVE-2026-1001",
      "severity": "critical",
      "title": "Remote code execution in axios",
      "packageName": "axios",
      "installedVersions": ["1.7.2"],
      "fixedVersion": "1.7.4",
      "exploited": { "dateAdded": "2026-10-30" },
      "targets": ["main", "2.3.4"]
    }
  ],
  "more": 0
}
```

| Field | Meaning |
|---|---|
| `project.url` | the project's Vulnerabilities tab, or `null` without `QUALOR_PUBLIC_URL` |
| `database.builtAt` | when the vulnerability database in use was built, or `null` without one |
| `vulnerabilities[].severity` | `critical` or `high` |
| `vulnerabilities[].exploited` | the CISA KEV entry, or `null` when it is not in KEV or the licence has no `vuln.priority` |
| `vulnerabilities[].targets` | the tracked branches and versions where it is new, main first |
| `more` | how many were left out: a payload lists at most 1 000 vulnerabilities |

A project with nothing new sends no delivery.

Every request is a `POST` with a JSON body and these headers:

| Header | Value |
|---|---|
| `X-Qualor-Event` | the event name |
| `X-Qualor-Delivery` | the delivery id. Deliveries are at-least-once, so deduplicate on it |
| `X-Qualor-Timestamp` | Unix seconds of this attempt |
| `X-Qualor-Signature` | `sha256=` + hex HMAC-SHA256 of `"<timestamp>.<raw body>"`, keyed with the webhook's secret |

Verify the signature over the **raw** body, and reject old timestamps:

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

function verify(rawBody, headers, secret, maxAgeSeconds = 300) {
  const ts = headers['x-qualor-timestamp'];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > maxAgeSeconds) return false;
  const expected = 'sha256=' + createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex');
  const given = String(headers['x-qualor-signature'] ?? '');
  return given.length === expected.length && timingSafeEqual(Buffer.from(given), Buffer.from(expected));
}
```

**The secret.** Qualor generates it (`whsec_…`) and shows it **once**, when the webhook is created.
Through the API you can send your own `secret` instead, 16 to 256 characters, to
`POST /api/v0/webhooks` or `PATCH /api/v0/webhooks/{id}`. Qualor then returns none. To have a new
one generated, press **Rotate secret** on the webhook (API:
`POST /api/v0/webhooks/{id}/regenerate-secret`). The old secret stops signing at once, so update the
receiver with the new one, which is also shown once.

**Delivery.** Each attempt has 10 s to complete. A delivery gets 7 attempts, with backoff of 1, 2,
4, 8, 16 and 32 minutes between them. Only a 2xx answer counts as success, and redirects are not
followed.

**Failures.** When a delivery gives up after its 7 attempts, instance administrators get an email
([Email](./email.md)), at most one a day for each webhook. Organisation administrators get the same
email for their organisation's webhooks, unless they turned it off in **Settings → Notifications**
([Email](./email.md#failing-webhooks-for-organisation-administrators)). A webhook that is switched
off alerts nobody.

**History.** Each webhook shows its last 20 deliveries as a strip, with the share delivered:
delivered above the line, failed below it, pending on it. **Recent deliveries** lists them with each
one's status, response code and the first 1 KiB of the answer. Deliveries are kept 30 days.
**Refresh** reloads the list. **Send again** sends a delivery once more (API:
`POST /api/v0/webhooks/{id}/deliveries/{deliveryId}/redeliver`).

**Receiver addresses.** Webhook URLs must be `https` and resolve to public addresses. To allow
`http` or internal receivers, such as a chat bot on the intranet, an operator sets the instance
setting in PostgreSQL:

```sql
INSERT INTO instance_settings (key, value) VALUES ('webhooks', '{"allowInternalHosts": true, "allowHttp": false}')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
```

### Audit event streaming (enterprise)

With a licence that lists `audit-log` and `audit-log.stream` (the Enterprise plan), **Settings →
Audit settings** configures a stream that posts new audit events to a SIEM as they are recorded.
There is one stream per instance, with its own URL and its own secret. A delivery carries
`X-Qualor-Event: audit.events` and the same `X-Qualor-Timestamp` and `X-Qualor-Signature` headers as
a webhook, verified the same way. A batch can be sent again after a timeout, so deduplicate on each
event's `seq`. The body, the retries, what is never sent and the Business plan's behaviour are in
[Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem).

## REST API

The API lives under `/api/v0`. It is JSON over HTTPS, described by OpenAPI 3.1 in
[`server/openapi.json`](../../server/openapi.json). Authenticate with
`Authorization: Bearer <token>`. Version 0 can change between releases.

The [MCP server](./mcp.md) and its OAuth sign-in endpoints (`/mcp`, `/oauth/*` and `/.well-known/*`)
are outside `/api/v0`. Their tokens belong to the app a person allowed and work only on `/mcp`. They
are not API tokens, and an API token does not work on `/mcp`.

```sh
export QUALOR_URL=https://qualor.example.com QUALOR_TOKEN=qlr_pat_…
q() { curl -fsS -H "Authorization: Bearer $QUALOR_TOKEN" -H 'Content-Type: application/json' "$@"; }

q "$QUALOR_URL/api/v0/projects?q=payments"                        # find projects
q "$QUALOR_URL/api/v0/projects/by-key?key=acme/payments-api"      # one project, with its main branch
q "$QUALOR_URL/api/v0/projects/<id>/branches"                     # branches and MRs with gate status
q "$QUALOR_URL/api/v0/branches/<id>/measures?metrics=coverage,ncloc"
q "$QUALOR_URL/api/v0/issues?branchId=<id>&severity=blocker&severity=high&inNewCode=true"
```

| Area | Endpoints |
|---|---|
| System | `GET /healthz`, `GET /readyz`, `GET /api/v0/system/info` (version, edition, features), `GET /api/v0/system/version` (the version alone, for any token, project analysis tokens too); instance admins: `GET/PUT/DELETE /api/v0/license` ([Enterprise](./enterprise.md#the-licence-api)) |
| Projects | `GET/POST /projects`, `GET/PATCH/DELETE /projects/{id}`, `GET /projects/by-key`, `POST/GET/DELETE /projects/{id}/tokens`, `GET /projects/{id}/members` and `PUT/DELETE /projects/{id}/members/{userId}` (a role on one project, [Roles and the audit log](./roles-and-audit.md#managing-members)) |
| Branches and analyses | `GET /projects/{id}/branches`, `GET /branches/{id}/analyses`, `GET /analyses/{id}`, `DELETE /branches/{id}` |
| Measures | `GET /branches/{id}/measures`, `GET /branches/{id}/measures/history`, `GET /branches/{id}/files`, `GET /branches/{id}/file?path=` |
| Dependencies | `GET /projects/{id}/dependencies` (every edition): the dependencies of a branch or a version, and their licences. Takes `?branch=`, `?mr=` or `?version=`, filters and paging ([Dependency licences](./dependency-licenses.md#the-api)) |
| Versions | `GET /projects/{id}/versions`, `PATCH /projects/{id}/versions/{versionId}` (a version's `tracking`), `GET/PUT /projects/{id}/vulnerability-monitoring` (which branches and versions are tracked) ([Releases and versions](./releases.md#the-api)) |
| Vulnerabilities | `GET /projects/{id}/vulnerabilities/targets`, `GET /projects/{id}/vulnerabilities` (read access), `PUT /projects/{id}/vulnerability-decisions` (`issue.triage`; 422 `REASON_REQUIRED` or `COMMENT_REQUIRED`). `POST /issues/{id}/transition` and `POST /issues/bulk-transition` accept `reason` ([Dependency vulnerabilities](./dependency-vulnerabilities.md#the-api)) |
| SBOM and VEX (enterprise) | `GET /projects/sbom`, `GET /projects/vex`, addressed by `?projectKey=`; a project analysis token reads its own project ([below](#sbom-and-vex-export-enterprise)) |
| Issues | `GET /issues`, `GET /issues/{id}`, `POST /issues/{id}/transition`, `POST /issues/bulk-transition`, `PATCH /issues/{id}` (severity), `GET /issues/{id}/changelog` |
| Rules, profiles, gates | `GET /rules`, `/quality-profiles…`, `/quality-gates…` (conditions, copy, set-default), `GET /metrics` |
| Users and organisations | `GET/POST/PATCH /users` (each user with `hasPassword` and `sso`; `GET /users?signIn=no-password`), `GET /users/lookup?username=`, `GET /users/search?q=` ([below](#searching-users)), `GET /organizations`, `…/members` (each with `managedBy`; `?q=`, trimmed, keeps the active members that match, as `/users/search` does) |
| Sign-in | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /auth/methods` (public: the password policy, the single sign-on buttons and whether there is a demo), `POST /auth/demo` (public: signs in to the [read-only demo](./users-projects-tokens.md#a-public-read-only-demo)) |
| SCM | `GET/POST/PATCH/DELETE /scm-connections`, `POST /scm-connections/{id}/test`. A connection takes an optional write-only `webhookSecret` (16 to 256 printable ASCII characters; `null` removes it). A `gitlab` or `github` connection answers with `webhookSecretSet`, `webhookSecretReadable` and `webhookUrl`, the address of its webhook ([GitLab](./gitlab.md#answers-to-replies-and-commands-webhook), [GitHub](./github.md#turn-on-the-webhook-recommended)) |
| Webhooks | `/webhooks…`, `/webhooks/{id}/deliveries`, `…/redeliver`, `…/regenerate-secret`, `POST /webhooks/{id}/test` (Slack and Teams webhooks). A webhook has `kind` (`generic`, `slack` or `teams`, set when it is created), `timezone` (Slack and Teams) and `urlMasked` (`true` when `url` shows only the end of the real URL) |
| AI assistant | `POST /issues/{id}/ai/{explain,triage,fix}`, `GET /issues/{id}/ai`, `GET /ai-requests/{id}`, `POST /ai-requests/{id}/post`, `GET /organizations/{id}/ai`; instance admins: `GET/PUT /system/llm`, `POST /system/llm/test` ([AI assistant](./ai-assistant.md)) |
| AI review | `GET/PUT /organizations/{id}/ai/review` (organisation admins). The scanner uses `GET /projects/review-context` and `POST /analyses/{id}/review-snapshot`. A finding is an issue of the engine `ai` (`GET /issues?engine=ai`), and `GET /issues/{id}` gives it `aiReview`. Replies and commands have no API of their own ([AI review](./ai-review.md#api)) |
| Email (instance admins) | `GET/PUT /system/mail`, `POST /system/mail/test`, `GET /system/mail/messages` ([Email](./email.md)) |
| Automatic fix suggestions (enterprise) | `GET/PUT /organizations/{id}/ai/auto-fix` (organisation admins), `PUT /projects/{id}/ai/auto-fix` (project settings). The project object carries `autoFix`. Without `llm.auto-fix`: the organisation `GET` answers `available: false`, its `PUT` answers 403 `FEATURE_NOT_LICENSED` only when it would switch suggestions on, and the project `PUT` always answers 403 `FEATURE_NOT_LICENSED` ([Automatic fix suggestions](./ai-assistant.md#automatic-fix-suggestions-enterprise)) |
| Licence policy (business and enterprise) | `GET /organizations/{id}/license-policy` (anyone in the organisation: the policy, the licence groups and the SPDX ids), `PUT /organizations/{id}/license-policy` (organisation admins, `org.licenses.manage`; `"policy": null` removes it). Without `license-policy`, the `GET` answers `available: false` and the `PUT` 403 `FEATURE_NOT_LICENSED`. An unknown licence id gives 400 `INVALID_LICENSE_ID` ([Dependency licences](./dependency-licenses.md#the-api)) |
| Single sign-on (enterprise) | `/ee/sso/connections…`, `/ee/sso/settings`, `/ee/sso/me/identities`, `/ee/sso/users/{userId}/identities` ([below](#single-sign-on-and-scim-enterprise)) |
| SCIM (enterprise) | `GET/POST /ee/scim/tokens`, `DELETE /ee/scim/tokens/{id}`, and the SCIM 2.0 service under `/ee/scim/v2` ([below](#single-sign-on-and-scim-enterprise)) |
| Audit log (enterprise) | `GET /ee/audit/events`, `GET /ee/audit/export`, `GET /ee/audit/head`, `GET /ee/audit/verify`, `GET/PUT /ee/audit/settings`, `POST /ee/audit/settings/stream/{regenerate-secret,test}` ([Roles and the audit log](./roles-and-audit.md)). The two stream routes, and a `PUT` with a `stream` object, also need `audit-log.stream` (403 `FEATURE_NOT_LICENSED` without it). Retention alone and `"stream": null` need only `audit-log` |
| Compliance reports (enterprise) | `GET/POST /ee/compliance/reports`, `GET/DELETE /ee/compliance/reports/{id}`, `GET /ee/compliance/reports/{id}/download` (`?format=json`, `csv` or `pdf`) ([Compliance reports](./compliance-reports.md#the-api)) |
| Support bundle (business and enterprise) | `GET /ee/support/bundle`, for an instance admin. One bundle at a time: 429 `RATE_LIMITED` otherwise ([The support bundle](./support-bundle.md)) |
| Portfolio reports (enterprise) | `GET /ee/portfolio`, `GET /ee/portfolio/projects`, `GET /ee/portfolio/export` (`?format=csv` or `pdf`), each with `?scope=organization&organizationId=…` or `?scope=all` ([Portfolio reports](./portfolio.md#the-api)) |

Errors are `application/problem+json` with a stable `code`, such as `PROJECT_NOT_FOUND`,
`INSUFFICIENT_SCOPE`, `INVALID_TRANSITION` or `AI_QUOTA_EXCEEDED`. The API answers 404 for resources
you cannot see, and 403, with a code that says why, for resources you can see but not change.

`GET /auth/me` and every project answer (`GET /projects`, `GET /projects/{id}`,
`GET /projects/by-key`) carry the caller's effective `permissions` for that organisation or project,
so a script can tell what it may do without trying. `/auth/me` also lists the caller's own
`projectGrants` across every organisation, at most 1 000 of them.

Example: mark issues as false positives in bulk:

```sh
q -X POST "$QUALOR_URL/api/v0/issues/bulk-transition" \
  -d '{"ids":["<issue id>","<issue id>"],"to":"false_positive","comment":"Generated code, see ADR-12"}'
```

### SBOM and VEX export (enterprise)

`GET /projects/sbom` and `GET /projects/vex` download a file for a branch or a version. They need
the `sbom` feature (403 `FEATURE_NOT_LICENSED` without it).

| Parameter | Meaning |
|---|---|
| `projectKey` | Required. The project's key, as the scanner uses it |
| `branch` | A branch name. A merge request is not a target |
| `version` | A version label. Give `branch` or `version`, not both (422); neither means the main branch |
| `format` | SBOM: `cyclonedx` (default) or `spdx`. VEX: `cyclonedx` (default) or `openvex` |

| Answer | Meaning |
|---|---|
| 200 | The file, as an attachment named `<key>-<target><suffix>` (`.cdx.json`, `.spdx.json`, `.vex.cdx.json` or `.openvex.json`). Never cached |
| 404 `PROJECT_NOT_FOUND` | No such project, or the caller cannot see it. The project token of another project gets it too |
| 404 `NOT_FOUND` | No such branch or version. For the SBOM, the target has no dependency inventory yet. For the VEX, vulnerability monitoring is off, or the target has not been checked yet |
| 403 | `FEATURE_NOT_LICENSED`, or `INSUFFICIENT_SCOPE` for a personal token without the `read` scope |

A project analysis token reads the SBOM and VEX of its own project and no other project's, so a
release job needs no personal token. A person needs read access to the project.

```sh
curl -fsS -G -H "Authorization: Bearer $QUALOR_PROJECT_TOKEN" -OJ \
  --data-urlencode "projectKey=acme/payments-api" --data-urlencode "version=$RELEASE_TAG" \
  --data-urlencode "format=spdx" "$QUALOR_URL/api/v0/projects/sbom"
curl -fsS -G -H "Authorization: Bearer $QUALOR_PROJECT_TOKEN" -OJ \
  --data-urlencode "projectKey=acme/payments-api" --data-urlencode "version=$RELEASE_TAG" \
  --data-urlencode "format=openvex" "$QUALOR_URL/api/v0/projects/vex"
```

### Searching users

`GET /users/search?q=` suggests people for the user name fields of the app. It answers active users
whose user name starts with `q`, or one of whose display name's words does, ignoring case, ordered
by user name. Each user has only `id`, `username` and `displayName`, never an email address.

| Parameter | Meaning |
|---|---|
| `q` | Spaces around it are trimmed. What is left needs at least 2 characters (1 for an instance admin; shorter answers 422), and at most 64 UTF-16 units (an emoji counts as 2). `%` and `_` match themselves |
| `limit` | the most users to answer: 1 to 10, 10 by default |
| `excludeOrganization=<id>` | leaves out the members of that organisation, which the caller must manage |
| `excludeProject=<id>` | leaves out the people with a role granted on that project, whose roles the caller must manage (Organization admin of its organisation) |

It needs what `GET /users/lookup` needs: a token with the **Admin** scope, of an instance admin or
of someone who manages the members of an organisation. An excluded organisation or project answers
403 when the caller can see it but not manage it, and 404 when they cannot see it. Each caller gets
60 searches a minute (429 `RATE_LIMITED` beyond that). `GET /users/lookup` has its own 30.

```sh
curl -fsS -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" \
  "$QUALOR_URL/api/v0/users/search?q=smi&excludeOrganization=<org id>"
```

### Single sign-on and SCIM (enterprise)

Instance admins manage single sign-on through these endpoints, below `/api/v0`, with a session or a
personal token with the **Admin** scope ([Single sign-on and SCIM](./sso-and-scim.md)). They need a
licence that lists `sso`. Several enabled connections need `sso.multi`, and SCIM needs `scim`: both
are in the Enterprise plan only. Secrets are write-only: an answer says only whether one is set
(`clientSecretSet`, `spKeySet`).

| Endpoint | What it does |
|---|---|
| `GET /auth/methods` | public: `password` (`everyone` or `break_glass_only`, as it applies now) and `providers`, the connections in effect with their `startUrl` (every enabled one with `sso.multi`, else the oldest enabled one), empty while `sso` is not licensed; and `demo`, whether the sign-in page offers the [read-only demo](./users-projects-tokens.md#a-public-read-only-demo) |
| `GET/POST /ee/sso/connections`, `GET/PATCH/DELETE /ee/sso/connections/{id}` | the connections (at most 10). An answer's `urls` holds the values to copy into the IdP, or `null` while `QUALOR_PUBLIC_URL` is unset; `inEffect` says whether the connection signs people in ([One connection or several](./sso-and-scim.md#one-connection-or-several)) |
| `POST /ee/sso/connections/{id}/test` | OIDC: reads discovery and the JWKS now, and lists the endpoints (the authorization endpoint the browser opens, and those Qualor will call); SAML: the certificates' fingerprints and expiry, and whether the SSO URL is allowed |
| `POST /ee/sso/connections/{id}/saml/metadata` | reads the IdP's metadata URL and answers what it holds, for review; saving is a `PATCH` |
| `GET/PUT /ee/sso/connections/{id}/mappings` | the group mappings; a `PUT` replaces the whole list (at most 500) |
| `GET/PUT /ee/sso/settings` | who may sign in with a password (`passwordSignIn`, `breakGlassUserIds`), and `forced` while `QUALOR_FORCE_PASSWORD_SIGN_IN` is set |
| `GET /ee/sso/users/{userId}/identities`, `DELETE …/{identityId}` | a user's linked accounts; unlink one, a SCIM one included |
| `GET /ee/sso/me/identities`, `DELETE …/{identityId}` | your own linked accounts (any signed-in user) |
| `POST /ee/sso/connections/{id}/link` | a browser session only: answers `{ url }`, the IdP page to open to link another account |
| `GET/POST /ee/scim/tokens`, `DELETE /ee/scim/tokens/{id}` | the SCIM tokens (feature `scim`). Create with `{ "connectionId", "name", "expiresAt"? }`; the answer's `token` is shown once |
| `/ee/scim/v2/…` | the SCIM 2.0 service (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Users`, `Groups`), authenticated with a SCIM token, not a Qualor token; its errors use the SCIM error format |

The browser flows (`/ee/sso/{id}/start`, `/ee/sso/oidc/{id}/callback`, `/ee/sso/saml/{id}/acs`,
`/ee/sso/finish`) and Qualor's public SAML metadata (`/ee/sso/saml/{id}/metadata`) are for the
browser and the IdP, not for scripts. A failed flow ends on the sign-in page with
`?sso_error=<code>` ([Troubleshooting](./troubleshooting.md#single-sign-on-and-scim)).

| Status and code | Meaning |
|---|---|
| 409 `PUBLIC_URL_REQUIRED` | enabling a connection needs `QUALOR_PUBLIC_URL` |
| 409 `SSO_CONNECTION_LIMIT_REACHED` | there are already 10 connections, in every plan |
| 409 `SSO_MULTI_NOT_LICENSED` | without `sso.multi` (the Business plan): a `POST` with `"enabled": true`, or a `PATCH` enabling a disabled connection, while another connection is enabled. Nothing is saved. Create it disabled, or disable the enabled one first |
| 409 `SSO_CONNECTION_NAME_TAKEN` | another connection has that name (case is ignored) |
| 409 `SCIM_TOKEN_LIMIT_REACHED` | the connection already has 5 active SCIM tokens: revoke one first |
| 409 `LAST_BREAK_GLASS_ADMIN` | `PATCH /users/{id}` would deactivate or demote the last break-glass admin while password sign-in is limited to them |
| 409 `LAST_SIGN_IN_METHOD` | unlinking would leave the user no way to sign in: an instance admin sets a password first (`PATCH /users/{id}`, which ends the user's sessions and revokes their personal tokens), and it counts only while password sign-in is allowed for that user |
| 409 `LAST_SSO_CONNECTION` | `PATCH` disabling, or `DELETE` deleting, the last enabled connection while password sign-in is limited to break-glass admins: set it back to everyone first (or, with `sso.multi`, enable another connection first) |
| 409 `SCIM_MANAGED_IDENTITY` | your own unlink of an account link the IdP provisions through SCIM: an instance admin may remove it |
| 503 `SSO_UNAVAILABLE` | a link could not start because the identity provider cannot be used now (its discovery or configuration failed): try again later |
| 403 `SESSION_REQUIRED` | linking needs a browser session, not a token |
| 403 `FEATURE_NOT_LICENSED` | the licence does not list `sso` (or `scim`, for the SCIM routes), or it lapsed |
| 422 `VALIDATION_FAILED` | a field is not valid; `errors[].path` names it, such as `body.oidc.issuer`, or `body.breakGlassUserIds` when "break-glass admins only" has no usable admin |

Example: list the sign-in methods (no token needed):

```sh
curl -fsS "$QUALOR_URL/api/v0/auth/methods"
```
