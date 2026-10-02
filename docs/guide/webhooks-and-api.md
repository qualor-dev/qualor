# Webhooks and REST API

## Webhooks

**Settings → Webhooks** (org admins) creates a webhook with **New webhook**. Its **Applies to**
field is **All projects** or one project. A webhook for one project is also listed under
**Project → Settings → Webhooks**, where **New webhook** creates one for that project. Through the
API, send `projectId` to `POST /api/v0/webhooks` for a single project. You choose the events:

| Event | Sent when |
|---|---|
| `analysis.completed` | an analysis succeeded |
| `gate.status_changed` | a branch's gate status differs from its previous analysis. This includes the first analysis, and a change caused by an issue status change |

The payload is the analysis as `GET /api/v0/analyses/{id}` returns it: status, revision, gate status
and result, engines and warnings. It also carries `project` (`id`, `key`, `name`) and `branch` (`id`,
`kind`, `name`, `isMain`), and, for `gate.status_changed`, `previousGateStatus`.

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

- Qualor generates the secret (`whsec_…`) and shows it **once**, when the webhook is created. To replace
  it, press **Rotate secret** on the webhook (API: `POST /api/v0/webhooks/{id}/regenerate-secret`).
  The old secret stops signing at once, so update the receiver with the new one, which is shown
  once.
- Each attempt has 10 s to complete. A delivery gets 7 attempts with exponential backoff (1, 2, 4, 8,
  16, 32 minutes). Only a 2xx answer counts as success, and redirects are not followed.
- In the UI, each webhook shows its last 20 deliveries as a strip (delivered above the line, failed
  below it, pending on it) with the share delivered; **Recent deliveries** lists them with each one's
  status, response code and the first 1 KiB of the answer. Deliveries are kept 30 days. **Refresh**
  reloads the list. **Send again** on a delivery sends it once more (API:
  `POST /api/v0/webhooks/{id}/deliveries/{deliveryId}/redeliver`).
- Webhook URLs must be `https` and resolve to public addresses. To allow `http` or internal
  receivers (a chat bot on the intranet, say), an operator sets the instance setting in PostgreSQL:

  ```sql
  INSERT INTO instance_settings (key, value) VALUES ('webhooks', '{"allowInternalHosts": true, "allowHttp": false}')
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
  ```

Typical uses: post gate failures on `main` to Slack or Teams, open a ticket when the security rating
drops, or feed a dashboard.

### Audit event streaming (enterprise)

With a licence listing `audit-log` and `audit-log.stream` (the Enterprise plan), **Settings →
Audit settings** configures a separate stream, one per instance, that posts new audit events to
a SIEM as they are recorded. A delivery carries `X-Qualor-Event: audit.events` and the same
`X-Qualor-Timestamp` and `X-Qualor-Signature` headers as a webhook, verified the same way, but
with its own secret and its own URL; deduplicate on each event's own `seq`, since a batch can be
resent after a timeout. See [Roles and the audit log](./roles-and-audit.md#streaming-to-a-siem)
for the body, the retry schedule, what is never sent, and what happens on the Business plan.

## REST API

The API lives under `/api/v0`. It is JSON over HTTPS, described by OpenAPI 3.1 in
[`server/openapi.json`](../../server/openapi.json). Authenticate with
`Authorization: Bearer <token>`. Version 0 may still change between releases.

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
| Issues | `GET /issues`, `GET /issues/{id}`, `POST /issues/{id}/transition`, `POST /issues/bulk-transition`, `PATCH /issues/{id}` (severity), `GET /issues/{id}/changelog` |
| Rules, profiles, gates | `GET /rules`, `/quality-profiles…`, `/quality-gates…` (conditions, copy, set-default), `GET /metrics` |
| Users and organisations | `GET/POST/PATCH /users` (each user with `hasPassword` and `sso`; `GET /users?signIn=no-password`), `GET /users/lookup?username=`, `GET /organizations`, `…/members` (each with `managedBy`) |
| Sign-in | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /auth/methods` (public: the password policy, the single sign-on buttons and whether there is a demo), `POST /auth/demo` (public: signs in to the [read-only demo](./users-projects-tokens.md#a-public-read-only-demo)) |
| SCM | `GET/POST/PATCH/DELETE /scm-connections`, `POST /scm-connections/{id}/test` |
| Webhooks | `/webhooks…`, `/webhooks/{id}/deliveries`, `…/redeliver`, `…/regenerate-secret` |
| AI assistant | `POST /issues/{id}/ai/{explain,triage,fix}`, `GET /issues/{id}/ai`, `GET /ai-requests/{id}`, `POST /ai-requests/{id}/post`, `GET /organizations/{id}/ai`; instance admins: `GET/PUT /system/llm`, `POST /system/llm/test` ([AI assistant](./ai-assistant.md)) |
| Single sign-on (enterprise) | `/ee/sso/connections…`, `/ee/sso/settings`, `/ee/sso/me/identities`, `/ee/sso/users/{userId}/identities` ([below](#single-sign-on-and-scim-enterprise)) |
| SCIM (enterprise) | `GET/POST /ee/scim/tokens`, `DELETE /ee/scim/tokens/{id}`, and the SCIM 2.0 service under `/ee/scim/v2` ([below](#single-sign-on-and-scim-enterprise)) |
| Audit log (enterprise) | `GET /ee/audit/events`, `GET /ee/audit/export`, `GET /ee/audit/head`, `GET /ee/audit/verify`, `GET/PUT /ee/audit/settings`, `POST /ee/audit/settings/stream/{regenerate-secret,test}` ([Roles and the audit log](./roles-and-audit.md)). The two stream routes, and a `PUT` with a `stream` object, need `audit-log.stream` too (403 `FEATURE_NOT_LICENSED` without it; retention alone and `"stream": null` need only `audit-log`) |

Errors are `application/problem+json` with a stable `code`, such as `PROJECT_NOT_FOUND`,
`INSUFFICIENT_SCOPE`, `INVALID_TRANSITION` or `AI_QUOTA_EXCEEDED`. The API answers 404 for resources you cannot see, and 403
for resources you can see but not change. The 403 carries a code that says why.

`GET /auth/me` and every project answer (`GET /projects`, `GET /projects/{id}`,
`GET /projects/by-key`) carry the caller's effective `permissions` for that organisation or
project, so a script can tell what it may do without trying it first. `/auth/me` also lists the
caller's own `projectGrants` across every organisation, at most 1 000 of them.

Example: mark issues as false positives in bulk:

```sh
q -X POST "$QUALOR_URL/api/v0/issues/bulk-transition" \
  -d '{"ids":["<issue id>","<issue id>"],"to":"false_positive","comment":"Generated code, see ADR-12"}'
```

### Single sign-on and SCIM (enterprise)

With a licence listing `sso` (and `sso.multi` for several enabled connections, `scim` for SCIM:
both in the Enterprise plan only), instance admins manage single sign-on through these
endpoints, below `/api/v0`, with a session or a personal token with the **Admin** scope
([Single sign-on and SCIM](./sso-and-scim.md)). Secrets are write-only: an answer says only
whether one is set (`clientSecretSet`, `spKeySet`).

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
`/ee/sso/finish`) are for the browser and the IdP, not for scripts; so is Qualor's SAML metadata,
public at `/ee/sso/saml/{id}/metadata`. A failed one ends on the sign-in
page with `?sso_error=<code>` ([Troubleshooting](./troubleshooting.md#single-sign-on-and-scim)).

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
