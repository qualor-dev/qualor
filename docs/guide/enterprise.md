# Enterprise

Qualor Enterprise is the same `qualor/server` image with a licence key. Without a key the server
is the community edition: MIT, with no limit on users, projects, organisations or lines of code.
A licence key switches on enterprise features only; it never limits how many organisations,
users or projects you have. With a valid key the server becomes the enterprise edition. Nothing
is installed or downloaded, and the key is checked on your server: Qualor never calls home, so it
works in air-gapped networks.

## What a licence adds

| | Community | Business | Enterprise |
|---|---|---|---|
| Roles (Organization admin, Project admin, Maintainer, Viewer) and roles on a single project | yes | yes, the same ([Roles and the audit log](./roles-and-audit.md)) | yes, the same |
| AI fix suggestions | at most 25 per organisation per day | up to your own budget (**Settings → AI assistant**), feature `llm.fix-quota` | the same as Business |
| The audit log, with its JSON Lines export | no | yes, feature `audit-log` ([Roles and the audit log](./roles-and-audit.md#the-audit-log-enterprise-audit-log)) | yes |
| Streaming the audit log to a SIEM | no | no | yes, feature `audit-log.stream` ([Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem)) |
| Single sign-on (OIDC, SAML 2.0) | no | one connection at a time, feature `sso` ([Single sign-on and SCIM](./sso-and-scim.md)) | yes |
| Several identity providers at once (up to 10 connections) | no | no | yes, feature `sso.multi` ([One connection or several](./sso-and-scim.md#one-connection-or-several)) |
| SCIM 2.0 provisioning | no | no | yes, feature `scim` ([SCIM](./sso-and-scim.md#scim-with-entra-id-and-okta)) |
| Portfolio reports, compliance exports | no | no | **not yet**: they are being built and will switch on with an Enterprise key |

A licence switches on the features its key lists, and nothing else. A Business key lists `sso`,
`audit-log` and `llm.fix-quota`; an Enterprise key lists those and `sso.multi`,
`audit-log.stream` and `scim` too. **Settings → Licence** lists the features the key has under
**Enterprise features**, each marked Active or Not active; `GET /api/v0/license` shows the same. Roles and
project access need no licence: they are part of every edition. Portfolio reports and compliance
exports are not available yet, in any edition.

Two features extend another and work only with it: `audit-log.stream` needs `audit-log`, and
`sso.multi` needs `sso`. A key that lists one without the other still loads, but the extension
stays off.

Keys issued before roles joined the community edition may list the feature `rbac`. They keep
working; the name `rbac` switches nothing on or off.

The audit log's export (**Settings → Audit log → Export JSON Lines**) is a plain download link, so
a refusal shows up only as a failed download in your browser, with no message on the page: 429
means another of your exports is still running (wait for it to finish), 403 means the licence has
lapsed (`audit-log` is no longer active — renew it), and 409 means the stored chain anchor is
damaged (an instance admin must repair it; the audit settings and chain head cards show the same
error with a plain-English explanation). See
[Troubleshooting](./troubleshooting.md#roles-and-the-audit-log).

The enterprise code ships inside the `qualor/server` image, in `/app/enterprise`. It is inert
without a key: the server does not even open the file. There is no separate image to pull and
nothing to switch when you buy a licence.

That code lives in the repository's [`enterprise/`](../../enterprise/) directory under its own
licence, [`enterprise/LICENSE`](../../enterprise/LICENSE). It is source-available, not open source:
you can read it, and copy and change it for development and testing, without a key. Running,
mirroring or redistributing the `qualor/server` image with no key configured needs no
subscription: the enterprise code is not in use then. Using the enterprise features in production
needs a subscription. Everything outside `enterprise/` is MIT.

## Plans and prices

| Plan | Price | What you get |
|---|---|---|
| Community | free | the community edition (MIT), with no limit on lines of code, users, projects or organisations, including all four roles and project access; no licence key; help from the community |
| Business | $4,900 a year | single sign-on (OIDC, SAML 2.0) with one enabled connection at a time, the audit log with its JSON Lines export, and the higher AI fix suggestion limit; email support |
| Enterprise | $12,000 a year | everything in Business, plus SCIM 2.0 provisioning, streaming the audit log to a SIEM, several identity providers at once (up to 10 connections), and portfolio reports and compliance exports once they ship; SLA support: email only, first reply within 1 business day for critical issues, no phone or 24x7 |

Prices are per server instance, per year, in US dollars. They never depend on lines of code or
on the number of users. A plan is the set of features its licence key lists (see
[What a licence adds](#what-a-licence-adds)); both plans use the same kind of key. Two- and
three-year terms and early customers get a discount on request.

Moving from SonarQube needs no plan: `qualor import sonarqube` is free, in every edition
([Migrate from SonarQube](./migrate-from-sonarqube.md)).

## Buy a licence

To buy a licence key, or to ask for a quote first, tell us the plan through the form on
[qualor.dev/enterprise](https://qualor.dev/enterprise#contact) or through
[qualor.dev/contact](https://qualor.dev/contact). We reply by email.

## Apply a key

A key is one line of text that starts with `QLK1.`. Give it to the server in one of three ways.
When more than one is present, the server uses the first of this list:

1. **`QUALOR_LICENSE`**, an environment variable holding the key. In the `compose.yml` of
   [Install the server](./install-server.md#the-compose-file), add a line under
   `environment:`

   ```yaml
   services:
     server:
       environment:
         QUALOR_LICENSE: ${QUALOR_LICENSE:-}
   ```

   and put the key in your `.env` file (`QUALOR_LICENSE=QLK1.…`). With Helm, keep the key in a
   Secret and pass it with `extraEnv`:

   ```sh
   kubectl -n qualor create secret generic qualor-license --from-literal=license='QLK1.…'
   ```

   ```yaml
   extraEnv:
     - name: QUALOR_LICENSE
       valueFrom:
         secretKeyRef:
           name: qualor-license
           key: license
   ```

2. **`QUALOR_LICENSE_FILE`**, the absolute path of a file holding the key, for example a Docker
   secret:

   ```yaml
   services:
     server:
       environment:
         QUALOR_LICENSE_FILE: /run/secrets/qualor_license
       secrets:
         - qualor_license
   secrets:
     qualor_license:
       file: ./qualor-license.txt
   ```

   The file is read once, at start, and may be at most 16 KiB. The server runs as user 65532, so
   that user must be able to read it. Save it as UTF-8, with or without a byte-order mark. UTF-16
   with a byte-order mark works too: that is what Notepad's "Unicode" and PowerShell 5.1's `>`
   write.

3. **The web UI or the API.** An instance admin opens **Settings → Licence**, pastes the key and
   selects **Save** (or sends it to [`PUT /api/v0/license`](#the-licence-api)). The key is checked
   at once, and a key that is not valid is refused with the reason. A saved key is stored in the
   database, in the instance settings.

Set at most one of the two variables: with both, the server does not start and says
`set QUALOR_LICENSE or QUALOR_LICENSE_FILE, not both`. While a variable is set, **Settings →
Licence** shows the key's status and names the variable, but cannot change or remove the key.

### Restart to apply it

**A new key takes effect at the next start of the server**, whichever way you gave it. After you
save a key in the web UI, the page says "Saved. Restart the server to apply the new key." and shows
**Restart required.** until you restart. Then restart it:

```sh
docker compose up -d server                          # Docker Compose, after a change to .env or compose.yml
docker compose restart server                        # Docker Compose, after saving a key in the web UI
kubectl -n qualor rollout restart statefulset/qualor # Helm with the embedded database (the default)
kubectl -n qualor rollout restart deployment/qualor  # Helm with an external or bundled database
```

At start the server writes one line about the licence to its log, such as:

```json
{"level":30,"component":"licence","licence":"active","edition":"enterprise","source":"environment","expires":"2027-10-01T00:00:00.000Z","plugins":["qualor-enterprise"],"msg":"running as the enterprise edition"}
```

It says the state of the licence (`none`, `active`, `grace`, `expired` or `invalid`), the edition,
where the key came from, when it expires and which enterprise plugins loaded. It never contains the
key, the customer's name or the licence id, so you can ship your logs to another service.

A key that the server rejects never stops it. The server starts as the community edition and logs
`licence key rejected` at level error with a `reason` (see [Troubleshooting](./troubleshooting.md#the-licence)).
A typo in a key never takes Qualor down.

A `QUALOR_LICENSE_FILE` that the server cannot read **does** stop the start, because a secret that
is not mounted is a mistake in the deployment. The server exits with one of these messages, and
never prints the file's content:

```text
qualor-server: QUALOR_LICENSE_FILE: cannot read /run/secrets/qualor_license
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is not a file
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is larger than 16 KiB
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is not a text file in UTF-8 (or UTF-16 with a byte-order mark); save it as UTF-8
```

### Pasting a key

A key copied from an e-mail is often broken over several lines. That is fine: the server removes
spaces and line breaks before it checks a key, in every one of the three ways. The web UI also
removes invisible characters that some mail and chat programs add (non-breaking spaces, zero-width
spaces, byte-order marks). After you save a key, the page never shows it again.

## Check the licence

**Settings → Licence** (instance admins only) shows:

- the edition and the state in words, such as "active until 1 October 2027", or the reason a key
  was rejected;
- whom the licence is for, the licence id, and when it was issued and expires;
- the time left, as a meter: the days until the licence expires, or the days left of the grace
  period;
- each enterprise feature the key lists, marked Active or Not active, and the enterprise plugins,
  with any load error;
- where the key comes from: `QUALOR_LICENSE`, `QUALOR_LICENSE_FILE`, or saved in Qualor.

Unless a variable sets the key, the page also has a field to paste a key with **Save** and, once a
key is saved in Qualor, a **Remove** button, which asks first.

Every signed-in user can see the edition and the active features in `GET /api/v0/system/info`.
Users who are not instance admins see nothing else about the licence.

## When a licence expires

1. From 30 days before the expiry date, instance admins see a notice at the top of every page: "The
   Qualor licence expires on … Renew it to keep the enterprise features." It links to the licence
   page.
2. On the expiry date a **14-day grace period** starts. Everything keeps working, and the notice
   says when the enterprise features stop.
3. When the grace period ends, the server runs as the community edition, without a restart:
   - the AI assistant's fix suggestions are limited to 25 per organisation per day again. A higher
     fix budget you saved stays saved and applies again with a renewed key; until then you can keep
     it or lower it in **Settings → AI assistant**, but not raise it;
   - the audit log stops recording new events. Retention keeps removing old ones at the period last
     saved, and **Settings → Audit log**, **Settings → Audit settings** and every `/api/v0/ee/audit`
     route answer 403 `FEATURE_NOT_LICENSED` until a key listing `audit-log` is applied
     ([When the licence ends](./roles-and-audit.md#when-the-licence-ends)). A SIEM stream pauses,
     keeps its settings and catches up after the renewal;
   - roles and roles on a single project keep working exactly as before: they do not depend on a
     licence;
   - single sign-on stops: the sign-in page shows no single sign-on button, **every user with a
     password can sign in with it**, and users without a password wait until an instance admin
     sets one (which ends their sessions and revokes their personal tokens). SCIM requests are refused, so **deprovisioning stops**: deactivate leavers in
     **Settings → Users** until the renewal ([When the licence lapses](./sso-and-scim.md#when-the-licence-lapses));
   - **nothing is deleted and nothing becomes read-only.** Every organisation, project, issue,
     history and setting stays, and every organisation keeps working as before, with the community
     edition's features;
   - instance admins see a notice at the top of every page: "The Qualor licence has expired.
     Enterprise features are off: Qualor runs as the community edition until the licence is
     renewed. Nothing was deleted."
4. Apply a renewed key and restart: everything works as before, with all its data.

Removing a key, or replacing it with one that lists fewer features, has the same effect at the
next start, for the features the new key no longer lists.

**Moving from Enterprise to Business** (a Business key replacing an Enterprise one, or a key that
no longer lists `audit-log.stream`, `sso.multi` or `scim`) deletes nothing either:

- **the SIEM stream pauses.** Its URL, secret and position are kept, and events keep waiting in
  the audit log. With an Enterprise key again, the stream carries on from where it stopped and
  catches up; events that retention removed in between are counted as skipped
  ([Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem));
- **only one single sign-on connection signs people in**: the oldest enabled one. The other
  connections are kept, still enabled, with their linked accounts, mappings and SCIM tokens, but
  the sign-in page no longer shows them. To choose which one works, disable the others
  ([One connection or several](./sso-and-scim.md#one-connection-or-several)). With an Enterprise
  key again, every enabled connection works at once;
- **SCIM requests are refused**, so deprovisioning stops: deactivate leavers in **Settings →
  Users** ([When the licence lapses](./sso-and-scim.md#when-the-licence-lapses)).

Keys issued before the organisation limit was removed may still carry an `organizations` field.
They keep working, and the server ignores that field.

## The licence API

Instance admins can manage the key over the REST API, with a session or a personal token with the
Admin scope. The key text is never returned by any of these endpoints.

```sh
export QUALOR_URL=https://qualor.example.com
H="Authorization: Bearer $QUALOR_ADMIN_TOKEN"

curl -fsS -H "$H" "$QUALOR_URL/api/v0/license"                     # the status
curl -fsS -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$(tr -d '\r\n' < qualor-license.txt)\"}" "$QUALOR_URL/api/v0/license"  # save a key
curl -fsS -X DELETE -H "$H" "$QUALOR_URL/api/v0/license"           # remove the saved key
```

| Endpoint | What it does |
|---|---|
| `GET /api/v0/license` | the edition, the state (`none`, `invalid`, `active`, `grace` or `expired`), the reason a key was rejected, where the key comes from, the licence's customer, dates and features, the active features and the plugins, and `restartRequired` |
| `PUT /api/v0/license` `{"key": "QLK1.…"}` | checks the key and saves it. It answers with the status, with `restartRequired: true` until the next start |
| `DELETE /api/v0/license` | removes the saved key. The server runs as the community edition from the next start |

| Status and code | Meaning |
|---|---|
| 422 `LICENSE_INVALID` | the key was refused. The `reason` field gives the reason as a code: `malformed` (not a Qualor licence key: check that it was copied completely), `unknown-key` (signed with a key this version of Qualor does not accept), `bad-signature` (changed: the signature does not match), `bad-payload` (contents not valid), `revoked`, or `not-yet-valid`. `errors[0].message` says the same in English |
| 422 `LICENSE_EXPIRED` | the key is past its grace period: ask for a renewed one |
| 409 `LICENSE_MANAGED_BY_ENVIRONMENT` | the key comes from `QUALOR_LICENSE` or `QUALOR_LICENSE_FILE`. Change the variable and restart instead |
| 413 `BODY_TOO_LARGE` | the request body is larger than 17 KiB. A key is far smaller: check what you sent |
| 403 | you are not an instance admin, or the token lacks the Admin scope |

## Questions

- **Is the key tied to a server?** No. It works on any server of yours, including a test instance
  and a standby.
- **Does the key send anything anywhere?** No. It is checked offline, with a public key built into
  Qualor.
- **Several replicas?** Each replica reads the key when it starts. A key saved in the web UI is
  stored in the database, so all replicas use it after their next start.
- **What if the server's clock is wrong?** The expiry uses the server's clock. A key issued "in the
  future" by more than a day is refused as not valid yet: check the clock.
- **A key that is not valid yet?** The server checks the key once, when it starts. If it started
  more than a day before the key's issue date, it keeps running as the community edition: restart it after the
  issue date. Saving such a key in the web UI is refused the same way until then.
