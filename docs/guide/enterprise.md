# Enterprise

Qualor Enterprise is the same `qualor/server` image with a licence key. The key switches on
enterprise features and never limits organisations, users, projects or lines of code. The server
checks it offline, so it works in air-gapped networks. Without a key, the server is the MIT
community edition.

## What a licence adds

| Feature | Feature key | Community | Business | Enterprise |
|---|---|---|---|---|
| [Roles](./roles-and-audit.md) (Organization admin, Project admin, Maintainer, Viewer), also on a single project | none | yes | yes | yes |
| [The audit log](./roles-and-audit.md#the-audit-log-enterprise-audit-log), with its JSON Lines export | `audit-log` | no | yes | yes |
| [Streaming the audit log to a SIEM](./roles-and-audit.md#streaming-to-a-siem) | `audit-log.stream` | no | no | yes |
| [Single sign-on](./sso-and-scim.md) (OIDC, SAML 2.0) | `sso` | no | one connection at a time | yes |
| [Several identity providers at once](./sso-and-scim.md#one-connection-or-several), up to 10 connections | `sso.multi` | no | no | yes |
| [SCIM 2.0 provisioning](./sso-and-scim.md#scim-with-entra-id-and-okta) | `scim` | no | no | yes |
| [Compliance reports](./compliance-reports.md) (OWASP Top 10, CWE Top 25, OWASP ASVS, PCI DSS 6.2.4) as JSON, CSV and PDF | `compliance-export` | no | no | yes |
| [Portfolio reports](./portfolio.md): the quality of every project and organisation, with 12-week or 12-month trends and the projects that need attention, as CSV and PDF | `portfolio` | no | no | yes |
| [AI review](./ai-review.md) of merge requests: comments and suggested changes on GitLab and GitHub, on your own model | none | yes | yes | yes |
| [Automatic fix suggestions](./ai-assistant.md#automatic-fix-suggestions-enterprise) for the new findings of merge requests, posted without a click | `llm.auto-fix` | no | no | yes |
| [The support bundle](./support-bundle.md): one zip with versions, configuration without secrets, health and recent failures | `support-bundle` | no | yes | yes |
| [Dependency licences](./dependency-licenses.md): every project's dependencies and their licences, on the **Dependencies** tab | none | yes | yes | yes |
| [A licence policy](./dependency-licenses.md#the-licence-policy-business-and-enterprise): forbidden licences become issues and fail the gate | `license-policy` | no | yes | yes |

A key switches on the features it lists, and nothing else. Two features work only with the one
they extend: `audit-log.stream` needs `audit-log`, and `sso.multi` needs `sso`. A key that lists
an extension without its base still loads, but the extension stays off.

Older keys may list entries that no longer do anything. They keep working:

- the feature `rbac`: roles are in every edition;
- the feature `llm.fix-quota`: no edition limits AI fix suggestions. Your own **Fix suggestions per
  day** in **Settings → AI provider** is the only limit
  ([Budgets and limits](./ai-assistant.md#budgets-and-limits));
- an `organizations` field: the server ignores it.

The enterprise code ships inside the `qualor/server` image, in `/app/enterprise`. Without a key the
server does not even open it, so there is no separate image to pull when you buy a licence. Its
source is the repository's [`enterprise/`](../../enterprise/) directory, under its own licence,
[`enterprise/LICENSE`](../../enterprise/LICENSE). It is source-available, not open source:

- you may read it, and copy and change it for development and testing, without a key;
- running, mirroring or redistributing the `qualor/server` image with no key configured needs no
  subscription, because the enterprise code is not in use then;
- using the enterprise features in production needs a subscription or a trial key.

Everything outside `enterprise/` is MIT.

## Plans and prices

| Plan | Price | What you get | Support |
|---|---|---|---|
| Community | free, no key | the community edition (MIT), including all four roles and project access, with no limit on lines of code, users, projects or organisations | the community |
| Business | $4,900 a year | single sign-on (OIDC, SAML 2.0) with one enabled connection at a time, the audit log with its JSON Lines export, the support bundle and the dependency licence policy | email |
| Enterprise | $12,000 a year | everything in Business, plus SCIM 2.0 provisioning, streaming the audit log to a SIEM, several identity providers at once (up to 10 connections), compliance reports, portfolio reports and automatic fix suggestions | SLA: email only, first reply within 1 business day for critical issues; no phone, no 24x7 |

Prices are per server instance and year, in US dollars. They never depend on lines of code or on
the number of users. Both plans use the same kind of key: a plan is the set of features its key
lists. Two- and three-year terms and early customers get a discount on request.

Moving from SonarQube needs no plan: `qualor import sonarqube` is free in every edition
([Migrate from SonarQube](./migrate-from-sonarqube.md)).

## Buy a licence

To buy a key, or to ask for a quote first, name the plan in the form on
[qualor.dev/enterprise](https://qualor.dev/enterprise#contact) or on
[qualor.dev/contact](https://qualor.dev/contact). We reply by email.

### Try it first

An instance admin on the community edition can ask for a free 30-day trial of Business or
Enterprise. In **Settings → Licence**, select **Request a trial**. It opens
[qualor.dev/trial](https://qualor.dev/trial) in a new tab. Choose the plan and enter your company
and email address. We email you a trial key. A trial key may be used in production for its 30 days.
Trial keys need Qualor 0.14.0 or later, and older servers reject them.

When the key arrives, paste it as described below and restart the server. To buy a licence or
extend the trial, email license@qualor.dev.

## Apply a key

A key is one line of text that starts with `QLK1.`. Give it to the server in one of three ways. If
more than one is present, the server uses the first in this list:

1. **`QUALOR_LICENSE`**, an environment variable holding the key. In the `compose.yml` of
   [Install the server](./install-server.md#the-compose-file), add a line under `environment:` and
   put the key in `.env` as `QUALOR_LICENSE=QLK1.…`:

   ```yaml
   services:
     server:
       environment:
         QUALOR_LICENSE: ${QUALOR_LICENSE:-}
   ```

   With Helm, keep the key in a Secret and pass it with `extraEnv`:

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

2. **`QUALOR_LICENSE_FILE`**, the absolute path of a file holding the key, such as a Docker
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

   The server reads the file once, at start. It may be at most 16 KiB, and user 65532, which the
   server runs as, must be able to read it. Save it as UTF-8, with or without a byte-order mark,
   or as UTF-16 with a byte-order mark (what Notepad's "Unicode" and PowerShell 5.1's `>` write).

3. **The web UI or the API.** An instance admin pastes the key in **Settings → Licence** and
   selects **Save**, or sends it to [`PUT /api/v0/license`](#the-licence-api). The key is checked
   at once, and an invalid key is refused with the reason. A saved key is stored in the database,
   in the instance settings.

Set at most one of the two variables. With both, the server does not start and says
`set QUALOR_LICENSE or QUALOR_LICENSE_FILE, not both`. While a variable is set,
**Settings → Licence** shows the key's status and names the variable, but cannot change or remove
the key.

### Restart to apply it

**A new key takes effect at the next start of the server**, whichever way you gave it. After you
save a key in the web UI, the page says "Saved. Restart the server to apply the new key." and shows
**Restart required.** until you restart:

```sh
docker compose up -d server                          # Docker Compose, after a change to .env or compose.yml
docker compose restart server                        # Docker Compose, after saving a key in the web UI
kubectl -n qualor rollout restart statefulset/qualor # Helm with the embedded database (the default)
kubectl -n qualor rollout restart deployment/qualor  # Helm with an external or bundled database
```

At start the server logs one line about the licence, such as:

```json
{"level":30,"component":"licence","licence":"active","edition":"enterprise","source":"environment","expires":"2027-10-01T00:00:00.000Z","plugins":["qualor-enterprise"],"msg":"running as the enterprise edition"}
```

It gives the state of the licence (`none`, `active`, `grace`, `expired` or `invalid`), the
edition, where the key came from, when it expires and which enterprise plugins loaded. It never
contains the key, the customer's name or the licence id, so you can ship your logs to another
service.

A rejected key never stops the server. It starts as the community edition and logs
`licence key rejected` at level error, with a `reason`
([Troubleshooting](./troubleshooting.md#the-licence)).

A `QUALOR_LICENSE_FILE` that the server cannot read **does** stop it, because a secret that is not
mounted is a deployment mistake. The server exits with one of these messages and never prints the
file's content:

```text
qualor-server: QUALOR_LICENSE_FILE: cannot read /run/secrets/qualor_license
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is not a file
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is larger than 16 KiB
qualor-server: QUALOR_LICENSE_FILE: /run/secrets/qualor_license is not a text file in UTF-8 (or UTF-16 with a byte-order mark); save it as UTF-8
```

### Pasting a key

A key copied from an email is often broken over several lines. That is fine: the server removes
spaces and line breaks before it checks a key, whichever way you gave it. The web UI also removes
the invisible characters some mail and chat programs add (non-breaking spaces, zero-width spaces,
byte-order marks). After you save a key, the page never shows it again.

## Check the licence

**Settings → Licence** (instance admins only) shows:

- the edition and the state in words, such as "active until 1 October 2027", or why a key was
  rejected;
- whom the licence is for, the licence id, and when it was issued and expires;
- a meter of the days left until expiry, or of the grace period;
- each enterprise feature the key lists, marked Active or Not active, and the enterprise plugins,
  with any load error;
- where the key comes from: `QUALOR_LICENSE`, `QUALOR_LICENSE_FILE`, or saved in Qualor.

Unless a variable sets the key, the page also has a field to paste a key with **Save**. A key saved
in Qualor also gets a **Remove** button, which asks first.

Every signed-in user sees the edition and the active features in `GET /api/v0/system/info`. Only
instance admins see anything else about the licence.

## When a trial ends

A trial key has no grace period. Seven days before the end, instance admins see a banner on every
page with the days left and license@qualor.dev, which you can dismiss until the next day. They also
get an email 7 days and 1 day before the end and on the day it ends ([Email](./email.md)). On the
end date the server runs as the community edition at once, without a restart, and nothing is
deleted. Each feature then behaves as in the table below. To keep the features, apply a paid key
and restart.

## When a licence expires

1. From 30 days before the expiry date, instance admins see a notice at the top of every page: "The
   Qualor licence expires on … Renew it to keep the enterprise features." It links to the licence
   page. Instance admins also get an email 30, 7 and 1 day before ([Email](./email.md)).
2. On the expiry date a **14-day grace period** starts. Everything keeps working, and the notice
   says when the enterprise features stop. Instance admins get an email when it starts.
3. When the grace period ends, the server runs as the community edition, without a restart.
   **Nothing is deleted and nothing becomes read-only**: every organisation, project, issue,
   history and setting stays, with the community edition's features. Instance admins see a notice
   on every page, "The Qualor licence has expired. Enterprise features are off: Qualor runs as the
   community edition until the licence is renewed. Nothing was deleted.", and get an email.
4. Apply a renewed key and restart: everything works as before, with all its data.

After the grace period, or on the end date of a trial, each feature behaves like this:

| Feature | After the grace period or the trial |
|---|---|
| Roles, also on a single project | keep working exactly as before: they need no licence |
| [The audit log](./roles-and-audit.md#when-the-licence-ends) | stops recording new events. Retention keeps removing old ones at the period last saved. **Settings → Audit log**, **Settings → Audit settings** and every `/api/v0/ee/audit` route answer 403 `FEATURE_NOT_LICENSED` until a key listing `audit-log` is applied. A SIEM stream pauses, keeps its settings and catches up after the renewal |
| [Single sign-on](./sso-and-scim.md#when-the-licence-lapses) | stops. The sign-in page shows no single sign-on button, and **every user with a password can sign in with it**. Users without a password wait until an instance admin sets one, which ends their sessions and revokes their personal tokens |
| [SCIM](./sso-and-scim.md#when-the-licence-lapses) | requests are refused, so **deprovisioning stops**: deactivate leavers in **Settings → Users** until the renewal |
| [Compliance reports](./compliance-reports.md#retention) | kept, none deleted, back with the renewal. Until then the **Compliance** tab and **Settings → Compliance reports** are not shown, and every `/api/v0/ee/compliance` route answers 403 `FEATURE_NOT_LICENSED` |
| [Automatic fix suggestions](./ai-assistant.md#automatic-fix-suggestions-enterprise) | stop at once: nothing more is asked of the model or posted. The settings are kept |
| [The support bundle](./support-bundle.md#when-the-licence-lapses) | **Settings → Support** and the support bundle command stop working, and the download answers 403 `FEATURE_NOT_LICENSED`. Nothing is deleted |
| [Portfolio](./portfolio.md#when-the-licence-lapses) | leaves the top bar, and every `/api/v0/ee/portfolio` route answers 403 `FEATURE_NOT_LICENSED`. It keeps no data of its own, so nothing is lost |
| [The licence policy](./dependency-licenses.md#when-the-licence-lapses) | kept but no longer applied: analyses neither add nor close licence issues, and changing the policy answers 403 `FEATURE_NOT_LICENSED`. The **Dependencies** tab keeps working |

Removing a key, or replacing it with one that lists fewer features, has the same effect at the
next start, for the features the new key no longer lists.

**Moving from Enterprise to Business** (a Business key replacing an Enterprise one, or any key
that no longer lists `audit-log.stream`, `sso.multi`, `scim`, `compliance-export`, `portfolio` or
`llm.auto-fix`) deletes nothing either. SCIM, compliance reports, the portfolio and automatic fix
suggestions stop as in the table, and come back with an Enterprise key. A person can still ask for
a fix suggestion. Two features behave differently:

- **The SIEM stream pauses.** The audit log keeps recording, and the stream keeps its URL, secret
  and position. With an Enterprise key again, it catches up from where it stopped, and counts the
  events retention removed in between as skipped
  ([Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem)).
- **Only one single sign-on connection signs people in**: the oldest enabled one. The others stay
  enabled, with their linked accounts, mappings and SCIM tokens, but leave the sign-in page.
  Disable the others to choose which one works
  ([One connection or several](./sso-and-scim.md#one-connection-or-several)). With an Enterprise
  key again, every enabled connection works at once.

## The licence API

Instance admins manage the key over the REST API, with a session or a personal token with the
**Admin** scope. No endpoint ever returns the key text.

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
| 422 `LICENSE_EXPIRED` | the key is past its grace period: ask for a renewed one. For a trial key the `title` is `This trial key has expired.`: a trial has no grace period, so write to license@qualor.dev to buy a licence or extend the trial |
| 409 `LICENSE_MANAGED_BY_ENVIRONMENT` | the key comes from `QUALOR_LICENSE` or `QUALOR_LICENSE_FILE`. Change the variable and restart instead |
| 413 `BODY_TOO_LARGE` | the request body is larger than 17 KiB. A key is far smaller: check what you sent |
| 403 | you are not an instance admin, or the token lacks the Admin scope |

## Questions

- **Is the key tied to a server?** No. It works on any server of yours, including a test instance
  and a standby.
- **Does the key send anything anywhere?** No. It is checked offline, with a public key built into
  Qualor.
- **Several replicas?** Each replica reads the key when it starts. A key saved in the web UI is in
  the database, so every replica uses it after its next start.
- **What if the server's clock is wrong?** The expiry uses the server's clock. A key issued more
  than a day "in the future" is refused as not valid yet: check the clock.
- **A key that is not valid yet?** The server checks the key once, at start. If it started more
  than a day before the key's issue date, it keeps running as the community edition: restart it
  after the issue date. The web UI refuses such a key the same way until then.
