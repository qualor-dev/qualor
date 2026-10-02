# Roles and the audit log

This page covers two things:

- **Roles and project access**, in every edition, with no licence: the four roles, a role on a
  single project (**Project → Access**) and **Settings → Members**.
- **The audit log**, an enterprise feature: it needs a licence key listing `audit-log` (the
  Business and Enterprise plans). Streaming it to a SIEM needs `audit-log.stream` too, which only
  the Enterprise plan lists ([Enterprise](./enterprise.md#plans-and-prices)).

## Roles and project access (every edition)

### Roles

| Can do this | Organization admin | Project admin | Maintainer | Viewer |
|---|---|---|---|---|
| Read the project: code, issues, quality gate, quality profile, AI answers | ✓ | ✓ | ✓ | ✓ |
| Upload analyses, triage issues (change a status, override a severity), use the AI assistant | ✓ | ✓ | ✓ | |
| Change project settings (except its GitLab/GitHub mapping), manage its analysis tokens, delete branches and merge requests, run the SonarQube status import | ✓ | ✓ | | |
| Manage the organisation: members, project-level roles, projects, quality gates and profiles, webhooks, GitLab/GitHub connections and each project's mapping to a repository, the audit log (with `audit-log`) | ✓ | | | |
| Delete the project | ✓ | | | |

- In the API the roles are `admin` (Organization admin), `project_admin`, `member` (Maintainer)
  and `viewer`.
- **Instance admins** have every permission in every organisation, whatever their memberships.
- A role can be granted at **organisation level**, where it applies to every project in it, or on a
  **single project** (**Project → Access**), where it applies to that project only. Organization
  admin cannot be granted on a project. **A project role adds to the organisation role; it never
  takes anything away.** For example, an organisation Viewer who is also given Maintainer on one
  project can triage issues there, and stays read-only everywhere else.
- Someone who has a role only on some projects of an organisation, not in the organisation itself,
  sees that organisation read-only — its name, quality gates, quality profiles, rules and AI
  summary — and only the projects they were given a role on, nothing else in it.
- **Mapping a project to a repository needs an Organization admin.** A Project admin can change the
  project's other settings, but a `PATCH /projects/<id>` that sets `scmConnectionId` or
  `scmProjectRef` answers 403 `FORBIDDEN` unless the caller is an Organization admin: the mapping
  decides which repository the organisation's GitLab or GitHub credentials act on.
- A licence that expires, is removed or is replaced changes no role and no grant: roles do not
  depend on a licence.

### Managing members

**Settings → Members** (Organization admins) lists the organisation's members and their roles. Add
someone by their **exact** user name (looked up with `GET /users/lookup`, which needs the same
permission), change a role to any of the four, or remove a member. An organisation always keeps at
least one Organization admin: demoting or removing its last one answers 409 `LAST_ADMIN` (an
instance admin does not count unless they hold that role in the organisation). Make someone else
Organization admin first.

**Project → Access** (Organization admins only — a Project admin cannot grant roles) does the same
for a role on one project: give someone a role by exact user name, change it, or remove it. The tab
reminds you that organisation roles apply on top of these. A project accepts at most **1 000**
roles granted directly on it; beyond that, `PUT` answers 409 `PROJECT_GRANT_LIMIT_REACHED`.

Both screens use the same API, with a personal token that has the **Admin** scope:

```sh
# organisation level (role: "admin", "project_admin", "member" or "viewer")
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}' "$QUALOR_URL/api/v0/organizations/<org id>/members/<user id>"

# one project only (role: "project_admin", "member" or "viewer")
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"member"}' "$QUALOR_URL/api/v0/projects/<project id>/members/<user id>"
```

`GET /api/v0/projects/<project id>/members` lists a project's grants (50 at a time; pass the
`nextCursor` it returns as `?cursor=`), and
`DELETE /api/v0/projects/<project id>/members/<user id>` removes one. A grant that single
sign-on's group sync made becomes a manual one when you change it by hand ([Single sign-on and
SCIM](./sso-and-scim.md)).

`GET /auth/me` lists the caller's own organisation memberships (with their effective
`permissions`) and their own `projectGrants` across every organisation — at most **1 000** of
them, ordered by project key; someone who somehow holds more sees only the first 1 000.

With `audit-log` licensed, every change of a role or a grant is recorded in the audit log
(`member.*` and `project_member.*`). Without it, roles change the same way and nothing is recorded.

## The audit log (enterprise, `audit-log`)

With an `audit-log` licence, Qualor records a defined catalogue of security-relevant events, in
order, so they cannot be inserted, changed or quietly removed without it showing.

### What is recorded

Grouped in plain words (the raw name behind each group, such as `member.role_changed`, is what
**Settings → Audit log**'s Actions filter and the API's `action` parameter match, exactly or as a
prefix ending in `.*`, for example `issue.*`):

- **Signing in and out:** a sign-in (with a password, to the
  [read-only demo](./users-projects-tokens.md#a-public-read-only-demo) as `demo`, or through single
  sign-on with the connection it used; one that only `QUALOR_FORCE_PASSWORD_SIGN_IN` allowed is marked `forced`), a
  failed attempt (see below; a correct password refused because only break-glass admins may use
  one has the reason `password_disabled`), a sign-out, a password change, and each start of the
  server with `QUALOR_FORCE_PASSWORD_SIGN_IN=true` (`auth.password_sign_in_forced`).
- **Single sign-on** (with `sso`, [Single sign-on and SCIM](./sso-and-scim.md)): a failed single
  sign-on on an existing connection (`sso.sign_in_failed`, with the error code the person saw; a
  request naming no existing connection only goes to the server log), an account created at a
  first sign-in, an account linked (by verified email, by the person, or to its SCIM record) or
  unlinked, a connection created, changed (the names of the changed fields only) or deleted, a
  connection's group mappings replaced, and the password sign-in setting changed.
- **SCIM** (with `scim`): a SCIM token created or revoked; a user created, changed, deactivated,
  reactivated or deleted by the identity provider; a SCIM group created, changed or deleted. Each
  event names the token and the connection that made the change.
- **Users and personal tokens:** a user created or changed, a personal token created or revoked.
- **Organisations and their members:** an organisation created; a member added, its role changed,
  or removed; the same three for a role on a single project. Changes made by single
  sign-on's group sync are recorded the same way, by `system`, with `managedBy` naming the
  connection.
- **Projects:** created, changed, deleted; a quality profile assigned to it; a branch deleted; a
  project's own analysis tokens created or revoked.
- **Quality gates and profiles:** created, changed, deleted, copied, made the default; a
  condition or a rule changed on one.
- **Issues:** a status change — one event per issue, even for a bulk transition of 500 — a
  severity override, and one summary event for a `qualor import sonarqube` status import (never
  one per issue).
- **Integrations:** a GitLab or GitHub connection created, changed or deleted; a webhook created,
  changed, deleted, its secret regenerated, or a delivery resent.
- **The licence:** a key uploaded or removed (never the key itself).
- **The AI assistant:** its settings changed (whether a key was set, removed or kept — never the
  key), a request sent to the provider, a fix suggestion queued to post.
- **The audit log itself:** its retention or SIEM stream settings changed, the stream's secret
  regenerated, an export started, and retention's own removal of old events.

A **failed sign-in never stores the name that was typed** — only when it happens to match an
existing user's name is that user's id and name stored, so a person who mistypes their password
into the user name field leaves nothing behind.

**Never recorded:** any password, token, token hash, webhook or stream secret, SCM token, GitHub
private key, licence key, the AI provider's key, a session id, a comment's text, or an AI prompt or
answer; nor an OIDC client secret, a SAML service provider key, a SCIM token, an ID token, an access
token, an authorization code, a SAML response or assertion, or what the identity provider says
about a person at sign-in. A SCIM change of a user records the old and new user name, display name,
email and external id, as an admin's change of a user records its fields. Also not recorded:
analysis uploads and their processing, every *read* except an export, a refused request other
than a sign-in attempt, an issue change Qualor itself makes (closing, reopening or mirroring
during ingestion, a gate re-evaluation), and GitHub's own webhook deliveries to Qualor.

Each event also keeps the caller's **IP address and browser** (cut to 256 characters) for as long
as retention keeps the event — worth knowing for your own privacy notice.

**Who can read it:** instance admins read and export every event, including instance-wide ones
(sign-ins, user and licence changes, single sign-on and SCIM, AI and audit settings). Organisation
admins read and export only their own organisation's events, in **Settings → Audit log**; naming another organisation, or
one that does not exist, answers 404, the same as elsewhere in the API.

### Retention

**Settings → Audit settings** sets how long events are kept: from 30 days to 100 years (36 500
days), **365 days by default**. The oldest events past that period are removed once a day. The
removal is itself recorded (as `audit.pruned`, with what it removed) so the rest of the log stays
one unbroken, verifiable chain. A very large one-time backlog (past 50 000 events) is removed over
several days rather than all at once.

### Export and verification

**Settings → Audit log → Export JSON Lines** downloads the filtered period as JSON Lines (one
event per line, oldest first), or call the API directly with a personal token that has the
**Admin** scope (every `/api/v0/ee/audit` route needs it):

```sh
curl -fsS -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" \
  "$QUALOR_URL/api/v0/ee/audit/export?from=2027-01-01T00:00:00Z&to=2027-02-01T00:00:00Z" > audit.jsonl
```

Each line carries its own hash and the previous line's hash, so anyone can check it, with this
script:

```js
// verify-audit.mjs: node verify-audit.mjs audit.jsonl
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const canonical = (v) =>
  v === null || typeof v !== 'object'
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(canonical).join(',')}]`
      : `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;

let previous = null;
let n = 0;
for (const line of readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean)) {
  const { prevHash, hash, ...record } = JSON.parse(line);
  const expected = createHash('sha256').update(`qualor-audit-v1\n${prevHash}\n${canonical(record)}`).digest('hex');
  if (expected !== hash) throw new Error(`event ${record.seq}: the hash does not match its content`);
  if (previous && prevHash !== previous) console.warn(`event ${record.seq}: not linked to the line before (a filtered export, or a gap)`);
  previous = hash;
  n += 1;
}
console.log(`${n} events verified`);
```

A few things worth knowing:

- **An export is not a snapshot.** It streams events as it reads them; if retention removes events
  partway through a long export (an export covers at most 366 days, and retention runs once a day,
  so this is rare), those events are missing from the file even though they fall inside the period
  you asked for.
- **A truncated download shows up as a failure when you verify it.** If the download is
  interrupted — a lost connection, a closed browser tab — the file you are left with is
  incomplete. Verifying it either fails outright, because the cut-off line is not valid JSON, or
  reports fewer events than you expected; neither means the audit log itself is damaged. Export the
  period again.
- **Exporting is itself recorded**, as `audit.exported`. Scoped to one organisation, the event
  belongs to that organisation, so its own admins can see who exported its events; an unscoped
  export (instance admins only) is an instance-level event.
- **The response is `Cache-Control: no-store`**: no proxy or browser keeps a cached copy of the
  audit log.
- **Settings → Audit log → Verify chain** (instance admins), or `GET /api/v0/ee/audit/verify`,
  checks the chain in the database — each event's hash and its link to the one before — and names
  the first event where it breaks. It checks the table as it is now; the script above checks a
  file you keep.
- The **chain head** (`GET /api/v0/ee/audit/head`, or **Settings → Audit log**, instance admins)
  is the newest event's `seq` and hash. Note it somewhere outside Qualor now and then: a chain that
  still verifies but no longer continues from a head you noted earlier means the newest events
  were removed, which the table alone cannot show. The same is true of a SIEM receiver's own
  record, or an earlier export.

### Streaming to a SIEM

Streaming needs the **Enterprise plan**: a key listing `audit-log.stream` as well as `audit-log`.

**Settings → Audit settings** configures one stream per instance: a URL, whether it is active, and
**Send test**. The stream starts at the chain head when it is first saved or its URL changes: the
receiver gets the events from then on, not the history before it (export that instead). Saving a
new stream generates a signing secret, shown **once** — the same rules as a
webhook URL apply (`https`, a public address, unless the instance allows otherwise; see
[Webhooks and REST API](./webhooks-and-api.md#webhooks)).

A delivery is a `POST` of up to 500 events at once, with `X-Qualor-Event: audit.events` and the
same timestamp and signature headers as a webhook — verify it exactly the same way (see
[Webhooks and REST API](./webhooks-and-api.md#webhooks)). Each event in the batch carries its own
`seq`; **deduplicate on that `seq`, not on the delivery id**, because a batch can be resent after a
timeout.

A failing receiver is retried with backoff (1 minute, doubling up to an hour) until it accepts a
batch again; nothing is lost until retention removes the waiting events, which **Settings → Audit
settings** then counts under **Removed by retention before they were sent** (`skipped` in the
API). There is no syslog output: an HTTP receiver is the only way to
stream events out live.

**On the Business plan** (a key listing `audit-log` without `audit-log.stream`), **Settings →
Audit settings** shows the note "Streaming the audit log to a SIEM needs the Enterprise plan.",
with **Stream URL**, **Active**, **Send test** and **Regenerate the secret** disabled. **Save**
saves retention only. A stream kept from before is shown under **Stream status**, with the note
"The stream is paused"; press **Remove** there to delete it. In the API, a stream cannot be added,
changed, tested or given a new secret: those requests answer 403 `FEATURE_NOT_LICENSED` naming
`audit-log.stream`, and a request that also changes retention saves neither. Save retention on its
own.

**When streaming stops and comes back.** When `audit-log.stream` goes (an Enterprise key replaced
by a Business one, or a lapse), the stream **pauses**: nothing is sent, and its URL, secret,
**Active** setting and position are kept as they were. Events keep being recorded and wait in the
audit log (**Waiting to be sent** grows). When a key listing it is applied again, the stream
**catches up** from where it stopped: it sends the waiting events in order, up to 10 000 every
10 seconds, and counts the ones retention removed in the meantime under **Removed by retention
before they were sent** (`skipped`), so your receiver sees the gap. To skip the backlog instead,
remove the stream and add it again once streaming is licensed: with streaming licensed, empty the
**Stream URL** and **Save**; without it, press **Remove** under **Stream status**. A new stream
starts at the chain head, with a new secret to give the receiver.

### When the licence ends

When `audit-log` lapses, **recording stops**: no new event is written until a renewed key is
applied. The events already recorded stay, and **retention keeps removing old ones** at the period
last saved (each removal is still recorded as `audit.pruned`, the one event written without the
feature). Until the renewal, **Settings → Audit log** and **Settings → Audit settings** are not
available, and every `/api/v0/ee/audit` route answers 403 `FEATURE_NOT_LICENSED`. The SIEM stream
pauses, and carries on from where it stopped once the key is renewed, as
[above](#streaming-to-a-siem); nothing is recorded while `audit-log` is off, so there is nothing
of that period to catch up.
