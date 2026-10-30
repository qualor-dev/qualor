# Roles and the audit log

Roles decide who can read, triage and administer each project. They are part of every edition and
need no licence. The audit log records security-relevant events in a chain that shows any change.
It needs a licence key listing `audit-log` (the Business and Enterprise plans). Streaming it to a
SIEM also needs `audit-log.stream`, which only the Enterprise plan lists
([Plans and prices](./enterprise.md#plans-and-prices)).

## Roles and project access (every edition)

### Roles

| Can do this | Organization admin | Project admin | Maintainer | Viewer |
|---|---|---|---|---|
| Read the project: code, issues, quality gate, quality profile, AI answers | ✓ | ✓ | ✓ | ✓ |
| Upload analyses, triage issues (change a status, override a severity), use the AI assistant | ✓ | ✓ | ✓ | |
| Change project settings (except its GitLab/GitHub mapping), manage its analysis tokens, delete branches and merge requests, run the SonarQube status import | ✓ | ✓ | | |
| Manage the organisation: members, project-level roles, projects, quality gates and profiles, webhooks, GitLab/GitHub connections and each project's mapping to a repository, the audit log (with `audit-log`) | ✓ | | | |
| Delete the project | ✓ | | | |
| Read and download compliance reports (with `compliance-export`): the project's, and the organisation's for a role in the organisation | ✓ | ✓ | ✓ | ✓ |
| Create a compliance report of the project (with `compliance-export`, permission `project.compliance.create`) | ✓ | ✓ | | |
| Create organisation compliance reports, delete any compliance report (with `compliance-export`, permission `org.compliance.manage`) | ✓ | | | |
| Switch automatic fix suggestions on for the organisation and set their threshold (with `llm.auto-fix`, permission `org.ai.manage`) | ✓ | | | |
| Switch [AI review](./ai-review.md) on for the organisation, choose its projects and set its budgets (permission `org.ai.manage`) | ✓ | | | |
| Opt one project out of automatic fix suggestions (with `llm.auto-fix`; part of changing project settings) | ✓ | ✓ | | |
| Read the project's dependencies and their licences (the **Dependencies** tab), and the organisation's licence policy | ✓ | ✓ | ✓ | ✓ |
| Set or remove the organisation's licence policy (with `license-policy`, permission `org.licenses.manage`) | ✓ | | | |

- In the API the roles are `admin` (Organization admin), `project_admin`, `member` (Maintainer)
  and `viewer`.
- **Instance admins** have every permission in every organisation, whatever their memberships.
- A role granted **in an organisation** applies to every project in it. A role granted **on a
  single project** (**Project → Access**) applies to that project only; Organization admin cannot
  be granted there.
- **A project role adds to the organisation role and never takes anything away.** An organisation
  Viewer who is Maintainer on one project can triage issues there, and stays read-only everywhere
  else.
- Someone with a role only on some projects, not in the organisation itself, sees the organisation
  read-only (its name, quality gates, quality profiles, rules and AI summary) and only those
  projects.
- **Mapping a project to a repository needs an Organization admin**, because the mapping decides
  which repository the organisation's GitLab or GitHub credentials act on. A Project admin can
  change the project's other settings, but a `PATCH /projects/<id>` that sets `scmConnectionId` or
  `scmProjectRef` answers 403 `FORBIDDEN` unless the caller is an Organization admin.
- Roles do not depend on a licence: a licence that expires, is removed or is replaced changes no
  role and no grant.

### Managing members

**Settings → Members** (Organization admins) lists the organisation's members and their roles.
To add someone, type their name: from two characters (one for an instance admin), the field
suggests active users who are not members yet, by the start of their user name or of a word of
their display name. Or type the whole user name and press **Add member**, which looks it up
(`GET /users/lookup`). Both requests need the same permission as the screen. You can change a
member's role to any of the four, or remove the member.

An organisation always keeps at least one Organization admin. Demoting or removing the last one
answers 409 `LAST_ADMIN`; an instance admin counts only if they hold that role in the
organisation. Make someone else Organization admin first.

**Project → Access** (Organization admins only; a Project admin cannot grant roles) does the same
for a role on one project. Its name field suggests active users the same way, members of the
organisation or not, and leaves out those who already have a role on the project
(`GET /users/search?excludeProject=`). A project takes at most **1 000** roles granted directly on
it; beyond that, `PUT` answers 409 `PROJECT_GRANT_LIMIT_REACHED`.

Both screens use the same API, with a personal token that has the **Admin** scope:

```sh
# organisation level (role: "admin", "project_admin", "member" or "viewer")
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}' "$QUALOR_URL/api/v0/organizations/<org id>/members/<user id>"

# one project only (role: "project_admin", "member" or "viewer")
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"member"}' "$QUALOR_URL/api/v0/projects/<project id>/members/<user id>"
```

`GET /api/v0/projects/<project id>/members` lists a project's grants, 50 at a time: pass the
`nextCursor` it returns as `?cursor=`. `DELETE /api/v0/projects/<project id>/members/<user id>`
removes one. A grant made by single sign-on's group sync becomes a manual one when you change it
by hand ([Group mappings and sync](./sso-and-scim.md#group-mappings-and-sync)).

`GET /auth/me` lists the caller's own organisation memberships, with their effective
`permissions`, and their `projectGrants` across every organisation: at most **1 000**, the first
by project key.

With `audit-log` licensed, every change of a role or a grant is recorded in the audit log
(`member.*` and `project_member.*`).

## The audit log (enterprise, `audit-log`)

With `audit-log` licensed, Qualor records the events below in order, each one chained to the one
before by its hash. An event cannot be inserted, changed or quietly removed without it showing.

### What is recorded

Each event has a raw name, such as `member.role_changed`. The **Actions** filter of
**Settings → Audit log** and the API's `action` parameter match it exactly, or as a prefix ending
in `.*` (for example `issue.*`).

- **Signing in and out:** a sign-in (with a password, to the
  [read-only demo](./users-projects-tokens.md#a-public-read-only-demo) as `demo`, or through single
  sign-on with the connection it used; one that only `QUALOR_FORCE_PASSWORD_SIGN_IN` allowed is
  marked `forced`); a failed attempt (see below; a correct password refused because only
  break-glass admins may use one has the reason `password_disabled`); a sign-out; a password
  change; a password reset link requested (`auth.password_reset_requested`, by `anonymous`, never
  with the name or address typed) and used (`auth.password_reset`); an invitation accepted
  (`auth.invitation_accepted`); and each start of the server with
  `QUALOR_FORCE_PASSWORD_SIGN_IN=true` (`auth.password_sign_in_forced`).
- **Single sign-on** (with `sso`, [Single sign-on and SCIM](./sso-and-scim.md)): a failed sign-in
  on an existing connection (`sso.sign_in_failed`, with the error code the person saw; a request
  naming no existing connection goes only to the server log); an account created at a first
  sign-in; an account linked (by verified email, by the person, or to its SCIM record) or
  unlinked; a connection created, changed (the names of the changed fields only) or deleted; a
  connection's group mappings replaced; and the password sign-in setting changed.
- **SCIM** (with `scim`): a SCIM token created or revoked; a user created, changed, deactivated,
  reactivated or deleted by the identity provider; a SCIM group created, changed or deleted. Each
  event names the token and the connection that made the change.
- **Users and personal tokens:** a user created (`invited` says whether by an invitation) or
  changed, an invitation sent or resent (`user.invited`) or revoked (`user.invitation_revoked`),
  and a personal token created or revoked.
- **MCP apps** ([MCP server](./mcp.md#for-administrators)): an app registered
  (`oauth.client_registered`), its access granted (`oauth.grant_created`) or ended
  (`oauth.grant_revoked`, with who ended it, or that a refresh token or authorization code was
  reused), and the MCP settings changed (`oauth.settings_changed`).
- **Organisations and their members:** an organisation created; a member added, its role changed,
  or removed; the same three for a role on a single project. Changes made by single sign-on's group
  sync are recorded the same way, by `system`, with `managedBy` naming the connection.
- **Projects:** created, changed or deleted; a quality profile assigned to it; a branch deleted; the
  vulnerability-monitoring settings changed; a version's tracking changed; a project's own
  analysis tokens created or revoked.
- **Quality gates and profiles:** created, changed, deleted, copied or made the default; a
  condition or a rule changed on one.
- **Issues:** a status change, one event per issue even in a bulk transition of 500; a severity
  override; one summary event for a `qualor import sonarqube` status import, never one per issue.
  A status changed by a reply in a merge request
  ([AI review](./ai-review.md#replies-and-commands)) is recorded by `system`, with no user.
- **Integrations:** a GitLab or GitHub connection created, changed or deleted; a webhook created,
  changed or deleted, its secret regenerated, or a delivery resent.
- **The licence:** a key uploaded or removed, never the key itself.
- **The AI assistant:** its settings changed (whether a key was set, removed or kept, never the
  key), a request sent to the provider, and a fix suggestion queued to post.
- **Automatic fix suggestions** (with `llm.auto-fix`,
  [Automatic fix suggestions](./ai-assistant.md#automatic-fix-suggestions-enterprise)): an
  organisation's settings changed (`organization.auto_fix_changed`, with the new on/off, minimum
  severity and maximum per analysis) and a project opting out or back in
  (`project.auto_fix_changed`). The requests and posts Qualor makes by itself are recorded as
  `ai.requested` and `ai.fix_posted` by `system`, with no user.
- **[AI review](./ai-review.md):** an organisation's settings changed
  (`organization.ai_review_changed`, with whether it is on, its scope, how many projects it lists,
  whether this change confirmed the warning, and the provider's host and model).
- **Email:** its settings changed (the names of the changed fields only, never the password), and a
  test message sent, with whether it was delivered.
- **The licence policy** (with `license-policy`, [Dependency licences](./dependency-licenses.md)):
  an organisation's policy set, changed or removed (`organization.license_policy_changed`, with the
  policy before and after).
- **The support bundle** (with `support-bundle`, [The support bundle](./support-bundle.md)): a
  download from **Settings → Support** (`support.bundle_downloaded`, with the size). The
  `support-bundle` command records nothing, since nobody is signed in.
- **The audit log itself:** its retention or SIEM stream settings changed, the stream's secret
  regenerated, an export, and retention's own removal of old events.
- **Compliance reports** (with `compliance-export`, [Compliance reports](./compliance-reports.md)):
  a report created (`compliance.report.created`), downloaded (`compliance.report.downloaded`, with
  the format and the report's SHA-256) or deleted by hand (`compliance.report.deleted`). Each
  event belongs to the report's organisation. Reports removed after their year are not recorded.

**A failed sign-in never stores the name that was typed.** Only when it matches an existing user
are that user's id and name stored, so a password typed into the user name field leaves nothing
behind.

**Never recorded:**

- any password, token or token hash, webhook or stream secret, SCM token, GitHub private key,
  licence key, the AI provider's key, session id, or password reset or invitation link;
- an OIDC client secret, a SAML service provider key, a SCIM token, an ID token, an access token,
  an authorization code, a SAML response or assertion, or what the identity provider says about a
  person at sign-in;
- a comment's text, or an AI prompt or answer;
- analysis uploads and their processing;
- reads, except an audit log export and a compliance report download (so neither the portfolio
  nor its downloads);
- refused requests, except sign-in attempts;
- issue changes Qualor makes itself: closing, reopening or mirroring during ingestion, and gate
  re-evaluations;
- GitHub's own webhook deliveries to Qualor;
- watching projects and notification settings, which are personal preferences.

A SCIM change of a user records the old and new user name, display name, email and external id,
as an admin's change of a user records its fields.

Each event also keeps the caller's **IP address and browser** (cut to 256 characters) for as long
as retention keeps the event. Your privacy notice may need to say so.

**Who can read it:** instance admins read and export every event, including instance-wide ones
(sign-ins, user and licence changes, single sign-on and SCIM, AI and audit settings). Organisation
admins read and export only their own organisation's events, in **Settings → Audit log**. Naming
another organisation, or one that does not exist, answers 404, as elsewhere in the API.

The **User name** filter of **Settings → Audit log** suggests active users as **Settings → Members**
does, or takes the whole user name. The API's `actorUserId` takes the user's id.

### Retention

**Settings → Audit settings** sets how long events are kept: from 30 days to 100 years (36 500
days), **365 days by default**. Once a day, the events older than that are removed. The removal
is itself recorded (`audit.pruned`, with what it removed), so the rest of the log stays one
unbroken, verifiable chain. A one-time backlog of more than 50 000 events is removed over several
days.

### Export and verification

**Settings → Audit log → Export JSON Lines** downloads the filtered period as JSON Lines: one event
per line, oldest first. The API does the same with a personal token that has the **Admin** scope,
which every `/api/v0/ee/audit` route needs:

```sh
curl -fsS -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" \
  "$QUALOR_URL/api/v0/ee/audit/export?from=2027-01-01T00:00:00Z&to=2027-02-01T00:00:00Z" > audit.jsonl
```

Each line carries its own hash and the previous line's hash. Anyone can check a file with this
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

- **An export is not a snapshot.** It streams events as it reads them. If retention removes events
  during a long export, they are missing from the file even though they fall inside the period you
  asked for. An export covers at most 366 days and retention runs once a day, so this is rare.
- **An interrupted download fails verification.** The script either fails on the cut-off line,
  which is not valid JSON, or reports fewer events than you expected. The audit log itself is not
  damaged: export the period again.
- **A refused export shows only as a failed download**, because the button is a plain download
  link. [Troubleshooting](./troubleshooting.md#roles-and-the-audit-log) says what each status
  means.
- **Exporting is itself recorded**, as `audit.exported`. An export scoped to one organisation
  belongs to that organisation, so its admins can see who exported its events. An unscoped export
  (instance admins only) is an instance-level event.
- **The response is `Cache-Control: no-store`**, so no proxy or browser keeps a copy of the audit
  log.
- **Settings → Audit log → Verify chain** (instance admins), or `GET /api/v0/ee/audit/verify`,
  checks the chain in the database: each event's hash and its link to the one before. It names the
  first event where the chain breaks. It checks the table as it is now; the script checks a file
  you keep.
- The **chain head** (`GET /api/v0/ee/audit/head`, or **Settings → Audit log**, instance admins)
  is the newest event's `seq` and hash. Note it outside Qualor now and then. A chain that still
  verifies but no longer continues from a head you noted means the newest events were removed,
  which the table alone cannot show. A SIEM receiver's own record, or an earlier export, shows it
  too.

### Streaming to a SIEM

Streaming needs the **Enterprise plan**: a key listing `audit-log.stream` as well as `audit-log`.

**Settings → Audit settings** configures one stream per instance: a URL, whether it is active, and
**Send test**. The stream starts at the chain head when it is first saved or its URL changes. The
receiver gets the events from then on, not the history before it: export that instead. Saving a
new stream generates a signing secret, shown **once**. The URL follows the rules of a webhook URL:
`https` and a public address, unless the instance allows otherwise
([Webhooks and REST API](./webhooks-and-api.md#webhooks)).

A delivery is a `POST` of up to 500 events, with `X-Qualor-Event: audit.events` and the timestamp
and signature headers of a webhook. Verify it the same way
([Webhooks and REST API](./webhooks-and-api.md#webhooks)). Each event in the batch carries its own
`seq`. **Deduplicate on that `seq`, not on the delivery id**, because a batch can be resent after a
timeout.

A failing receiver is retried with backoff, from 1 minute doubling up to an hour, until it accepts
a batch again. Nothing is lost unless retention removes the waiting events first. **Settings →
Audit settings** counts those under **Removed by retention before they were sent** (`skipped` in
the API). There is no syslog output: an HTTP receiver is the only way to stream events out live.

**On the Business plan** (a key listing `audit-log` without `audit-log.stream`), **Settings → Audit
settings** says that streaming needs the Enterprise plan. **Stream URL**, **Active**, **Send test**
and **Regenerate the secret** are disabled, and **Save** saves retention only. A stream kept from
before shows as paused under **Stream status**, where **Remove** deletes it. In the API, adding,
changing or testing a stream, or giving it a new secret, answers 403 `FEATURE_NOT_LICENSED` naming
`audit-log.stream`. A request that also changes retention saves neither, so save retention on its
own.

**When streaming stops and comes back.** When `audit-log.stream` goes (an Enterprise key replaced
by a Business one, or a lapse), the stream **pauses**. Nothing is sent, and its URL, secret,
**Active** setting and position are kept. Events are still recorded and wait in the audit log
(**Waiting to be sent** grows). When a key listing `audit-log.stream` is applied again, the stream
**catches up** from where it stopped. It sends the waiting events in order, up to 10 000 every 10
seconds, and counts those that retention removed meanwhile under **Removed by retention before
they were sent** (`skipped`), so your receiver sees the gap.

To skip the backlog instead, remove the stream and add it again once streaming is licensed. With
streaming licensed, empty **Stream URL** and **Save**; without it, press **Remove** under **Stream
status**. A new stream starts at the chain head, with a new secret to give the receiver.

### When the licence ends

When `audit-log` lapses, **recording stops**: no new event is written until a renewed key is
applied. The events already recorded stay, and **retention keeps removing old ones** at the period
last saved. Each removal is still recorded as `audit.pruned`, the one event written without the
feature. Until the renewal, **Settings → Audit log** and **Settings → Audit settings** are not
available, and every `/api/v0/ee/audit` route answers 403 `FEATURE_NOT_LICENSED`. The SIEM stream
pauses and carries on from where it stopped once the key is renewed, as
[above](#streaming-to-a-siem). Nothing is recorded while `audit-log` is off, so that period has
nothing to catch up.
