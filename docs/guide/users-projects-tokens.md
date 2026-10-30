# Users, projects and tokens

Organisations hold projects, people get roles in them, and CI uploads analyses with tokens.

## Organisations

An organisation is a tenant: it owns its projects, quality profiles, quality gates, webhooks and
GitLab/GitHub connections. The first start creates the organisation `default`, and most companies
need no other. Organisations, users, projects and lines of code are unlimited in every edition.

An instance admin creates more in **Settings → Organizations** with **New organization**
(`POST /api/v0/organizations`). The key, 2 to 64 lowercase letters, digits and hyphens, is what the
CLI and the audit log use. Neither the name nor the key can be changed later. You become the new
organisation's Organization admin, and the organisation switcher in the header lists it.

## Users and roles

These roles exist in every edition, without a licence:

| Role | Can |
|---|---|
| **Instance admin** | everything, including users and organisations |
| **Organization admin** (`admin`) | manage the organisation: projects, project tokens, quality profiles, gates, webhooks, GitLab/GitHub connections and each project's mapping to a repository, members and roles on single projects; with the Enterprise plan, create and delete compliance reports of the organisation and of its projects (`org.compliance.manage`) |
| **Project admin** (`project_admin`) | what a Maintainer can, and also change project settings (except the GitLab/GitHub mapping), manage project tokens, delete branches and merge requests, run the SonarQube status import, and, with the Enterprise plan, create compliance reports of the project (`project.compliance.create`) |
| **Maintainer** (`member`) | read the projects, upload analyses, triage issues (change a status, override a severity) and use the AI assistant |
| **Viewer** (`viewer`) | read the projects: code, issues, quality gate, quality profile and AI answers |

A role in an organisation applies to all its projects. An Organization admin can also give someone
Project admin, Maintainer or Viewer on a **single project**, in **Project → Access**. A project role
only adds to the organisation role. The full permission table is in
[Roles and the audit log](./roles-and-audit.md).

Instance admins manage users in **Settings → Users**: create or invite users, reset passwords,
deactivate users, and make or remove instance admins.

- Passwords have at least 12 characters, and sign-in is rate-limited.
- A user created with an initial password, and a user whose password was reset, must choose a new
  password at their next password sign-in. A single sign-on sign-in does not ask.
- **Reset password** on a user's row ends that user's sessions and revokes their personal tokens.
  CI jobs that use one of those tokens need a new one.
- An instance admin needs an email address to get Qualor's [alerts by email](./email.md), and
  everyone needs one to get [project notifications](./email.md#project-notifications). An instance
  admin sets it in **Settings → Users**.

Organization admins manage membership and roles in **Settings → Members**: add someone by name,
change their role, or remove them. An organisation always keeps at least one Organization admin:
demoting or removing the last one answers 409 `LAST_ADMIN`, so make someone else Organization admin
first. The same screen calls the API:

```sh
# role: "admin", "project_admin", "member" or "viewer"
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"member"}' "$QUALOR_URL/api/v0/organizations/<org id>/members/<user id>"
```

Roles on a single project use `/api/v0/projects/<project id>/members/<user id>` the same way
([Managing members](./roles-and-audit.md#managing-members)).

### Forgotten passwords and invitations

Both need Qualor to send email ([Email](./email.md#account-emails)) and `QUALOR_PUBLIC_URL` to be
set. Without them, an instance admin resets a forgotten password in **Settings → Users**.

**Forgot password?** on the sign-in page sends a one-time link to the account's email address,
valid for 60 minutes. The page answers the same whether or not an account matches.

- Only people who sign in with a password get a link: not single sign-on accounts without one, not
  the [demo account](#a-public-read-only-demo), and, while password sign-in is limited to
  break-glass admins, only those admins.
- The new password signs out every session of the account. Personal tokens keep working.
- Each IP address may ask 5 times a minute, and each name or email typed gets at most 3 requests in
  15 minutes.

**Invitations.** In **Settings → Users → New user**, choose **Send an invitation email** instead of
setting an initial password. The user needs an email address, and chooses a password through the
link, which works for 7 days.

- The list shows **Invited · expires …** or **Invitation expired**, with **Resend invitation** (the
  earlier link stops working) and **Revoke invitation**.
- **Resend invitation** is refused for a user who already has a password or a single sign-on
  identity.
- Setting a password for the user, changing their email address or deactivating them ends the
  invitation and any reset link. So does linking the account to single sign-on.

### A public, read-only demo

To let anyone look around a server without an account:

1. Create a user, for example `guest`, with a long password nobody needs to know.
2. Sign in as that user once and choose a new password. Do it before step 4: the demo stays off
   while the user must change its password, and the demo user cannot change it.
3. Give it the **Viewer** role in the organisations it may show.
4. Set `QUALOR_DEMO_USER=guest` ([Server settings](./install-server.md#server-settings)).

The sign-in page then shows **Explore the demo**, which signs the visitor in as that user without a
password. The visitor sees everything a Viewer of those organisations sees: the projects' code,
issues and AI answers already given. Give the demo user only organisations whose code may be
public.

- **Read-only, whatever happens.** The server refuses every change made as the demo user with 403
  `DEMO_READ_ONLY`, even if someone later gives it a higher role or signs in with its password: no
  triage, no AI requests, no tokens, no password change. Signing out still works.
- **Shown only while it is safe.** The button appears, and `POST /api/v0/auth/demo` works, only
  while the user exists, is active, is not an instance admin, needs no password change, and holds
  no role above Viewer anywhere, single projects included. Otherwise the button is gone and the
  call answers 404 `DEMO_UNAVAILABLE`.
- **Short sessions.** A demo session lasts at most 24 hours, or less if `QUALOR_SESSION_TTL_HOURS`
  is shorter. The demo user's expired sessions are removed at each new demo sign-in. Demo sign-ins
  are rate-limited per address like password sign-ins, and recorded in the audit log with the
  method `demo`.

### Single sign-on users

With an enterprise licence that lists `sso`, people can also sign in through your identity provider
([Single sign-on and SCIM](./sso-and-scim.md)). Their account is created at their first sign-in, or
by SCIM, which needs the Enterprise plan. Such an account has **no password**: it signs in only
through single sign-on.

**Settings → Users** shows how each user signs in:

| Badge | Meaning |
|---|---|
| **No password** | the user cannot sign in with a password. The **No password** filter lists only these users (`GET /api/v0/users?signIn=no-password`) |
| **SSO** | the account is linked to an identity provider |
| **SCIM** | the identity provider provisions the account, and may overwrite changes made to it in Qualor |

In `GET /api/v0/users`, each user carries `hasPassword` and `sso` (`identities`, the number of
linked accounts, and `scim`).

**After the `sso` licence lapses**, users without a password cannot sign in. Give one a password
with **Reset password** on their row in **Settings → Users**, and they choose their own at their
next sign-in. The same works for a user whose only linked connection was deleted. Only an instance
admin can do this, because changing your own password needs the current one.
**Settings → Sign-in** sets who else may use a password.

Single sign-on group mappings can manage memberships too. **Settings → Members** marks such a
membership "From SSO group sync: _connection_", and `GET …/members` gives it a `managedBy` with the
connection's id and name (`null` for a membership made by hand). Changing its role by hand turns it
into a manual membership. Removing it works, but the next sync adds it back while the person's
group still maps to it.

## Projects

A project is one analysed codebase, usually one repository. A monorepo can hold several projects,
each with its own key and its own `sources.include`.

- **Create one** in **Projects → New project**, with a key and a name. To create many at once from
  a GitHub or GitLab connection, use **Add repositories**
  ([Quick start](./quick-start.md#fastest-path-add-repositories)). An upload never creates a
  project: the project must exist before the first scan.
- **The key** is what the scanner reports. It defaults to the CI project path (`CI_PROJECT_PATH`,
  `GITHUB_REPOSITORY`). Set it with `project.key` in `qualor.yml`, `QUALOR_PROJECT_KEY` or
  `--project-key`. Keys are unique on the instance and may contain letters, digits, `.`, `_`, `-`,
  `/` and `:`.
- **The main branch** is `main` by default. Every other branch and every merge request is compared
  with it.

### Project settings

A project's **Settings** tab has these panels, and shows each person only the ones they may use:

| Panel | What it does | Who sees it |
|---|---|---|
| **New code** | how new code is defined on the main branch ([Quality gates](./quality-gates.md#new-code)) | Project admin, Organization admin |
| **Quality gate and profiles** | the project's **Quality gate** (without a choice the organisation's default applies) and the **Quality profile per language** | Project admin, Organization admin |
| **Main branch** | the name of the main branch. Analyses of the previous main branch stay on that branch, and new code on the new one starts from its own analyses | Project admin, Organization admin |
| **Analysis tokens** | create and revoke the project's analysis tokens ([below](#project-analysis-tokens)) | Project admin, Organization admin |
| **Webhooks** | webhooks that fire for this project only ([Webhooks](./webhooks-and-api.md#webhooks)) | Organization admin |
| **Danger zone** | **Delete project** | Organization admin |

**Delete project** removes the project's branches and merge requests, analyses, issues and their
history, analysis tokens and project webhooks. It cannot be undone, so it asks you to type the
project key first. The API call is `DELETE /api/v0/projects/<id>?confirm=<key>`.

The same settings are available through `PATCH /api/v0/projects/<id>`, with a personal token that
has the **Admin** scope. The project id is in the project's URL.

```sh
curl -fsS -X PATCH -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"mainBranchName":"master","newCodeDefinition":{"type":"days","value":30}}' \
  "$QUALOR_URL/api/v0/projects/<project id>"
```

| Field | Meaning |
|---|---|
| `name` | display name |
| `mainBranchName` | the default branch |
| `newCodeDefinition` | how new code is defined on the main branch; see [Quality gates](./quality-gates.md#new-code) |
| `qualityGateId` | a gate for this project, or `null` for the organisation's default gate |
| `scmConnectionId`, `scmProjectRef` | the GitLab/GitHub mapping. **Settings → Repositories** also sets it. Only an org admin can change it (403 `FORBIDDEN` otherwise, even for a Project admin) |

To assign a quality profile to one project, send `{"profileId": "..."}` to
`PUT /api/v0/projects/<id>/quality-profiles/<language>`. Send `null` to return that language to the
organisation's default profile.

## Tokens

Every token is shown **once**, when it is created, and the server stores only a hash. Tokens look
like `qlr_pat_…` (personal) or `qlr_prj_…` (project). Qualor's own Gitleaks configuration knows the
`qlr_` prefix, so a leaked token is reported as a secret.

### Personal tokens

Create one in **Settings → Access tokens → New token**: choose the scopes and, if you like, an
expiry. Only a signed-in browser session can create a personal token, so a token can never create
another one.

| Scope (UI) | API name | Allows |
|---|---|---|
| Read | `read` | read the organisations you belong to |
| Write (triage issues) | `write` | also change issues, profiles and gates, as far as your role allows |
| Admin | `admin` | also everything your role allows administratively |
| Upload analyses | `analysis:write` | upload analyses (what CI needs) |

A token has the rights that both its scopes and its user's role allow.

### Project analysis tokens

A project token can **only upload analyses to its one project**, which makes it the best token for
CI. Create one in **Project → Settings → Analysis tokens** with **New token**: give it a name and,
if you like, an **Expires after** period. Press **Done** once you have stored the token. **Revoke**
stops a token at once.

Through the API, create one with a personal token that has the **Admin** scope:

```sh
curl -fsS -X POST -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"gitlab-ci"}' "$QUALOR_URL/api/v0/projects/<project id>/tokens"
# → {"token":"qlr_prj_…", ...}   store it as the masked CI variable QUALOR_TOKEN
```

List and revoke project tokens with `GET` and `DELETE /api/v0/projects/<id>/tokens[/<token id>]`.

### Apps connected through MCP

AI agents such as Claude Code or Cursor use no personal token. They sign in through your browser,
you allow the app on a consent page, and Qualor gives it its own short-lived login that works only
on the [MCP address](./mcp.md). You see these apps in **Settings → Connected apps** and disconnect
them there. An administrator can do the same for any user. They do not appear under **Access
tokens**.

### Which token where

| Use | Token |
|---|---|
| CI of one repository | a project analysis token |
| One CI token for many repositories | a personal token (**Upload analyses**) of a dedicated bot user. The projects must exist |
| Scripts and automation (onboarding, reports) | a personal token with **Read**, **Write** or **Admin**, as needed |
| `qualor import sonarqube` | a personal token with **Admin**, of an org admin |

Keep `QUALOR_TOKEN` in the CI's secret store: a masked GitLab variable, or a GitHub Actions secret.
Never put it in `qualor.yml`: the CLI refuses a config file that has a `token` key.
