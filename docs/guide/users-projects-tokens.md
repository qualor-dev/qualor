# Users, projects and tokens

## Organisations

An organisation is a tenant. It owns its projects, quality profiles, quality gates, webhooks and
GitLab/GitHub connections. The first start creates the organisation `default`. There is no limit
on organisations, users, projects or lines of code, in the community edition or with an
[enterprise licence](./enterprise.md). Most companies need only `default`.

An instance admin creates more organisations in **Settings → Organizations** with **New
organization**. Give it a name and a key of 2 to 64 lowercase letters, digits and hyphens. The key
is what the CLI and the audit log use. Neither can be changed later. You become the new
organisation's Organization admin, and the organisation switcher in the header lists it. The same
screen calls `POST /api/v0/organizations`.

## Users and roles

Every edition has these roles; none needs a licence.

| Role | Can |
|---|---|
| **Instance admin** | everything, including users and organisations |
| **Organization admin** (`admin`) | manage the organisation: projects, project tokens, quality profiles, gates, webhooks, GitLab/GitHub connections and each project's mapping to a repository, members and roles on single projects |
| **Project admin** (`project_admin`) | what a Maintainer can, and also change project settings (except the GitLab/GitHub mapping), manage project tokens, delete branches and merge requests, and run the SonarQube status import |
| **Maintainer** (`member`) | read the projects, upload analyses, triage issues (change a status, override a severity) and use the AI assistant |
| **Viewer** (`viewer`) | read the projects: code, issues, quality gate, quality profile and AI answers |

A role given in an organisation applies to all its projects. An Organization admin can also give
someone Project admin, Maintainer or Viewer on a **single project**, in **Project → Access**; a
project role only adds to the organisation role. The full permission table is in
[Roles and the audit log](./roles-and-audit.md).

Instance admins manage users in **Settings → Users**: create users, reset passwords, deactivate
users, and make or remove instance admins. A new user and a user whose password was reset must
choose a new password at their next password sign-in (a single sign-on sign-in does not ask).
Passwords have at least 12 characters, and sign-in is rate-limited.

Organization admins manage organisation membership and roles in **Settings → Members**: add
someone by their exact user name, change their role, or remove them. An organisation always keeps
at least one Organization admin: demoting or removing the last one answers 409 `LAST_ADMIN`, so
make someone else Organization admin first. The same screen calls the API:

```sh
# role: "admin", "project_admin", "member" or "viewer"
curl -fsS -X PUT -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"member"}' "$QUALOR_URL/api/v0/organizations/<org id>/members/<user id>"
```

Roles on a single project use `/api/v0/projects/<project id>/members/<user id>` the same way (see
[Roles and the audit log](./roles-and-audit.md#managing-members)).

### Single sign-on users

With an enterprise licence listing `sso`, people can also sign in through your identity provider,
and an account can be created at their first sign-in or by SCIM (SCIM needs the Enterprise plan)
([Single sign-on and SCIM](./sso-and-scim.md)). Such an account has **no password**: it signs in
only through single sign-on. **Settings → Users** shows how each user signs in with badges:

- **No password**: the user cannot sign in with a password (the **No password** filter lists only
  these users; `GET /api/v0/users?signIn=no-password` in the API);
- **SSO**: the user has an account linked to an identity provider;
- **SCIM**: the identity provider provisions the account, and may overwrite changes made to it in
  Qualor.

Each user in `GET /api/v0/users` carries `hasPassword` and `sso` (`identities`, the number of
linked accounts, and `scim`).

**After the `sso` licence lapses**, users without a password cannot sign in. Give one a password
in **Settings → Users**, with **Reset password** on their row: they choose their own at their
next sign-in, as any user whose password was reset does. Setting (resetting) a password ends that user's
sessions and revokes their personal tokens, so their CI jobs need a new token. The same works for
a user whose only linked connection was deleted. Only an instance admin can give a user without a
password one: changing your own password needs the current one. Who else may use a password is set in **Settings → Sign-in**.

Group mappings of single sign-on can manage memberships too. **Settings → Members** marks such a
membership "From SSO group sync: *connection*", and `GET …/members` gives it a `managedBy` with the
connection's id and name (`null` for a membership made by hand). Changing its role by hand takes it
over from group sync: from then on it is a manual membership. Removing it works too, but the next
sync adds it back while the person's group still maps to it.

## Projects

A project is one analysed codebase, usually one repository. A monorepo can hold several projects,
each with its own key and its own `sources.include`.

- **Create one** in **Projects → New project**, with a key and a name. Or let the first upload create
  it: this happens when the scan uses a personal token of an org admin with the **Upload analyses**
  scope.
- **The key** is what the scanner reports. It defaults to the CI project path (`CI_PROJECT_PATH`,
  `GITHUB_REPOSITORY`). You can set it with `project.key` in `qualor.yml`, `QUALOR_PROJECT_KEY` or
  `--project-key`. Keys are unique on the instance. They may contain letters, digits, `.`, `_`, `-`,
  `/` and `:`.
- **The main branch** is `main` by default. Every other branch and every merge request is compared
  with it.
- **Deleting** a project needs its key as confirmation. The API call is
  `DELETE /api/v0/projects/<id>?confirm=<key>`.

Some project settings have no screen in the UI yet. Set them with `PATCH /api/v0/projects/<id>` (the
project id is in the project's URL), using a personal token with the **Admin** scope:

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

To assign a quality profile to one project, use `PUT /api/v0/projects/<id>/quality-profiles/<language>`
with the body `{"profileId": "..."}`. Send `null` to return that language to the organisation's
default profile.

## Tokens

Every token is shown **once**, when it is created. The server stores only a hash. Tokens look like
`qlr_pat_…` (personal) or `qlr_prj_…` (project). Qualor's own Gitleaks configuration knows the `qlr_`
prefix, so a leaked token is reported as a secret.

### Personal tokens

**Settings → Access tokens → New token.** You choose the scopes and, optionally, an expiry. Only a
signed-in browser session can create a personal token, so a token can never create another one.

| Scope (UI) | API name | Allows |
|---|---|---|
| Read | `read` | read the organisations you belong to |
| Write (triage issues) | `write` | also change issues, profiles and gates, as far as your role allows |
| Admin | `admin` | also everything your role allows administratively |
| Upload analyses | `analysis:write` | upload analyses (what CI needs) |

A token has the rights that both its scopes and its user's role allow.

### Project analysis tokens

A project token can **only upload analyses to its one project**. It is the best token for CI. Create
one with a personal token that has the Admin scope:

```sh
curl -fsS -X POST -H "Authorization: Bearer $QUALOR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"gitlab-ci"}' "$QUALOR_URL/api/v0/projects/<project id>/tokens"
# → {"token":"qlr_prj_…", ...}   store it as the masked CI variable QUALOR_TOKEN
```

List and revoke project tokens with `GET` and `DELETE /api/v0/projects/<id>/tokens[/<token id>]`.

### Which token where

| Use | Token |
|---|---|
| CI of one repository | a project analysis token |
| One CI token for many repositories, with projects created on first scan | a personal token (**Upload analyses**) of a dedicated bot user who is org admin |
| Scripts and automation (onboarding, reports) | a personal token with **Read**, **Write** or **Admin**, as needed |
| `qualor import sonarqube` | a personal token with **Admin**, of an org admin |

Keep `QUALOR_TOKEN` in the CI's secret store: a masked GitLab variable, or a GitHub Actions secret.
Never put it in `qualor.yml`: the CLI refuses a config file that has a `token` key.
