# Changelog

All notable changes to Qualor are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The Business and Enterprise plans now differ by features, not only by support
  (`docs/guide/enterprise.md`). Business ($4,900 a year): single sign-on with one enabled
  connection at a time (`sso`), the audit log with its JSON Lines export (`audit-log`) and the
  higher AI fix suggestion limit (`llm.fix-quota`), with email support. Enterprise ($12,000 a
  year): everything in Business, plus SCIM (`scim`), streaming the audit log to a SIEM
  (`audit-log.stream`), several identity providers at once, up to 10 connections (`sso.multi`),
  and portfolio and compliance reports when they ship, with SLA support: email only, first reply
  within 1 business day for critical issues, no phone or 24x7. Help migrating from SonarQube is no
  longer offered; `qualor import sonarqube` stays free in every edition.
- Two new enterprise features, each active only with the one it extends: `audit-log.stream` (needs
  `audit-log`) gates the SIEM stream's settings, test, secret and delivery; `sso.multi` (needs
  `sso`) lets more than one single sign-on connection be enabled and in effect. `license:sign`
  refuses a feature without the one it needs, and its usage names both plans' feature lists.
- Existing keys that list `audit-log` without `audit-log.stream` lose SIEM streaming: the stream
  pauses with its settings and position kept, and catches up when the feature returns (events
  removed by retention meanwhile are counted as skipped). Keys that list `sso` without `sso.multi`
  keep one connection in effect, the oldest enabled one; the others are kept, still enabled, and
  answer `unavailable`. Nothing is deleted.
- New error code: 409 `SSO_MULTI_NOT_LICENSED` (without `sso.multi`, creating a connection enabled
  or enabling one while another is enabled). `PUT /api/v0/ee/audit/settings` with a `stream`
  object, and the two stream routes, answer 403 `FEATURE_NOT_LICENSED` without
  `audit-log.stream`. Single sign-on connections gain `inEffect`, and `GET /api/v0/auth/methods`
  lists only the connections in effect.

### Added

- The server (API, web UI, worker and its own PostgreSQL 18) and the `qualor` CLI with ESLint,
  PMD, SpotBugs, OpenGrep, Gitleaks, Trivy and Roslyn/Roslynator for C#, coverage import,
  duplication and metrics, quality gates on new code.
- GitLab merge request decoration, the GitLab CI/CD component, Code Quality, SAST and Dependency
  Scanning reports, and a GitHub App with check runs and pull request comments.
- `qualor import sonarqube` and the AI assistant (explain, triage, fix suggestions with your own
  model).
- A Helm chart, signed release artifacts with checksums and SBOMs, `CONTRIBUTING.md` and
  `SECURITY.md`.
- Enterprise licence keys: offline, Ed25519-signed, with a 14-day grace period after expiry. The
  enterprise plugin ships in `qualor/server` and loads only with a valid key; Settings → Licence
  and `GET/PUT/DELETE /api/v0/license` for instance admins. A licence key switches enterprise
  features on and nothing else; when it lapses only those features switch off, and nothing is
  deleted. The enterprise code is source-available under the Qualor Enterprise Licence
  (`enterprise/LICENSE`); a licence key is bought through https://qualor.dev/contact
  (`docs/guide/enterprise.md`). Plans and prices, per server instance per year: Community free,
  Business $4,900 and Enterprise $12,000, which differ by features and support (see Changed
  above).
- Roles, in every edition with no licence: four roles (Organization admin, Project admin,
  Maintainer and Viewer; `admin`, `project_admin`, `member` and `viewer` in the API) and a role
  on a single project (Project → Access, `GET/PUT/DELETE /api/v0/projects/{id}/members`). A
  Settings → Members screen adds a member by exact user name (`GET /users/lookup`), changes a
  role, or removes a member. `GET /auth/me` and every project answer gain `permissions`, the
  caller's effective permissions; `/auth/me` also gains `projectGrants`. A bulk issue transition
  lists the issues a viewer may read but not triage in `failed`, with `code: "FORBIDDEN"`, in its
  200 answer. An organisation keeps at least one Admin: demoting or removing the last one answers
  409 `LAST_ADMIN`. Mapping a project to a
  GitLab/GitHub repository (`scmConnectionId`, `scmProjectRef`) needs an org admin. Text in a
  request that holds a lone UTF-16 surrogate is refused with 422 `VALIDATION_FAILED`.
- An audit log, with an enterprise licence listing `audit-log`: a defined catalogue of
  security-relevant events in a hash-chained, append-only table, configurable retention with a
  daily prune, a JSON Lines export with a verification script, a read API
  (`GET /api/v0/ee/audit/events`), and a signed SIEM stream, which needs `audit-log.stream` too
  (`docs/guide/roles-and-audit.md`). New
  error codes: 409 `PROJECT_GRANT_LIMIT_REACHED` (a project's 1 000 roles) and 409
  `AUDIT_CHAIN_ANCHOR_MALFORMED` (the stored chain anchor needs repair; changes the audit log would
  record, and sign-in while the audit table is empty, are refused until it is restored; changes
  that remove access, such as signing out, revoking a token or removing a member, still go through
  and are logged instead).
- Single sign-on and SCIM, with an enterprise licence listing `sso` and `scim`
  (`docs/guide/sso-and-scim.md`): OIDC (authorization code with PKCE) and SAML 2.0 connections
  configured by instance admins, sign-in buttons on the sign-in page, accounts created at the
  first sign-in or linked by an IdP-verified email (for SAML, when the admin marks the IdP as
  verifying it; never by user name), new screens Settings → Single sign-on, Settings → Sign-in,
  Settings → SCIM and Settings → Linked accounts, "No password", "SSO" and "SCIM" badges and a
  "No password" filter on Settings → Users, a banner for instance admins while the emergency
  switch is on, group mappings onto organisation and project roles that own only the memberships they
  create, password sign-in limited to break-glass admins if wanted, and SCIM 2.0 `/Users` and
  `/Groups` for Entra ID and Okta with hashed `qlr_scim_` tokens (found by the `qualor-token`
  Gitleaks rule); SCIM deactivation ends sessions and revokes personal tokens. New server
  variables: `QUALOR_SSO_INTERNAL_HOSTS` (an identity provider on the internal network) and
  `QUALOR_FORCE_PASSWORD_SIGN_IN` (the emergency switch: `true` re-enables password sign-in for
  everyone with a password, logged at every start and recorded as `auth.password_sign_in_forced`;
  any value but `true`, `false` or empty stops the start); in the Helm chart they are
  `config.ssoInternalHosts` and `config.forcePasswordSignIn`. Single sign-on needs
  `QUALOR_PUBLIC_URL`. New public endpoint `GET /api/v0/auth/methods`; each user in
  `GET /api/v0/users` and `GET /api/v0/auth/me` gains `hasPassword` and `sso`, with
  `?signIn=no-password`; each organisation
  member gains `managedBy`; `/api/v0/ee/sso` and `/api/v0/ee/scim` routes, and the SCIM service at
  `/api/v0/ee/scim/v2`. New error codes: 409 `PUBLIC_URL_REQUIRED`,
  `SSO_CONNECTION_LIMIT_REACHED`, `SSO_CONNECTION_NAME_TAKEN`, `SCIM_TOKEN_LIMIT_REACHED`,
  `LAST_BREAK_GLASS_ADMIN`, `LAST_SIGN_IN_METHOD`, `LAST_SSO_CONNECTION` (the last enabled
  connection while password sign-in is limited to break-glass admins) and `SCIM_MANAGED_IDENTITY`,
  and 503 `SSO_UNAVAILABLE`. The browser flows are rate-limited per address, and SCIM per token
  and, for failed authentications, per address. New audit actions: `auth.password_sign_in_forced`, `sso.*` (a failed sign-in,
  an account provisioned, linked or unlinked, connection, mapping and sign-in setting changes),
  `scim_token.created`, `scim_token.revoked` and `scim.*` (users and groups); `auth.sign_in`
  gains the method and `forced`, and group sync's member changes carry `managedBy`. Not supported
  yet: Entra ID's `common` issuer and Azure AD B2C, single logout, IdP-initiated SAML.

### Changed

- **Breaking:** the community edition has no organisation limit, and no limit on lines of code,
  users or projects. A licence key no longer carries one; keys that do still verify, and the field
  is ignored. After a licence lapses only the enterprise features switch off: every organisation
  stays writable, and instance admins see a notice that the enterprise features are off. The
  problem codes `ORG_READ_ONLY` and `ORG_LIMIT_REACHED` are gone, and so are `organizationLimit`
  in problem answers, `readOnly` in `GET /api/v0/organizations`, the organisation count in
  `GET /api/v0/license`, and `limits` in `GET /api/v0/system/info`. `pnpm license:sign` refuses
  `--organizations`. `enterprise/LICENSE` drops §3 item b (the organisation limit).
- **Breaking:** roles and project access are part of the community edition: the four roles
  (Organization admin, Project admin, Maintainer, Viewer), roles on a single project and the Access
  tab need no licence. The project grant API moved from `/api/v0/ee/rbac/projects/{id}/members` to
  `/api/v0/projects/{id}/members`; the `/api/v0/ee/rbac` paths are removed, not redirected. The
  licence feature `rbac` enables nothing; keys that list it still work, and
  `pnpm license:sign` refuses it. SSO group mappings to every role and to projects need only
  `sso`. On a development server whose `rbac` licence had lapsed, stored roles and grants apply
  again.
- `enterprise/LICENSE` is titled "Qualor Enterprise Licence" and no longer carries a draft
  banner; its terms are unchanged.

### Upgrade notes

- Migration `0006` (single sign-on and SCIM) adds a column, a foreign key and an index to the
  organisation and project membership tables and holds a lock on both until it finishes. On a
  large external database, run the upgrade at a quiet time: a server of the previous version still
  serving requests waits meanwhile (`docs/guide/install-server.md#upgrades`).
