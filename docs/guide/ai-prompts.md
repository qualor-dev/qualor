# AI prompts

These prompts let an AI coding agent set up Qualor for you. That can be Claude Code, Codex, Cursor,
Copilot agent mode or any agent that can read web pages and run commands. Copy a prompt, fill in the
`<…>` placeholders or let the agent ask for them, and paste it into the agent's session.

The prompts point the agent to this documentation as raw Markdown, which is easy for a model to read:
`https://qualor.dev/docs/<page>.md`. The same files are in the repository under
[`docs/guide/`](https://github.com/qualor-dev/qualor/tree/main/docs/guide).

**Before you start**

- Give the agent only the access the task needs. Use a shell on the target host for the server, a
  checkout of the repository for CI, and API tokens with the smallest scope that works.
- Every prompt tells the agent never to print, log or commit secrets, and to stop and ask before
  anything outward-facing or hard to undo. Keep those lines when you edit a prompt.
- Review the agent's merge requests like any other change.

## Full rollout in a company

The complete path: inventory, server, pilot repositories, merge request comments, gate tuning,
rollout and handover. Use it when you start from nothing.

```prompt
You are a platform engineer rolling out Qualor, an open-source,
self-hosted code quality platform (a SonarQube alternative), in our
company. Work in phases, and finish each one before you start the
next. Read the documentation before you act. It is Markdown, served
at https://qualor.dev/docs/<page>.md: README, quick-start,
install-server, users-projects-tokens, gitlab, github, other-ci,
languages-and-analyzers, configuration, quality-gates, cli,
migrate-from-sonarqube, webhooks-and-api, troubleshooting. Fetch the
pages as you need them. Prefer them over your memory, because Qualor
changes quickly.

Company context (ask me for anything that is missing, before phase
2):
- SCM: <GitLab self-managed at https://gitlab.example.com |
  GitLab.com | GitHub.com | GitHub Enterprise Server>
- CI: <GitLab CI | GitHub Actions | Jenkins | other>
- Host for the Qualor server: <a Linux VM with Docker, reachable by
  SSH as ...> or <Kubernetes cluster ...>
- Public address for Qualor: <https://qualor.example.com>, and TLS:
  <Caddy/Let's Encrypt | our nginx | a cloud load balancer>
- Database: <the server's own (default) | our PostgreSQL 16+ at
  db.example.com, DATABASE_URL in our secret store>
- Can runners and the server pull from Docker Hub? <yes | no, use
  our registry mirror.acme.internal/qualor>
- Pilot repositories (2–3, different languages): <group/app-a,
  group/app-b>
- Languages in use: <TypeScript, Java, C#, ...>
- Do we use SonarQube today? <no | yes, at https://sonar.example.com
  (Server x.y) or SonarQube Cloud org <key>>

Phase 1, inventory. List the repositories of the pilot scope and,
for each one: languages, build tool, how tests produce coverage
(LCOV, Cobertura or JaCoCo, and the path), whether an ESLint config
exists, the default branch, and the current CI file. Present this as
a table and wait for my go-ahead.

Phase 2, server. Deploy the server from the qualor/server image on
Docker Hub with the compose.yml and .env of install-server.md:
generated secrets in .env with mode 600, TLS in front,
QUALOR_TRUST_PROXY, QUALOR_PUBLIC_URL, and QUALOR_SCM_INTERNAL_HOSTS
if our SCM is on an internal network. On Kubernetes, install the
Helm chart instead, as the Kubernetes section of install-server.md
shows: the secrets in a Secret, values.yaml with publicUrl,
trustProxy and the ingress, and database.mode external if we have a
managed PostgreSQL. If we cannot pull from Docker
Hub, copy qualor/server, qualor/scanner (and qualor/scanner-dotnet
for C#) into our registry first, as install-server.md shows. Use the
same release tag for the server and the scanner. Set up a daily
pg_dump backup, and store .env (it holds QUALOR_SECRET_KEY)
separately. Verify /readyz, sign-in, and a changed
admin password. Tell me where every secret is stored, without
printing it.

Phase 3, pilot. For each pilot repository: create the Qualor project
(its key is the CI project path), make its main branch name match
the default branch, create a project analysis token and store it as
a masked, not protected, CI variable QUALOR_TOKEN, together with
QUALOR_URL. Add the CI job from the docs, with full git history,
dependencies installed or the build run before the scan, the
coverage report produced before the scan, and the GitLab component
or GitHub workflow where it applies. Add a minimal qualor.yml only
when the defaults are not enough. Start with the gate as a soft
check (allow-failure / not required). Open one merge request per
repository and make sure the pipeline is green and the analysis
appears in Qualor.

Phase 4, merge request feedback. Connect the SCM in Qualor as
gitlab.md or github.md describes: a project or group access token
with the api scope and Maintainer role for GitLab, or a GitHub App
with Checks and Pull requests write for GitHub. Map each pilot
project, run the connection test, and show me a merge request with
Qualor's summary comment and inline findings.

Phase 5, tuning. Look at the pilot results. Propose the
organisation's gate and profile changes, with a reason for each:
which noisy rules to deactivate, which severities to change, and
whether to keep the default "Qualor way" gate (no new issues, 80 %
coverage on new code, at most 3 % new duplication). Apply them only
after I agree. If we use SonarQube, run `qualor import sonarqube
--dry-run` and show me the plan first.

Phase 6, rollout. Write a script that onboards every remaining
repository through the Qualor API and the SCM API: create the
project, create a token, set the CI variables, and open a merge
request that adds the job. Run it in batches of 10 and report the
results. After two weeks without false alarms, propose making the
check required.

Phase 7, handover. Write docs/qualor-runbook.md in our
infrastructure repository. Cover where everything runs, how to
upgrade, back up and restore, rotate tokens, onboard a new
repository, and what developers should do when the gate fails.

Rules for the whole task:
- Never print, log, echo or commit a token, password or private key.
  Use CI secret stores and files with mode 600. Redact secrets in
  everything you show me.
- Ask before anything outward-facing or hard to undo: pushing to
  shared branches, changing organisation-wide CI settings, deleting
  anything, exposing a port to the internet, or making checks
  required.
- Pin image tags. Never use :latest.
- When something fails, read troubleshooting.md and the job log
  before you change anything, and tell me the root cause you found.
- At the end of each phase, give me a short status: what was done,
  what was verified and how, and what is open.
```

## Install the server on one host

```prompt
Install a production Qualor server on this Linux host. Follow
https://qualor.dev/docs/install-server.md exactly, and read
https://qualor.dev/docs/quick-start.md for the first steps.

Inputs:
- public address: <https://qualor.example.com>
- TLS: <Caddy with Let's Encrypt | existing nginx with the
  certificate at ... | a load balancer in front>
- internal SCM host that Qualor must reach, if any:
  <gitlab.corp.example.com[:port] | none>
- database: <the server's own, on the volume | external PostgreSQL:
  DATABASE_URL is in the environment variable QUALOR_DATABASE_URL>

Steps:
1. Check the prerequisites: Docker with Compose v2, at least 1 GiB
   of free memory for the server (4 GiB if reports will be large),
   and disk space. Report what is missing.
2. Create /opt/qualor/compose.yml exactly as install-server.md
   shows, and check that the host can pull qualor/server:<tag> from
   Docker Hub (tag: <0.2 | a full version such as 0.2.0>).
3. Create /opt/qualor/.env with QUALOR_VERSION, a value from
   `openssl rand -hex 32` for each secret, QUALOR_PUBLIC_URL,
   QUALOR_TRUST_PROXY=1 and, if needed, QUALOR_SCM_INTERNAL_HOSTS
   and DATABASE_URL, with mode 600. Never show the secret values.
4. Start it with `docker compose up -d` and wait until the server is
   healthy.
5. Configure the reverse proxy: body size 50m, request buffering
   off, 300 s read timeout, and the X-Forwarded-* headers.
6. Verify: /healthz and /readyz over the public address, the
   certificate, and a sign-in as admin. Then ask me to change the
   admin password in the UI (don't do it through the API).
7. Add a systemd timer or cron job for a daily backup into
   /var/backups/qualor, keeping 14 days, with the pg_dump command
   of install-server.md ("Backups"). Test the restore on a scratch
   copy (a second volume), never on the live one.
8. Summarise: URLs, file locations, how to upgrade, and where the
   secrets live (the location, never the value).

Ask before opening firewall ports or changing an existing nginx
site.
```

## Add Qualor to a GitLab repository

```prompt
Add Qualor to the GitLab repository in the current directory. Read
https://qualor.dev/docs/gitlab.md,
https://qualor.dev/docs/languages-and-analyzers.md and
https://qualor.dev/docs/configuration.md first.

Inputs:
- Qualor server: <https://qualor.example.com>
- Qualor release: <0.2 | a full version such as 0.2.0>
- scanner image: <qualor/scanner (qualor/scanner-dotnet for C#) |
  our copy at mirror.acme.internal/qualor/scanner>
- GitLab: <GitLab.com: use gitlab.com/qualor/qualor/qualor |
  self-managed with a mirror of the component at tools/qualor |
  self-managed without a mirror: use the plain job>

Do this:
1. Inspect the repository: languages, package manager and build
   tool, how tests are run and whether they write coverage (and to
   which path), the ESLint config, the default branch, and the
   existing .gitlab-ci.yml (stages, rules, whether merge request
   pipelines are used).
2. Add a `qualor` job, with the component if there is one, otherwise
   the plain job from gitlab.md. It must have GIT_DEPTH 0, run in
   merge request pipelines and on the default branch, install the
   dependencies (JS/TS) or build (Java) before the scan, produce
   coverage before the scan (reuse the existing test job's artifact
   through `needs` if one exists, instead of running the tests
   twice), and keep the Code Quality, SAST and Dependency Scanning
   reports as artifacts. Set allow_failure: true for now.
3. Add qualor.yml only if needed: coverage paths, excludes for
   generated code, SpotBugs class directories, or a PMD ruleset.
4. Tell me which CI/CD variables to create (QUALOR_URL, and
   QUALOR_TOKEN masked but not protected), and the exact Qualor
   project key (the GitLab project path). If I give you an admin
   token for Qualor in the environment variable QUALOR_ADMIN_TOKEN,
   create the project and a project analysis token yourself through
   the API (users-projects-tokens.md), and set the variable through
   the GitLab API without ever printing the token.
5. Validate the config locally if Docker is available: `docker run
   --rm -v "$PWD":/src -w /src qualor/scanner:<release> validate`.
6. Commit on a new branch, and open a merge request titled "ci: add
   Qualor quality gate". In the description, list what the job does
   and what reviewers will see.

Never print or commit a token. Ask before pushing if you are unsure
about the branch or remote.
```

## Add Qualor to a GitHub repository

```prompt
Add Qualor to the GitHub repository in the current directory. Read
https://qualor.dev/docs/github.md,
https://qualor.dev/docs/languages-and-analyzers.md and
https://qualor.dev/docs/configuration.md first.

Inputs:
- Qualor server: <https://qualor.example.com>
- scanner image: <qualor/scanner:0.2 (qualor/scanner-dotnet:0.2 for
  C#) | a full version | our copy in a private registry>

Do this:
1. Inspect the repository: languages, build tool, test and coverage
   commands and paths, the ESLint config, the default branch, and
   the existing workflows.
2. Create .github/workflows/qualor.yml from the template in
   github.md: triggers on pull_request and on push to the default
   branch, permissions contents: read, the scanner container with
   --user 1001, actions/checkout pinned by SHA with fetch-depth 0,
   persist-credentials false and the PR head ref, the fork guard,
   and then install/build, tests with coverage, and `qualor scan`.
   For C#, use the qualor-dotnet.yml template with our real build
   command. If the image is private, add container credentials and
   packages: read.
3. Add qualor.yml only if needed.
4. Tell me to set the variables QUALOR_URL and QUALOR_SCANNER_IMAGE
   and the secret QUALOR_TOKEN. If `gh` is authenticated and
   QUALOR_ADMIN_TOKEN is in the environment, create the Qualor
   project (key owner/repo) and a project analysis token through the
   Qualor API, then run `gh secret set QUALOR_TOKEN` with the token
   on stdin. Never print it.
5. Open a pull request titled "ci: add Qualor quality gate". Do not
   make the check required: I will do that after a trial period.

Finally, remind me that the Qualor GitHub App must be installed on
this repository, and the repository mapped to its Qualor project,
for the pull request annotations and summary comment (github.md,
"The GitHub App").
```

## Add Qualor to a C# / .NET repository

```prompt
Add Qualor's C# analysis to the .NET repository in the current
directory. Read https://qualor.dev/docs/languages-and-analyzers.md
(the C# section), and https://qualor.dev/docs/gitlab.md or
https://qualor.dev/docs/github.md, depending on our CI.

1. Find the solution or project to build, the SDK version
   (global.json), private NuGet feeds (and how the existing CI
   authenticates to them), the test projects and how they collect
   coverage (coverlet or dotnet-coverage, Cobertura format).
2. Create a job in the qualor/scanner-dotnet:<release> image that
   runs: qualor dotnet begin; the project's own restore and `dotnet
   build <sln> --no-incremental` (no -warnaserror, no
   TreatWarningsAsErrors=true on the command line); the tests with
   Cobertura coverage; then `qualor dotnet end` with QUALOR_URL and
   QUALOR_TOKEN given to that step only. Add the cleanup `qualor
   dotnet abort` for failures (after_script on GitLab, `if:
   failure() || cancelled()` on GitHub). Full git history.
3. Add qualor.yml with coverage.reports pointing to the Cobertura
   files (glob) if they are not at the default path.
4. If the repository must keep failing on compiler warnings, keep
   that in its existing build job: explain why, because the scan job
   turns warnings-as-errors off.
5. Open a merge/pull request and explain the new job in the
   description.

Never print or commit feed credentials or tokens.
```

## Onboard every repository of a group or organisation

```prompt
Write and run a script that puts all repositories of <GitLab group
"platform" | GitHub organisation "acme"> under Qualor. Read
https://qualor.dev/docs/users-projects-tokens.md,
https://qualor.dev/docs/webhooks-and-api.md and
https://qualor.dev/docs/gitlab.md (or github.md) first.

Available in the environment (never print them): QUALOR_URL,
QUALOR_ADMIN_TOKEN (a Qualor personal token with the Admin scope),
and <GITLAB_TOKEN with the api scope | GH_TOKEN for gh>.

The script (bash or Python, idempotent and safe to rerun) must, for
each non-archived repository:
1. Skip it if a Qualor project with its key (the project path, or
   owner/repo) already exists.
2. Otherwise create the Qualor project, set mainBranchName to the
   repository's default branch, and create a project analysis token.
3. Store QUALOR_TOKEN (masked, not protected, on GitLab; an Actions
   secret on GitHub) and QUALOR_URL, unless they are already set at
   the group or organisation level.
4. Detect the language and build tool, and open a merge request /
   pull request that adds the Qualor job from the docs, with
   allow-failure or a non-required check.
5. Map the Qualor project to the repository for merge request
   comments (PATCH /projects/{id} with scmConnectionId <id> and
   scmProjectRef).
6. Write one line per repository to onboarding-report.csv: key,
   status (created/skipped/failed), the MR/PR URL, and the error.

Start with --dry-run and show me the plan for the first 10
repositories. Then run it in batches of 10 and pause between
batches. Respect the rate limits: on a 429, wait as long as
Retry-After says. Never write a token to disk except where the CI's
own API stores it, and never into the report.
```

## Migrate from SonarQube

```prompt
Migrate our SonarQube setup to Qualor. Read
https://qualor.dev/docs/migrate-from-sonarqube.md and
https://qualor.dev/docs/quality-gates.md first.

Inputs: SonarQube URL <https://sonar.example.com> (or SonarQube
Cloud with organisation <key>), SONAR_TOKEN (a user token),
QUALOR_URL and QUALOR_TOKEN (a personal token with the Admin scope),
all in the environment. Never print them.

1. Run `qualor import sonarqube --url ... --dry-run --output
   import-plan.json` (through the qualor/scanner image if the CLI is
   not installed).
2. Summarise the plan for me: profiles, gates and projects to
   create; the unmapped rules with the most resolved issues;
   unmapped gate conditions and what the Qualor gate will lack
   because of them; and the conflicts. Recommend whether to use
   --create-projects and --set-defaults.
3. After my approval, run the import without --dry-run.
4. Check which projects have not been scanned by Qualor yet. Once
   each has one main-branch analysis, run the import again with
   `--only issues`, and report how many statuses were applied, were
   already set, or stayed unmatched or ambiguous, and why.
5. Propose a side-by-side period: which pipelines run both scanners,
   how we compare verdicts, and when to remove SonarQube.

The import only reads SonarQube. Do not change anything in
SonarQube.
```

## Tune the gate for a legacy codebase

```prompt
Help me tune Qualor's quality gate and profiles for our codebase so
that it blocks real problems without crying wolf. Read
https://qualor.dev/docs/quality-gates.md and
https://qualor.dev/docs/webhooks-and-api.md.

Environment: QUALOR_URL and QUALOR_TOKEN (Read scope is enough for
step 1). Projects: <keys | all>.

1. Through the API, collect for each project: the gate status of
   recent merge request analyses, which conditions failed and how
   often, the rules with the most new issues, the issues marked
   false positive or won't fix (and their comments), and coverage
   and duplication on new code.
2. Find the noise: rules that are often marked false positive, rules
   whose findings are mostly style, and conditions that fail on
   small changes.
3. Propose concrete changes, each with its expected effect and a
   reason: rules to deactivate, or severities to override, in a copy
   of the "Qualor way" profile; gate conditions to change (for
   example new_blocker_issues + new_high_issues instead of
   new_issues > 0 for the first months, then back); and ESLint, PMD
   or .editorconfig changes that belong in the repositories instead.
4. Apply only the changes I approve. Copy the built-in profile or
   gate (they are read-only), make the copy the default, and record
   what changed in a short changelog I can share with the team.
```

## Fix a failing Qualor job

```prompt
The Qualor job in our CI fails. Find the root cause and fix it. Read
https://qualor.dev/docs/troubleshooting.md and
https://qualor.dev/docs/cli.md first.

Here is the job log (tokens removed): <paste the log>

1. Identify the exit code and what it means (cli.md, "Exit codes").
2. If it is 1, the gate failed. That is not a bug. List the failed
   conditions and the new issues behind them, and tell me which are
   real problems and which look like false positives.
3. For any other exit code, find the cause in the log and the
   repository: qualor.yml, the CI job, the git depth, installed
   dependencies, compiled classes, coverage paths, the server URL,
   CA or proxy, and the token's scope. Rerun with
   QUALOR_LOG_LEVEL=debug or `qualor validate` if you need more
   detail.
4. Make the smallest fix, explain it, and open a merge/pull request.
   Do not weaken the gate, lower thresholds or set allow-failure to
   make the job pass, unless I ask you to.
```

## Set up single sign-on and SCIM

For an enterprise licence listing `sso`, and `scim` for provisioning. SCIM, and a second enabled
connection next to one you already have, need the Enterprise plan (`scim`, `sso.multi`); the
Business plan gives one enabled connection and no SCIM. It adds an OIDC connection with a group
mapping and a SCIM token through the API. The agent needs a personal token of an instance admin
with the **Admin** scope.

```prompt
Set up single sign-on and SCIM provisioning on our Qualor server
through its REST API. Read https://qualor.dev/docs/sso-and-scim.md
first, and the "Single sign-on and SCIM (enterprise)" section of
https://qualor.dev/docs/webhooks-and-api.md.

Inputs:
- Qualor address: <https://qualor.example.com>, in QUALOR_URL
- an instance admin's personal token with the Admin scope, in the
  environment variable QUALOR_ADMIN_TOKEN
- identity provider: <Keycloak | Entra ID | Okta | Google Workspace>
- issuer URL: <https://login.microsoftonline.com/<tenant id>/v2.0>
- client id: <...>; the client secret is in the environment variable
  QUALOR_OIDC_CLIENT_SECRET
- connection name shown on the sign-in page: <Acme SSO>
- group mapping: IdP group <value; for Entra ID the group's object
  id> gets the role <admin | project_admin | member | viewer> in the
  organisation <key>
- SCIM: <yes, for Entra ID or Okta | no>

Steps:
1. GET /api/v0/system/info and check that `features` lists `sso`
   (and `scim` if SCIM is wanted). If not, stop and tell me: the
   licence key must list them (SCIM needs the Enterprise plan).
   GET /api/v0/ee/sso/connections: if another connection is
   enabled and `features` lacks `sso.multi` (the Business plan),
   tell me that the new connection must stay disabled until I
   disable the other one (several enabled connections need the
   Enterprise plan), and skip step 6.
2. POST /api/v0/ee/sso/connections with name, protocol "oidc",
   enabled false, groupSource "claims", and oidc { issuer,
   clientId, clientSecret }. Keep the issuer exactly as given,
   trailing slash included. Read the answer's `urls.redirectUri`;
   if `urls` is null, stop: QUALOR_PUBLIC_URL must be set on the
   server first.
3. Tell me the redirect URI to register at the identity provider,
   and wait until I confirm it is registered.
4. POST /api/v0/ee/sso/connections/<id>/test. If `ok` is false,
   report `problem` and stop.
5. Find the organisation's id with GET /api/v0/organizations, then
   PUT /api/v0/ee/sso/connections/<id>/mappings with the group
   mapping (projectId null). Mappings to every role and to projects
   need only `sso`.
6. PATCH the connection with { "enabled": true }, and check that
   GET /api/v0/auth/methods lists it. If the answer is 409
   SSO_MULTI_NOT_LICENSED, stop and tell me: another connection is
   enabled and the plan allows one.
7. If SCIM is wanted: POST /api/v0/ee/scim/tokens with the
   connection id and a name. The answer's `token` is shown once:
   never print, log or commit it. Write it to a file readable only
   by me (mode 600) and tell me the path, and tell me the SCIM base
   URL, <QUALOR_URL>/api/v0/ee/scim/v2, for the identity provider's
   provisioning settings.
8. Summarise the connection id, the mapping, and what I must do at
   the identity provider next.

Never print, log or commit the client secret, the admin token or
the SCIM token. Do not change the password sign-in setting
(/ee/sso/settings): ask me first, because limiting password
sign-in to break-glass admins can lock people out.
```

## Upgrade Qualor

```prompt
Upgrade our Qualor server and scanner to release <version>. Read
the "Upgrades" and "Backups" sections of
https://qualor.dev/docs/install-server.md first, and the release
notes on Docker Hub / GitHub.

1. Report the running version (GET /api/v0/system/info) and the
   target version, and summarise the release notes, especially
   migrations and breaking changes.
2. Take a pg_dump, and check that it is not empty. Note the current
   QUALOR_VERSION in .env: it is the rollback target.
3. Set QUALOR_VERSION to the new release in .env, then run
   `docker compose pull server` and `docker compose up -d`. Watch
   the logs until /readyz is 200. (If we copy images into our own
   registry, copy the new tags there first.)
4. Smoke test: sign in, open a project, and run one scan with
   qualor/scanner:<version> against a test project.
5. Open merge/pull requests that move the scanner tag and the GitLab
   component version in the CI configuration (or in the shared
   variable) to the same release.
6. If anything fails, roll back exactly as the docs describe: the
   previous QUALOR_VERSION, plus a restore into an empty database.
   Tell me before you do it.
```

## Explain Qualor to developers

```prompt
Write a one-page guide for our developers: "Qualor in your merge
requests". Read https://qualor.dev/docs/quality-gates.md, and
https://qualor.dev/docs/gitlab.md or
https://qualor.dev/docs/github.md.

Explain in plain language, with short examples: what the check does
and why it looks only at new code; how to read the summary comment
and the inline findings; how to fix a failing gate; when and how to
mark an issue false positive or won't fix (a comment is required,
and it re-evaluates the gate without a new pipeline); where the
rules come from (our own ESLint, PMD and .editorconfig settings) and
how to propose a rule change; and who to ask. Our Qualor address is
<https://qualor.example.com>, and the owning team is <team,
channel>. Keep it under 600 words. Save it as <path in our
handbook>.
```
