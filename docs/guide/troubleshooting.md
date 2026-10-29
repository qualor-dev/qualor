# Troubleshooting

Find the message or symptom you see, then its cause and fix. For a scan, start with two commands:

```sh
qualor validate                        # the resolved configuration, secrets redacted
QUALOR_LOG_LEVEL=debug qualor scan     # every analyzer's command line, output and skip reason
```

The scanner's exit codes are in the [CLI reference](./cli.md#exit-codes).

## The scan

| Message or symptom | Cause | Fix |
| --- | --- | --- |
| exit 2, `no project key` | no CI project path is detected outside GitLab and GitHub | set `QUALOR_PROJECT_KEY`, `--project-key` or `project.key` |
| exit 2, `server.url comes only from qualor.yml` | the token is sent only to a URL from `QUALOR_URL` or `--server-url` | set `QUALOR_URL` in the CI |
| exit 2, `invalid qualor.yml` and `analyzers: Unrecognized key: "eslnt"` | a typo in `qualor.yml`: unknown keys are errors | fix the key. The JSON Schema helps in the editor |
| exit 2, `invalid qualor.yml` naming `token` | secrets may not be in the config | remove it and use `QUALOR_TOKEN` |
| exit 2, `registry configs download rules over the network` | a registry id (`p/…`) in `semgrep.configs` | commit the rules and point to them |
| exit 3 | an analyzer with `enabled: true` is missing or crashed. Gitleaks is `true` by default | use the scanner image, or set `enabled: auto` |
| exit 4, connection refused or timeout | the runner cannot reach the server | check `QUALOR_URL`, the firewall, and `HTTPS_PROXY` and `NO_PROXY` |
| exit 4, certificate error | the server's certificate comes from a private CA | set `QUALOR_CA_FILE` (outside the checkout) or `NODE_EXTRA_CA_CERTS` |
| exit 4, `413` or upload rejected | the report is larger than the server or the proxy allows | raise `client_max_body_size` in the proxy, or `QUALOR_UPLOAD_MAX_COMPRESSED_BYTES` |
| exit 4, gate wait timed out | the server is busy, or its worker is stuck | check the server logs. If analyses are just slow, raise `gate.timeoutSeconds` |
| exit 4, `PROJECT_NOT_FOUND` | no project has that key, or the token belongs to another project | create the project, or fix the key |
| exit 5 | the token is invalid, revoked, lacks **Upload analyses**, or is another project's | create a new token |
| `this scanner is 0.3.2 and the server is 0.4.0` | the scanner image in CI is from another release than the server | pin the scanner to the tag the message names |
| `AI review: no snapshot sent, …` | the AI review snapshot was not uploaded, for the reason the message gives. The scan result is not affected | see [AI review: Troubleshooting](./ai-review.md#troubleshooting) |
| `the repository has no ESLint configuration` | no ESLint config at the repository root | add `eslint.config.js`, or set `analyzers.eslint.configFile` |
| ESLint fails, `Cannot find package …` | the dependencies are not installed | run `npm ci`, or your package manager's equivalent, before the scan |
| `… is a legacy eslintrc configuration, which ESLint 9 does not read` | ESLint 9 and later read only flat configs | migrate to `eslint.config.js` |
| SpotBugs: `no compiled classes in …` | the project was not built | build before the scan, or set `classDirs` |
| `the qualor/scanner image ships no Semgrep rules yet` | no Semgrep rules are bundled | name your rule files in `analyzers.semgrep.configs`, or ignore the message |
| `SEMGREP_CONFIG_MISSING` | a file in `analyzers.semgrep.configs` does not exist. The other files ran, and an AI review snapshot is not sent | fix the path, or remove the entry |
| `Qualor's security rules are not installed` | the scan does not run in a `qualor/scanner` image with the rules. Images of earlier Qualor releases have none | use a current `qualor/scanner` image, or unpack a [rules release](https://github.com/qualor-dev/qualor-rules/releases) and set `QUALOR_RULES_DIR` to it. Or ignore the message |
| `QUALOR_RULES_DIR must be an absolute path outside the repository` | `QUALOR_RULES_DIR` is relative, or points into the checkout | set it to an absolute path outside the checkout, or unset it |
| `QUALOR_RULES_DIR does not exist` | the directory it names is missing | create or unpack the rules there, or unset `QUALOR_RULES_DIR` |
| `the rules pack … does not match its manifest checksum`, or another `rules pack` reason | `QUALOR_RULES_DIR` holds a changed or incomplete copy of the rules | unpack the rules again, or unset `QUALOR_RULES_DIR` |
| `LICENSE_SCAN_TIMEOUT` or `LICENSE_SCAN_FAILED` | Trivy's licence pass ran longer than `analyzers.trivy.licenseTimeoutSeconds`, or failed. The vulnerability findings are not affected | raise the timeout, or read the scan log ([Dependency licences](./dependency-licenses.md#warnings)) |
| Dependencies tab: most packages have an **Unknown** licence | pnpm, Yarn, Go, NuGet, Maven and Gradle licences are read from the installed packages | install the dependencies in the scan job, before `qualor scan` ([Dependency licences](./dependency-licenses.md#which-ecosystems-give-licences)) |
| `VULNERABILITY_DB_STALE` | Trivy's database is more than 14 days old | move to a newer scanner release, or fetch a database in the job with `QUALOR_TRIVY_CACHE_DIR` |
| `ROSLYN_PROJECT_NOT_ANALYZED` | a C# project was not recompiled | build with `--no-incremental` |
| `no C# project was built between qualor dotnet begin and end` | the build ran elsewhere, or not at all | run the build in the same job, between the two commands |
| `TAINT_ENGINE_FALLBACK` | Qualor's Roslyn taint engine gave no complete result, so the OpenGrep C# rules ran instead. The message gives the reason, the log the detail | see the reasons below |
| `TAINT_ENGINE_PROJECT_ERRORS` | the engine analysed C# projects with load or compile errors, for example unresolved packages. Their findings may be incomplete | restore the packages and build without errors. The log names each project and its first error |
| `NESTED_REPOSITORY_SKIPPED` | a submodule or nested clone | none: this is expected. Scan that repository on its own |
| many issues in generated code | generated files are scanned | add them to `sources.exclude` |

The reasons of `TAINT_ENGINE_FALLBACK` ([C#](./languages-and-analyzers.md#c)):

| Reason | Fix |
| --- | --- |
| `budget` | raise `QUALOR_TAINT_TIME_LIMIT` (seconds) or `QUALOR_TAINT_MEMORY_LIMIT` (megabytes), or give the job more memory. The log line `taint engine memory limit` shows the value in use. The defaults are in the [configuration reference](./configuration.md#environment-variables-scanner) |
| `load` | the sources of a project could not all be loaded. The log names the project: check its build output and the paths under the checkout |
| `no-inputs` | build between `qualor dotnet begin` and `end`, with `--no-incremental` |
| `dotnet-missing` | use the `qualor/scanner-dotnet` image |
| `no-engine`, `engine-mismatch` | use a current image, or unpack the rules release again |
| `crash` | report it, with the log |

## The gate

| Symptom | Cause | Fix |
| --- | --- | --- |
| gate `error`, "new code unavailable" | a shallow clone, and the baseline could not be fetched | `GIT_DEPTH: 0` (GitLab), `fetch-depth: 0` (GitHub), `git fetch --unshallow` elsewhere |
| gate `error` on the main branch, "`<sha>` could not be fetched from origin", with the full history | the project holds analyses of another git history (the repository was re-created, or the project key reused), so the baseline commit is not in this repository. A 30-day new-code period does not help: its baseline is still an old-history analysis | set the [new-code definition](./quality-gates.md#new-code) to an analysis of the new history (`{ "type": "analysis", "analysisId": "…" }`), or use a new project |
| every merge request analysis shows up as a branch | the job ran in a branch pipeline | GitLab: use `merge_request_event` rules. Other CI: pass `--mr` and `--mr-target` |
| a coverage condition shows "no value" | no coverage report was imported | run the tests with coverage before the scan, and list the report in `coverage.reports` |
| coverage is 0 % for tested files | the report's paths do not match the repository's | set `coverage.pathPrefixes`, or generate the report from the repository root |
| the gate fails on old issues | an overall condition, which counts on the main branch only, or new lines that really touch old code | open the failed condition in the UI. The issue list filters by "new code" |
| `NEW_CODE_DEFINITION_FALLBACK` | `previous_version` is set, but no analysis has a version label | set `project.version`, for example to `${CI_COMMIT_TAG}` |
| marking a false positive does not change the verdict | the change applies to the branch's latest analysis | reload: the re-evaluation runs within seconds |

## Merge request and pull request comments

Test the connection first: **Settings → Repositories** has a **Check** for each project's mapping,
and its message says what is wrong.

| Symptom | Cause and fix |
| --- | --- |
| nothing on GitLab | no connection or mapping, or the analysis did not come from GitLab CI. Local scans are never decorated |
| "This GitLab is on an internal address" | the operator must list the host in `QUALOR_SCM_INTERNAL_HOSTS` |
| "GitLab refused the token" | the token is wrong, revoked or expired. Enter a new one |
| "The token lacks a permission" | the token lacks the `api` scope or the Maintainer role. Developer is enough for comments, but not for a commit status on a protected branch |
| "The stored token can no longer be read" | `QUALOR_SECRET_KEY` changed. Enter the token again |
| comments have no links | `QUALOR_PUBLIC_URL` is not set |
| no inline discussion or review comment for an issue | the issue is not on an added line of the diff, or it is past the 50 per merge or pull request. The summary counts both |
| GitHub: `not_installed` or `permission_missing` | install the App on the repository, with Checks, Contents and Pull requests write ([GitHub: Troubleshooting](./github.md#troubleshooting)) |
| GitHub: no inline comments for the analyzers' issues | the workflow checked out the merge commit. Use `ref: ${{ github.event.pull_request.head.sha }}`. AI review's comments are posted either way |
| no AI review section in the summary | AI review is not on for the project ([Why AI review is off for a project](./ai-review.md#why-ai-review-is-off-for-a-project)), or the analysis is not of a merge request |
| the AI review section says the review did not run or failed | see [AI review: What the summary says](./ai-review.md#what-the-summary-says) |
| GitHub: Re-run does nothing | the webhook is inactive, its secret differs, or `QUALOR_PUBLIC_URL` is not set |
| a reply to an AI review comment, or a `qualor review` note, is answered late or never | see [AI review: Why a reply or a command was not answered](./ai-review.md#why-a-reply-or-a-command-was-not-answered). A webhook makes the answer immediate. Without one, it comes at the next analysis ([GitLab](./gitlab.md#answers-to-replies-and-commands-webhook), [GitHub](./github.md#turn-on-the-webhook-recommended)) |
| Slack or Teams: a webhook is refused, a message does not arrive, or there is no digest | see [Slack and Microsoft Teams: Troubleshooting](./chat-notifications.md#troubleshooting) |

## The AI assistant

Every message and error code of the AI assistant, and automatic fix suggestions, are in
[AI assistant: Troubleshooting](./ai-assistant.md#troubleshooting). Two symptoms show no message:

| Symptom | Fix |
| --- | --- |
| no AI assistant panel in the issue view | an instance admin connects a provider and allows the organisation to use AI in **Settings → AI provider** |
| an action is missing from the panel | its feature is off for the organisation, or the issue cannot be sent: a secret rule, a credentials file, an excluded path or project. Triage and fix need an open issue |

## The server

To send us the state of a server, download a [support bundle](./support-bundle.md) (Business and
Enterprise).

| Symptom | Fix |
| --- | --- |
| `required variable … is missing a value` | set `QUALOR_VERSION`, `QUALOR_SECRET_KEY` and `QUALOR_BOOTSTRAP_ADMIN_PASSWORD` in `.env`, next to `compose.yml` |
| `manifest unknown` or `pull access denied` | a mistyped tag or image name, or no access to Docker Hub. Check `QUALOR_VERSION`. Behind a firewall, use your own registry copy (`QUALOR_IMAGE_PREFIX`) |
| Docker Hub `toomanyrequests` | the anonymous pull limit: run `docker login`, or copy the images into your own registry |
| `another Qualor server (host …) is using /var/lib/qualor` | two containers share the data volume. Stop the other one. After a crash, start again after 30 s |
| `the data directory holds a PostgreSQL <n> cluster and this image carries PostgreSQL <m>` | the volume was made by a release with another PostgreSQL major version. Follow that release's upgrade notes: back up with the old image, restore with the new one |
| `/readyz` answers 503 | migrations are still running, or the database is unreachable. Read `docker compose logs server` |
| sign-in fails behind a proxy, or every user shares one rate limit | set `QUALOR_TRUST_PROXY` |
| users are signed out after a restart | `QUALOR_SECRET_KEY` changed |
| the server stops at start, naming `QUALOR_SMTP_URL` or `QUALOR_SMTP_FROM` | the URL is not `smtp://…` or `smtps://…` as [Email](./email.md#set-up-with-environment-variables) shows (URL-encode `@`, `:` and `/` in the user name and password), or `QUALOR_SMTP_FROM` is missing |
| **Send test** fails, or **Recent messages** lists an error | see [Email: Troubleshooting](./email.md#troubleshooting) |
| the server runs out of memory on large reports | give it 4 GiB, and keep `QUALOR_WORKER_CONCURRENCY=1` |

## The licence

The server logs a key it refuses as `licence key rejected`, with a `reason`:

| `reason` | Cause | Fix |
| --- | --- | --- |
| `malformed` | not a Qualor key, or cut short when it was copied | copy the whole key again. Line breaks and spaces do not matter |
| `unknown-key` | the key was signed with a key this version of Qualor does not know: it is for a newer version, or it was altered | upgrade the server, or ask us for a new key ([Enterprise](./enterprise.md#buy-a-licence)) |
| `bad-signature` or `bad-payload` | the key was changed after it was issued | copy the key again from the original message, or ask for a new one |
| `revoked` | this licence was withdrawn | ask for a new key |
| `not-yet-valid` | the key's issue date is more than a day ahead of the server's clock | check the server's clock (NTP) |

| Message or symptom | Cause | Fix |
| --- | --- | --- |
| `qualor-server: QUALOR_LICENSE_FILE: cannot read …`, and the server does not start | the file is not there (the secret is not mounted), or user 65532 cannot read it | fix the secret mount or the file's permissions, or unset `QUALOR_LICENSE_FILE` |
| `qualor-server: QUALOR_LICENSE_FILE: … is not a file` | the path names a directory or a device, often a secret mounted as a directory | point the variable at the file inside it |
| `qualor-server: QUALOR_LICENSE_FILE: … is larger than 16 KiB` | the path names some other file | point the variable at the file that holds only the key |
| `qualor-server: QUALOR_LICENSE_FILE: … is not a text file in UTF-8 (or UTF-16 with a byte-order mark); save it as UTF-8` | the file is in another encoding, such as UTF-16 without a byte-order mark | save the key as UTF-8 (in PowerShell: `Set-Content -Encoding utf8`) |
| `set QUALOR_LICENSE or QUALOR_LICENSE_FILE, not both` | both variables are set | keep one |
| **Settings → Licence** says **Restart required.** | a key was saved or removed in the web UI. It applies at the next start | restart the server |
| the licence page has no field to paste a key | the key comes from `QUALOR_LICENSE` or `QUALOR_LICENSE_FILE` (`LICENSE_MANAGED_BY_ENVIRONMENT` in the API) | change the variable and restart |

## Roles and the audit log

| Message or symptom | Cause | Fix |
| --- | --- | --- |
| `PROJECT_GRANT_LIMIT_REACHED` (409) | the project already has 1 000 roles granted directly on it | remove a grant you no longer need, or give the role at organisation level |
| a bulk status change answers 200, but lists some issues in `failed` with `code: "FORBIDDEN"` | the caller's role may read those issues but not triage them (a Viewer). The other issues in the request changed | ask an org admin for the right role, then retry the refused ones |
| `LAST_ADMIN` (409) changing a member's role or removing a member | the member is the organisation's last Organization admin, and an organisation always keeps one | make someone else Organization admin first |
| `FORBIDDEN` (403) setting `scmConnectionId` or `scmProjectRef` on a project | mapping a project to a GitLab or GitHub repository needs an org admin, even for a Project admin | ask an org admin to set the mapping (**Settings → Repositories**, or the same `PATCH`) |
| a status change answers `CONCURRENCY_CONFLICT` (503) with `Retry-After` | another change to the same issue, or the audit log's recording of it, ran at the same moment. Nothing was written | wait as long as `Retry-After` says, and send the request again |
| "The chain breaks at event N" (**Settings → Audit log → Verify chain**) | event N's content, or its link to the event before it, no longer matches its stored hash. A row was changed, a row was deleted outside retention, or the retention anchor was changed | compare event N with an earlier export or your SIEM receiver's copy. If they agree with what came before it, the database changed since: ask whoever administers it |
| `AUDIT_CHAIN_ANCHOR_MALFORMED` (409) on changes, or sign-in refused with it | the stored anchor of the audit chain was changed and no longer parses | see [Repair the audit-chain anchor](#repair-the-audit-chain-anchor) |
| the SIEM stream stopped after a licence change: **Waiting to be sent** grows, and nothing fails | the key no longer lists `audit-log.stream` (a Business key replaced an Enterprise one). The stream is paused, its settings and position kept | apply an Enterprise key and restart: the stream catches up from where it stopped. To send nothing more, press **Remove** under **Stream status** ([Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem)) |
| `FEATURE_NOT_LICENSED` (403) naming `audit-log.stream` | the request changed the stream (a `stream` object in `PUT /api/v0/ee/audit/settings`, `POST /api/v0/ee/audit/settings/stream/test` or `POST /api/v0/ee/audit/settings/stream/regenerate-secret`), and the key lists `audit-log` without `audit-log.stream`, which needs the Enterprise plan. A request that also changed retention saved nothing | save retention on its own. To use the stream, apply an Enterprise key |
| the SIEM stream keeps failing | the receiver is down or refuses the connection, or its address or certificate changed | read `Last error` and `Failing since` in **Settings → Audit settings**, and fix the receiver. Events wait and are retried until retention removes them ([Streaming to a SIEM](./roles-and-audit.md#streaming-to-a-siem)) |
| **Export JSON Lines** does nothing, or the browser reports a failed download, with no message on the page | the button is a plain download link, so the page never shows why a download was refused | 429: another of your exports is still running; wait for it, or its download, to finish. 403: the licence lapsed (`audit-log` is no longer active); renew it. 409: the stored chain anchor is damaged; an instance admin must [repair it](#repair-the-audit-chain-anchor). The audit settings and chain head cards show this error too |

### Repair the audit-chain anchor

`AUDIT_CHAIN_ANCHOR_MALFORMED` means the `audit-chain` row of the table `instance_settings` was
changed and no longer parses. The row records where retention last cut the chain. Qualor refuses
to guess, so it records nothing:

- Every change it would record answers 409.
- While the audit table is empty, even signing in is refused. Personal tokens and sessions that are
  already signed in keep working.
- Retention stops removing events until the row is repaired.
- Removing access is never blocked. Signing out, revoking a personal or project token, deactivating
  a user, removing a member or a project role, and demoting a role still work. Their audit event is
  not written. Instead, the server log gets one error line,
  `audit event skipped: the audit-chain anchor is malformed`, naming the action and the ids of who
  did it and to whom.

An instance admin who can write the database restores the row:

```sql
UPDATE instance_settings
   SET value = '{"throughSeq":"<seq>","throughHash":"<64 hex characters>","prunedAt":"<ISO 8601 time>"}'::jsonb,
       updated_at = now()
 WHERE key = 'audit-chain';
```

Take the values from a database backup. Without one, take them from the newest `audit.pruned` event
in an export or your SIEM receiver's copy: `details.throughSeq`, `details.throughHash`, and its
`occurredAt` as `prunedAt`. Then run **Verify chain**. Keep the server log's `audit event skipped`
lines: they are the only record of the access removed meanwhile.

## Single sign-on and SCIM

A failed single sign-on ends on the sign-in page, or on **Settings → Linked accounts** for a link,
with a fixed message. The address ends in `?sso_error=<code>`. A code the page does not know shows
"Single sign-on failed. Try again, or ask an administrator."

The person never sees the precise reason. The server log has it, in a `warn` line
`single sign-on failed` with `component: "sso"`, the `connectionId`, the `reason` (the code below)
and a `detail`, such as `oidc.id_token.aud`, `oidc.discovery`, `saml.recipient` or
`saml.precheck.signature_shape`. With the audit log licensed, each failure on an existing
connection is also recorded as `sso.sign_in_failed`. A request naming a connection that does not
exist is only logged.

| `sso_error` code | What the person sees | Cause | Fix |
| --- | --- | --- | --- |
| `unavailable` | This sign-in method is not available. | the connection is unknown, disabled or deleted, or not in effect on the Business plan (log detail `oidc.not_in_effect` or `saml.not_in_effect`, see below). Or its sign-in could not start: the IdP's discovery document could not be read, or the stored configuration is not valid | enable the connection, and press **Test** in **Settings → Single sign-on**. The log's `detail` says which step failed |
| `flow_expired` | The sign-in took too long or was already used. Try again. | more than 10 minutes passed at the IdP, the page was reloaded or opened from the browser history, or the answer was already used | start again from Qualor's sign-in page. A SAML sign-in started from the IdP's app launcher (IdP-initiated) is not supported |
| `flow_mismatch` | The sign-in was started in another tab or browser. Start again here. | the sign-in finished in another browser or tab than the latest one that started it, or the browser blocks Qualor's cookies | start again, in one tab. Allow cookies for Qualor |
| `idp_error` | Your identity provider did not complete the sign-in. Try again, or ask an administrator. | the IdP answered with an error: the person cancelled, is not assigned to the application, or the IdP refused the request | check the IdP's own sign-in log. Assign the person to the application |
| `invalid_response` | Qualor could not accept the answer of your identity provider. Ask an administrator to check the connection. | the answer failed one of the checks listed below the table | read the log's `detail`, then fix the connection or the IdP |
| `replayed` | This sign-in was already used. Start again. | the same SAML assertion arrived twice | start again. If it keeps happening, something between the IdP and Qualor resends responses |
| `required_claim` | Your identity provider account is not allowed to sign in to Qualor. Ask an administrator. | a required claim of the connection, such as Google's `hd`, is missing or has another value | expected for accounts outside your domain. Otherwise, check the required claims |
| `no_account` | There is no Qualor account for you yet. Ask an administrator. | no account is linked, and the connection does not create accounts at the first sign-in | create the account and let the person link it, turn on linking by verified email, or let the connection create accounts |
| `inactive_user` | Your Qualor account is deactivated. | the linked Qualor account is deactivated | reactivate it in **Settings → Users**, or at the IdP for a SCIM user |
| `email_in_use` | Your identity provider's email already has a Qualor account. … | a new account would take a verified email that another Qualor user already has | the person signs in to that account with its password and links it under **Settings → Linked accounts**. Or an admin turns on linking by verified email, which never links instance admins |
| `username_unavailable` | A Qualor account could not be created for you because your user name is already taken. … | the user name and its variants `-2` to `-20` are all taken | rename one of the existing accounts, or send another username claim |
| `identity_in_use` | This identity provider account is already linked to another Qualor account. | a link: the IdP account belongs to another Qualor user | an instance admin unlinks it from that user first |
| `already_linked` | Your Qualor account is already linked to an account of this identity provider. | a link: this user already has a link on this connection | unlink the old one first, under **Settings → Linked accounts** |
| `rate_limited` | Too many sign-in attempts. Wait a minute and try again. | more than 30 starts a minute from one address, or more than 60 OIDC callbacks, SAML answers or finish steps | wait a minute. Many people behind one proxy share an address: set `QUALOR_TRUST_PROXY` |

`invalid_response` means the IdP's answer failed one of these checks:

- The issuer, audience, redirect URI, ACS URL or certificate is wrong.
- The token has expired, or is dated in the future: check the clocks.
- The ID token is signed with a key the JWKS lacks, with `HS256`, or with an RSA key under 2048
  bits.
- The SAML response is signed with SHA-1 (see the SHA-1 row below), or holds comments or a
  DOCTYPE.
- The assertion is not signed.
- It has more than 1 000 groups: send only the groups Qualor maps.
- The SAML sign-in is larger than 16 KiB.

| Message or symptom | Cause | Fix |
| --- | --- | --- |
| nobody can sign in: the IdP is down or the connection is broken | password sign-in is limited to break-glass admins, and none is at hand | set `QUALOR_FORCE_PASSWORD_SIGN_IN=true` and restart. Sign in with a password and fix the connection. Then remove the variable and restart ([If your identity provider is down](./sso-and-scim.md#if-your-identity-provider-is-down)) |
| the server does not start: `QUALOR_FORCE_PASSWORD_SIGN_IN must be true or false` | another value, such as `yes` or `1` | use `true` or `false`, or leave it empty |
| `PUBLIC_URL_REQUIRED` (409) enabling a connection | `QUALOR_PUBLIC_URL` is not set. The connection page shows no values to copy either | set `QUALOR_PUBLIC_URL` and restart |
| **Test** says "The discovery document names another issuer. …" | the issuer entered differs from the one the discovery document names, even by a trailing slash. Or it is Entra ID's `common` endpoint or Azure AD B2C, which are not supported | copy `issuer` exactly from `<issuer>/.well-known/openid-configuration`. For Entra ID, use `https://login.microsoftonline.com/<tenant id>/v2.0` |
| **Test** says "The host is not public. List it in QUALOR_SSO_INTERNAL_HOSTS if Qualor may call it.", or "The issuer URL is not allowed. Use https, or list the host in QUALOR_SSO_INTERNAL_HOSTS." | the IdP resolves to an internal address, or uses plain `http` | add its host (and port) to `QUALOR_SSO_INTERNAL_HOSTS` and restart. Link-local and cloud metadata addresses are never allowed |
| the IdP says its certificate or signature is SHA-1, or every SAML sign-in fails with the detail `saml.precheck.signature_shape` | the IdP signs with SHA-1, which Qualor refuses | switch the IdP to SHA-256. Keycloak: **Signature algorithm** `RSA_SHA256`. Entra ID: **Signing Algorithm** `SHA-256`. Okta: `RSA_SHA256`. AD FS: **Secure hash algorithm** `SHA-256` |
| new SAML users get names like `G-3f2a…` | no username attribute is set, so the NameID became the user name. Keycloak's persistent NameID is opaque | send a username attribute and name it in **Username claim** |
| a user who signed in through SSO has no email | the IdP did not mark it verified: `email_verified` in OIDC, or, for SAML, **This identity provider verifies the email attribute** is not ticked | none: an unverified email is never stored. Use SCIM, or tick that SAML setting if your IdP does verify emails |
| a group mapping gives nothing | the group value differs (case counts, and Entra ID sends object ids), the connection's groups do not come from claims or SCIM, or a mapped project already has 1 000 roles granted directly on it, so sync skips that grant | compare the mapping with what the IdP sends. For a full project, remove grants you no longer need |
| a role set by hand changes back, or a removed member comes back | group sync manages the membership ("From SSO group sync" on **Settings → Members**) | change its role by hand to take it over from sync, or change the IdP groups or the mappings |
| `LAST_BREAK_GLASS_ADMIN` (409) deactivating or demoting an instance admin | password sign-in is limited to break-glass admins, and this is the last one who could still use a password. The guard follows the stored setting, even while `QUALOR_FORCE_PASSWORD_SIGN_IN` is set or the licence has lapsed | add another one under **Break-glass administrators** in **Settings → Sign-in**, or first set **Password sign-in** back to **Everyone with a password** |
| `LAST_SIGN_IN_METHOD` (409) unlinking an account | nothing else would sign the user in: no password the current policy lets them use (the emergency switch does not count), and no link on another connection in effect | an instance admin sets a password first with **Reset password** on the user's row in **Settings → Users**, which ends the user's sessions and revokes their personal tokens. Then unlink. The password counts only while password sign-in is allowed for that user. A user without a password cannot set one themselves |
| `LAST_SSO_CONNECTION` (409) disabling or deleting a connection | password sign-in is limited to break-glass admins, and this is the last enabled connection: nobody else could sign in | first set **Password sign-in** back to **Everyone with a password** in **Settings → Sign-in**. On the Enterprise plan, you can enable another connection first instead. To switch identity provider on the Business plan, follow [the steps](./sso-and-scim.md#switch-identity-provider-on-the-business-plan) |
| `SSO_MULTI_NOT_LICENSED` (409) creating or enabling a connection: "Your plan allows one enabled single sign-on connection. …" | the key lists `sso` without `sso.multi` (the Business plan), and another connection is already enabled | create the connection disabled and prepare it. To switch to it, disable the enabled one first ([Switch identity provider on the Business plan](./sso-and-scim.md#switch-identity-provider-on-the-business-plan)). Several enabled connections need the Enterprise plan |
| `SSO_CONNECTION_LIMIT_REACHED` (409) adding a connection | 10 connections are stored, enabled or not: the most any plan allows | delete a connection you no longer need |
| a provider disappeared from the sign-in page after a licence change, and its sign-ins end with `unavailable` (log detail `oidc.not_in_effect` or `saml.not_in_effect`) | the new key lists `sso` without `sso.multi` (a Business key replaced an Enterprise one), so only the oldest enabled connection is in effect. Nothing was deleted | to use another connection instead, disable the one in effect: the next oldest enabled one takes over. To use them all again, apply an Enterprise key and restart ([After a move to the Business plan](./sso-and-scim.md#after-a-move-to-the-business-plan)) |
| `SCIM_MANAGED_IDENTITY` (409) unlinking your own account | the IdP provisions this link through SCIM | ask an instance admin, or have the IdP unassign you |
| `SSO_UNAVAILABLE` (503) linking an account | the connection's IdP cannot be used now: its discovery failed | try again later. An admin presses **Test** on the connection |
| signed out of the IdP, but still signed in to Qualor | Qualor does no single logout | sign out of Qualor too. Deactivating a user ends all their sessions |

### SCIM

| Message or symptom | Cause | Fix |
| --- | --- | --- |
| SCIM answers 401 | the token is missing, mistyped, revoked or expired, or its connection was deleted | create a token (**New token** in **Settings → SCIM**) and give it to the IdP |
| SCIM answers 429 | more than 1 200 requests a minute with one token. Or the request's token is wrong or missing, and its address already sent 60 such requests this minute; a valid token from that address still works | wait for `Retry-After`, and fix the token the IdP sends. A 429 in the server log may come from another client at the same address with a revoked or wrong token. Behind a reverse proxy, set `QUALOR_TRUST_PROXY` so each client is counted by its own address |
| SCIM answers 503 with `Retry-After` | the request collided with another change in the database, and changed nothing | none: the IdP retries it. If it persists, check the server log |
| SCIM answers 403 `FEATURE_NOT_LICENSED` | the licence does not list `scim`, or it lapsed. SCIM is in the Enterprise plan only, not in Business. Deprovisioning has stopped | apply an Enterprise key, or renew the licence, and restart. Meanwhile, deactivate leavers in **Settings → Users** |
| SCIM answers 409 `uniqueness` creating a user | the `userName` or `externalId` is already on the connection, or the email belongs to another Qualor account, such as one SCIM deleted earlier (its row stays) | change the old account's email. Or reactivate it and turn on linking by verified email, so the new SCIM user links to it |
| SCIM answers 400 `mutability` deactivating a user | the user is the last active instance admin, or the last break-glass admin while password sign-in is limited | make another instance admin or break-glass admin first |
| SCIM answers 400 `invalidFilter` | a filter other than one `eq` comparison on a supported attribute | see [SCIM](./sso-and-scim.md#scim-with-entra-id-and-okta) for what is supported |
| someone an admin deactivated is active again | the IdP sent `active: true` over SCIM, which overrides a deactivation made in Qualor | deactivate or unassign them at the IdP |

Still stuck? Open an issue on [GitHub](https://github.com/qualor-dev/qualor/issues) with the CLI
version (`qualor version`), the exit code and the debug log, tokens removed.
