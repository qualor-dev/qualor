# Jira

Qualor turns a code issue or a dependency vulnerability into a Jira issue with one click, or by
itself for new vulnerabilities. It shows the Jira key and the Jira status next to the finding. When
Qualor stops finding the problem, it says so in a comment on the Jira issue.

It works with Jira Cloud and with Jira Data Center or Server 9.0 or later. It is in every edition.
Jira Cloud now calls issues "work items". This guide says "Jira issue" for both.

An organisation admin connects Jira once. A project admin maps each project to a Jira project.
Everyone who may triage issues creates Jira issues.

## Before you start

- A Jira account that can browse the Jira project and create issues in it. Use an account that sees
  only the projects Qualor should write to: a project admin chooses the Jira project, and Qualor
  creates issues wherever the account may.
- Jira Cloud: the account's email and an API token.
- Jira Data Center or Server: a personal access token.
- `QUALOR_PUBLIC_URL` on the server. Without it Jira issues carry no link back to Qualor, and
  **Settings → Jira** warns about it ([Install the server](./install-server.md)).

## Connect Jira Cloud

In Qualor, an **org admin** opens **Settings → Jira**:

1. Choose **Jira Cloud**.
2. Enter the **Address** of your site, `https://your-site.atlassian.net`, with no path.
3. Enter the **Email** of the Atlassian account that owns the token.
4. Enter the **API token** ([create one](https://id.atlassian.com/manage-profile/security/api-tokens)).
5. Press **Save**, then **Test**. The test shows "Connected as <name>; N projects visible".

A Jira Cloud site must have a public address.

### A scoped token

A classic token works on the site address. A scoped token does not: Jira answers it with 401, 404,
or an empty project list. Use the API URL instead:

1. Open <https://admin.atlassian.com>, choose your site, and read the address. The cloud id follows
   `/s/`.
2. Enter `https://api.atlassian.com/ex/jira/<cloud id>` in **Scoped token? API URL**.
   The cloud id is a UUID.
3. Give the token the scopes `read:jira-user`, `read:jira-work` and `write:jira-work`.

With the API URL set, Qualor sends every call to it. Links for people still use the site address.

### Renew the token

A Jira Cloud token lives at most 365 days. When a connection that worked starts to answer 401,
create a new token and save it in **Settings → Jira**. A new token clears the problem.

## Connect Jira Data Center or Server

Version 9.0 or later. In **Settings → Jira**:

1. Choose **Jira Data Center or Server**.
2. Enter the **Address**: the base URL, with the context path if Jira has one, such as
   `https://jira.corp.example/jira`.
3. Enter a **Personal access token** (in Jira, **Profile → Personal Access Tokens**).
4. Press **Save**, then **Test**.

The address uses `https`. Qualor calls Jira only when it resolves to a public address, so list a
Jira on your network, or one over plain `http`, in `QUALOR_JIRA_INTERNAL_HOSTS`:

```sh
QUALOR_JIRA_INTERNAL_HOSTS=jira.corp.example.com            # https on 443
QUALOR_JIRA_INTERNAL_HOSTS=jira.corp.example.com:8443,10.0.0.12
```

At most 50 entries, each with an optional port. If Jira's certificate comes from a private CA, give
the server that CA with `NODE_EXTRA_CA_CERTS`
([Install the server](./install-server.md#server-settings)).

After repeated failed sign-ins, Jira Data Center locks the account with a CAPTCHA. Sign in to Jira in a
browser with that account and answer the CAPTCHA, or ask a Jira administrator to reset its failed
logins. Qualor then probes the account at most once an hour, because
every failed attempt extends the lockout.

## The connection

| Action | Result |
|---|---|
| **Save** | creates or updates the connection. The token is stored encrypted and never shown again |
| **Test** | calls Jira as the account and shows who it is and how many projects it sees |
| **Remove** | deletes the connection, the project mappings and the links. Jira keeps its issues |

Leave the token empty to keep the stored one. Changing the **Address**, the API URL or the
deployment needs the token again, and Qualor asks you to confirm: a new address is a different Jira,
and Jira issue ids repeat across sites. It deletes the mappings and links of the old one, shows how
many, and leaves the Jira issues in Jira. Changing only the email or the token keeps everything.

The page also counts the links by state: **Waiting**, **Created**, **Failed**, **Missing**,
**Unlinked**.

## Map a project

A **project admin** opens **Project → Settings → Jira**. The panel shows when the organisation has a
connection. Without one, an org admin sees a link to **Settings → Jira**.

| Field | Meaning |
|---|---|
| **Jira project** | search by key or name. The list holds the Jira projects the account sees, at most 50 |
| **Jira issue type** | the type Qualor creates, such as Bug or Task |
| **Labels** | up to 10 extra labels, separated by commas, each 1 to 100 characters without spaces. Qualor always adds `qualor` |
| **Priority by severity** | a Jira priority for Blocker, High, Medium, Low and Info |
| **Automatic creation** | [the rule](#the-automatic-rule), off by default |

A vulnerability uses the same scale: Critical is Blocker, and Unknown is Medium.

### Which issue types work

Qualor can create a type when it can fill every field the type requires. It fills the project, the
issue type, the summary, the description, the labels, and the priority when you set one for every
severity. Jira fills the reporter with the account of the token. A required field with a default is
no problem. A type with another required
field is shown disabled: "<name> — needs: <field names>". Choose another type, or ask the Jira
administrator to make those fields optional or give them a default.

Sub-task types are not offered. The description must be on the type's create screen. The labels
field is optional, but without it Qualor cannot find a Jira issue again after a lost answer, so that
create fails as "Qualor could not tell whether Jira created the issue." (see
[Troubleshooting](#troubleshooting)).

**Save** checks the type again. A type that became unsupported is refused with the field names.

**Remove mapping** stops new Jira issues for the project. Existing links stay and keep syncing.
Mapping the project to another Jira project later changes only the new issues.

## Create Jira issues

Qualor makes one Jira issue per finding:

- A **code issue** is a finding on the project's main branch. Issues on other branches and on merge
  requests get none.
- A **vulnerability** is one finding per project, package and vulnerability, however many branches
  and versions have it.
- A **Trivy issue** on the main branch or a tracked branch links through its vulnerability. The
  Issues tab and the Vulnerabilities tab show the same Jira issue.

A closed finding shows no button. Where the project has no mapping, a project admin sees **Map this project to Jira**.

| Where | How |
|---|---|
| The issue page | the **Jira** card, **Create Jira issue** |
| The **Issues** tab | select rows and **Create Jira issues**: at most 500 issues. A row that has a Jira issue shows a pill with its key, with no actions |
| The **Vulnerabilities** tab | **Create Jira issue** on a row, or tick rows, or **Select all on this page**, and **Create Jira issues**: at most 100 vulnerabilities |

The issue page shows **Creating…**, then the Jira key as a link, the Jira status and when Qualor read it
("checked 5 min ago"). A row of the Issues tab or the Vulnerabilities tab shows a pill: **Creating Jira
issue…**, then the key and the status, without the checked time.
A bulk request ends with a line such as "12 queued, 3 already linked, 1 not linkable".

Creation runs in the background. Each new Jira issue counts against the same per-user limit as
status changes: 120 a minute, with a burst of 500. A request over it is refused whole, and the
screen says when to try again.

The issue page's **Jira** card and a Vulnerabilities row offer the same actions. The card shows:

| State | What you see | What you can do |
|---|---|---|
| Waiting | **Creating…** | wait |
| Created | the key, the status, "checked 5 min ago" | **Unlink** |
| Failed | the reason | **Retry**, **Unlink** |
| Missing | "Not found in Jira" | **Create again**, **Unlink** |
| Unlinked | no link | **Create Jira issue** |

**Unlink** asks for confirmation. The Jira issue stays in Jira, Qualor stops updating it, and the
[automatic rule](#the-automatic-rule) never creates another one for that finding. **Create Jira
issue** on an unlinked, failed or missing finding makes a new Jira issue.

A person needs the permission to triage issues. A request needs a connection without a credential
problem and a mapped project: otherwise the screen says what is missing.

### What the Jira issue holds

| Part | Content |
|---|---|
| Summary | the issue's message, or `<vulnerability id> in <package> (<severity>)`. At most 255 characters |
| Description of a code issue | the rule, the message, the project, the branch, the file and line, the severity, the quality, when Qualor first saw it, and a link to the issue in Qualor |
| Description of a vulnerability | the title, the package and its installed versions, the fixed version or "no fixed version yet", the severity, the branches and versions that have it (at most 20, then "and N more"), the advisory link, and a link to the Vulnerabilities tab |
| With Business or Enterprise | for a vulnerability, **Exploited** (CISA KEV, with the date) and **EPSS** |
| Labels | `qualor`, your labels, and `qualor-<id>-<number>`. Do not remove the last one: Qualor finds a Jira issue again by it |
| Priority | the one you chose for the severity |

There is no code snippet: code stays in Qualor. Qualor shows everything that came from a report, a
rule or an advisory as plain text, so it cannot become a link, an image or a macro in Jira. The
links to Qualor appear only when the server has `QUALOR_PUBLIC_URL`.

## Status and comments

Every 15 minutes Qualor reads the Jira status of its linked issues. The status shows next to the
finding: grey for a new status, blue for one in progress, green for a done one (the status category). A Jira
issue that moved to another project keeps its link under the new key. A Jira issue that Qualor cannot
find in two passes in a row becomes **Missing**.

Qualor comments on the Jira issue, and never moves it through its workflow:

| When | Comment |
|---|---|
| Qualor no longer finds the issue or the vulnerability | "Qualor no longer finds … " |
| It finds it again | "Qualor finds this again: …" |

What counts as gone:

- **A code issue** is gone when Qualor closes it, after an analysis in which the analyzer ran. Won't
  fix, false positive and resolved are not gone.
- **A vulnerability** is gone when none of the tracked branches and versions has it any more, and no
  Trivy issue for it is open there. A triage decision (not affected, won't fix, `.trivyignore`) is
  not gone. A failed re-check removes nothing.
- While vulnerability monitoring is off, for the server or for the project, Qualor does not judge
  its vulnerability links: no comment either way.

Gone, back and gone again makes three comments. The comment names the branch and the date for a
code issue.

## The automatic rule

The rule creates Jira issues for new vulnerabilities, without a click. It is off by default.

In **Project → Settings → Jira**, **Automatic creation** takes one of **Off**, **Critical**,
**High and above**, **Medium and above**, **Low and above**. **Exploited vulnerabilities (CISA KEV)**
adds the exploited ones. It needs Business or Enterprise: the same feature that fills the CISA data
([Exploited and exploit probability](./dependency-vulnerabilities.md#exploited-and-exploit-probability-business-and-enterprise)).

| Rule | Behaviour |
|---|---|
| What counts | vulnerabilities **first found after you save**. Saving the rule, or changing its threshold, never creates Jira issues for the backlog |
| New | as the Vulnerabilities tab means it ([New vulnerabilities](./dependency-vulnerabilities.md#new-vulnerabilities)). A first check of a branch or version is a baseline and creates nothing |
| A target tracked again | a version or branch that is tracked again counts what appeared while it was untracked as new, as the tab does |
| Exploited | a vulnerability that CISA added to the catalogue on or after the day you saved, or that is new |
| Unknown severity | never counts by severity |
| Pace | at most 50 new Jira issues per organisation in one 15-minute pass. The rest follow in the next passes |
| Unlinked | a finding whose link you removed is never created again |
| Needs | vulnerability monitoring on for the project. The panel says when it is off |

No audit entry records an automatic Jira issue, because Qualor acts, not a person.

## Permissions

| To do this | Permission | Role |
|---|---|---|
| See, save, test and remove the connection | `org.jira.manage` | Organization admin |
| Map a project, set the rule | `project.settings` | Project admin and above |
| Create, retry and unlink Jira issues | `issue.triage` | Maintainer and above |
| See the Jira links | `project.read` | everyone who reads the project |

Every change is in the [audit log](./roles-and-audit.md#what-is-recorded). The token and the email
never are.

## Troubleshooting

A problem shows under **Settings → Jira**, in the project's Jira panel, and in the result of
**Test**. Problems that need an admin stop new Jira issues: the pass makes one probe call and
resumes when it succeeds. A timeout or an unreachable Jira blocks nothing.

| Problem | Cause | Fix |
|---|---|---|
| `token_refused` | Jira answered 401: the token expired, was revoked, or the email is wrong | create a new token. A Jira Cloud token lives at most 365 days. Save it with the email |
| `no_projects` | a scoped token on the site address | set the **API URL** ([A scoped token](#a-scoped-token)), or give the account access to a project |
| `captcha` | Jira Data Center locked the account | sign in to Jira in a browser with that account and answer the CAPTCHA, or ask a Jira administrator to reset its failed logins. Qualor probes at most hourly |
| `redirected` | the address redirects, often to a sign-in proxy or the wrong host | enter the final address of Jira |
| `bad_answer` | the answer was not Jira data, often a sign-in page | use the address of Jira itself |
| `url_not_allowed`, `not_public` | the host is private, or `http` | the operator lists it in `QUALOR_JIRA_INTERNAL_HOSTS`. Jira Cloud needs a public address |
| `unresolved`, `unreachable`, `timeout` | the server cannot reach Jira, or it is down | check the address and the network. Passes try again |
| `not_found` | Jira could not find what was asked for, or the account cannot see it | check the address and the Jira project, and that the account sees it |
| `http_error` | Jira answered with an error Qualor cannot use | try again later |
| `rate_limited` | Jira asked Qualor to slow down (HTTP 429) | nothing: Qualor tries again later |
| "The finding is closed or can no longer have a Jira issue." (`finding_gone`) | the finding was deleted, or was closed, before the Jira issue was made | nothing to do |
| `permission_missing` | the account may not browse or create | give it Browse projects and Create issues in the Jira project |
| `undecryptable` | the server key `QUALOR_SECRET_KEY` changed | enter the token again |
| A failed Jira issue shows Jira's own reason | Jira refused a field, such as a required one or an unknown label | fix the field in Jira or in the mapping, then **Retry** |
| The type shows "needs: …" | the type requires fields Qualor cannot fill | [Which issue types work](#which-issue-types-work) |
| "Qualor could not tell whether Jira created the issue" | the answer to a create was lost, and the screen has no labels to look for it | look in Jira for the finding. **Retry** creates it again |
| "The project had no Jira mapping when the Jira issue was to be created." | the mapping was removed before creation | map the project, then **Retry** |
| `limit_reached` | Jira refused the request as too large | shorten the labels of the mapping, or ask the Jira administrator about the limit |
| Jira issues have no link back to Qualor | `QUALOR_PUBLIC_URL` is not set on the server | set it |
| Nothing is created and no problem shows | the project is not mapped, or vulnerability monitoring is off for an automatic rule | check the panel |

More in [Troubleshooting](./troubleshooting.md).
