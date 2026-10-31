# Dependency vulnerabilities

**Project → Vulnerabilities** lists the known vulnerabilities in the dependencies of your tracked
branches and versions, and lets you decide on each one once for the whole project. The server finds
them by matching each target's dependency list with its own copy of the Trivy database
([The vulnerability database](./vulnerability-database.md)). A scan does not have to run.

The tab sits between **Issues** and **Dependencies**. Everything on this page is in every edition.

## When the tab shows

The tab shows when both switches are on:

| Switch | Where |
|---|---|
| **Vulnerability monitoring** | **Settings → Vulnerability database**, for the instance |
| **Track vulnerabilities in this project** | **Project → Settings → Vulnerability monitoring** |

With either one off, the tab and the badge are hidden. Decisions still work and are kept, so the
store is complete when you switch monitoring on again.

Without data, the tab says "No vulnerability data yet." Instance admins get a link to **Settings →
Vulnerability database**. Everyone else is told to ask an instance admin. A project with no
released versions shows the CI snippets of
[Record a version on each tag](./releases.md#record-a-version-on-each-tag).

## By version

**By version** is the default view. It has one row per tracked target:

- the main branch,
- the branches that match the project's branch patterns,
- the tracked versions ([Which versions are tracked](./releases.md#which-versions-are-tracked)).

| Column | Meaning |
|---|---|
| **Branch or version** | the name, with **Pinned** for a pinned version and "No dependency list" for a target without one |
| **Critical**, **High**, **Medium** | the open vulnerabilities of that severity. Low and Unknown show on the cards only |
| **New** | "N new": see [New vulnerabilities](#new-vulnerabilities) |

A count leaves out the vulnerabilities that a decision closed (Not affected, Won't fix) and the
ones that `.trivyignore` ignores ([The `.trivyignore` file](#the-trivyignore-file)).

Select a row to see that target's vulnerabilities as cards.

Versions that are not tracked fold into one line, such as "2.1.9 · 2.0.5 · 14 more — not tracked".
**Show** lists them with "Not tracked" and the counts they kept. **Hide** folds them again.

The menu of a version row changes how the version is tracked. It needs the permission to change
the project's settings (Organization admin and Project admin, [Roles](./roles-and-audit.md#roles)).

| Menu entry | Effect |
|---|---|
| **Pin** | the version is tracked, whatever the rule says |
| **Unpin** | removes the pin: the rule decides |
| **Mark as unsupported** | the version is never tracked |
| **Track automatically** | removes the mark: the rule decides |

The marks are the ones of [Releases and versions](./releases.md#which-versions-are-tracked).

## By vulnerability

**By vulnerability** shows one card per vulnerability across all tracked targets. Select a row of
**By version** to see the cards of one target.

| On the card | Meaning |
|---|---|
| id, severity | the vulnerability's id and its severity (Critical, High, Medium, Low or Unknown) |
| package | the package, and "installed → fixed", or "No fixed version" |
| **In** / **Not in** | the targets that have the vulnerability, and the tracked ones that do not |
| "Found <date>" | when Qualor first saw it. " without a scan" means the server found it after a new database, with no new analysis |
| "Ignored in .trivyignore" | the card is dimmed and does not count |
| the decision | a triaged card is dimmed and shows its status and reason, or "Reason not given" |

Two filters narrow the list:

| Filter | Options |
|---|---|
| **Status** | All, Open, Not affected, Won't fix |
| **Severity** | All, Critical, High, Medium, Low, Unknown |

## New vulnerabilities

A target shows "N new" for the vulnerabilities that need a decision. A vulnerability counts as new
when it is all of these:

- open, with no decision that closes it;
- not ignored by `.trivyignore`;
- found by the server after its first re-check that followed the target's latest analysis.

| Target | When "new" clears |
|---|---|
| A branch | with its next analysis, or when the vulnerability is triaged |
| A version | when the vulnerability is triaged, or the version stops being tracked. A rescan of the same tag also resets it |

Right after you upgrade to 0.15, nothing is new: what the server finds first is the baseline. A
branch or version that starts to be tracked shows nothing new from its first re-check either.

The **badge** "New vulnerabilities in main and 2 versions" shows in the projects list and on the
project page. It names the main branch, the number of branches and the number of versions with new
vulnerabilities, such as "New vulnerabilities in 3 versions". It links to the tab.

## Statuses and reasons

Triage sets a **status** for a vulnerability in a package:

| Status | Meaning | Reason | Comment |
|---|---|---|---|
| **Open** | needs a decision | no | optional |
| **Not affected (false positive)** | the project is not exposed | required | required |
| **Affected, won't fix** | the project is exposed and accepts it | no | required |

A comment has at most 2000 characters. The decision records who made it and when.

The reason says why the project is not affected. The reasons are the five VEX justifications, in
plain words:

| Reason in the UI | OpenVEX justification |
|---|---|
| The package is not in the build | `component_not_present` |
| The vulnerable code is not in the build | `vulnerable_code_not_present` |
| The vulnerable code is never called | `vulnerable_code_not_in_execute_path` |
| An attacker cannot control the input | `vulnerable_code_cannot_be_controlled_by_adversary` |
| Another control already protects it | `inline_mitigations_already_exist` |

**Change status** on a card opens the dialog. It needs the permission to triage issues
(Maintainer and above). A Viewer reads the tab and sees no **Change status** button.

### One decision, a wide scope

A decision belongs to a package name and a vulnerability id. It covers the whole project: the main
branch, all branches and all versions. The ecosystem is not part of the key.

**Applies to** narrows a decision to one branch or version. That decision overrides the project's
decision on that target, and nowhere else. When you save a project-wide decision from a target's
view, the dialog can remove that target's override in the same step.

Decisions are written whether monitoring is on or off.

## Trivy issues on the Issues tab

A Trivy vulnerability is also an issue of the Trivy engine. Both places use the same decisions.

| You do this | What happens |
|---|---|
| Set a Trivy issue on `main` or on a tracked branch to Won't fix or False positive | the project's decision changes. If that branch has a decision of its own, that decision changes instead |
| Reopen such an issue | the decision becomes Open |
| Resolve such an issue | nothing is written. The next dependency list shows whether the package changed |
| Triage a Trivy issue on another branch or in a merge request | the issue changes and no decision is written |

The other direction:

- A project decision that is not Open sets the matching Trivy issues on `main` and on tracked
  branches to that status, and closes out the open ones everywhere else.
- A new Trivy issue takes the decision at ingestion.
- Resolved and closed issues never change.
- A branch with its own decision is not changed by a project-wide decision.

The status dialog of the Issues tab asks for a **Reason** when you set False positive on such an
issue. It says "Select a reason." until you do. A Trivy issue without a package name that Qualor can
read writes no decision and asks for no reason.

The decisions also change the gate: Won't fix and false positive issues do not count
([Issue statuses](./quality-gates.md#issue-statuses)).

### Migrated decisions

On upgrade, each False positive and Won't fix Trivy issue on `main` became a project decision with
no reason. When several issues share a package and vulnerability, the latest one counts, and its
comment becomes the decision's comment. The tab shows "Reason not given" and the Issues tab asks for
a reason at the next edit.

## The `.trivyignore` file

The scanner sends the ids that the repository's `.trivyignore` ignores, with their `exp:` dates
([The vulnerability database](./vulnerability-database.md#the-re-check)). A vulnerability ignored
there shows dimmed with "Ignored in .trivyignore". It is not counted and is never new.

## The rate limit

A decision counts as 1, plus 1 for each issue it changes, against the per-user budget of issue
changes. The Issues tab uses the same budget: 120 changes a minute, with a burst of 500. Beyond it
the API answers 429 `RATE_LIMITED` with a `Retry-After` header, and a decision is not saved.

## The API

| Route | Needs | Answers |
|---|---|---|
| `GET /api/v0/projects/:id/vulnerabilities/targets` | read access to the project | the tracked targets with their counts and `new`, the untracked versions, the data date and the last check |
| `GET /api/v0/projects/:id/vulnerabilities` | read access | the vulnerabilities, as cards. Query: `target` (`branch:<id>` or `version:<id>`), `status` (`all`, `open`, `false_positive`, `wont_fix`), `severity`, `page`, `pageSize` (50 by default, at most 100) |
| `PUT /api/v0/projects/:id/vulnerability-decisions` | `issue.triage` | the decision and `appliedIssues`, the number of issues it changed |

A decision is a body like this:

```sh
q -X PUT "$QUALOR_URL/api/v0/projects/<project id>/vulnerability-decisions" -d '{
  "packageName":"lodash","vulnerabilityId":"CVE-2021-23337","scope":{"kind":"project"},
  "status":"false_positive","reason":"vulnerable_code_not_in_execute_path",
  "comment":"Only used in a build script"}'
```

- `scope` is `{"kind":"project"}`, or `{"kind":"branch","id":"…"}` or `{"kind":"version","id":"…"}`.
  A merge request has no decisions.
- `reason` is one of the five OpenVEX values above. It is required for `false_positive` and
  refused for any other status.
- `replaceOverrideOf` removes a target's decision in the same step. It needs a project-wide scope.
- The pair must exist in the project, or the answer is 404.

`POST /issues/{id}/transition` and `POST /issues/bulk-transition` accept the same `reason`.

| Code | When |
|---|---|
| `REASON_REQUIRED` (422, `body.reason`) | a false positive that writes a project decision has no reason |
| `COMMENT_REQUIRED` (422, `body.comment`) | Not affected or Won't fix has no comment |

The [MCP](./mcp.md) tool `qualor_transition_issue` accepts an optional `reason` too.

A decision is an audit event, `vulnerability.decision_changed`
([Roles and the audit log](./roles-and-audit.md#what-is-recorded), Enterprise).
