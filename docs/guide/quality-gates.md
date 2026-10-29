# Quality gates, profiles and issues

A **quality gate** decides whether an analysis passes. A **quality profile** decides which findings
become issues. An issue's **status** records your team's decision about it.

## Judge new code

Qualor's default gate judges only **new code**: the lines a change adds or modifies. Old problems
stay visible, but they do not block merge requests. The gate asks three questions:

- Did the change add any issue?
- Is the new code covered by tests?
- Is the new code duplicated?

You can add conditions on the overall numbers too.

## New code

New code is what changed since a **baseline**. The baseline depends on what is analysed:

| Analysis of | Baseline |
|---|---|
| a merge request / pull request | `merge-base(revision, target branch)` |
| another branch | `merge-base(revision, reference branch)`, by default the main branch |
| the main branch | the project's **new-code definition**, below |

Set the main branch's definition in **Project → Settings → New code**, or with `newCodeDefinition`
in the API ([Projects](./users-projects-tokens.md#projects)):

| Definition | Baseline |
|---|---|
| `{ "type": "days", "value": 30 }` (default); **Default (30 days)** or **Last days** in the UI | the oldest analysis of the last 30 days (**Last days** takes 1 to 3650) |
| `{ "type": "previous_version" }`; **Since the previous version** | the latest analysis with another `project.version`, for example `${CI_COMMIT_TAG}` |
| `{ "type": "analysis", "analysisId": "…" }`; **From a specific analysis** | a fixed analysis, chosen from the main branch's recent analyses |

The panel shows the analysis new code is measured from. It warns when no analysis has a version
label yet (the last 30 days are used instead), and when the chosen analysis is gone.

An issue is **new** when its line is in new code. A newly enabled rule that flags old lines
therefore does not fail merge requests.

The baseline comes from git, so CI jobs need the **full history** (`GIT_DEPTH: 0`,
`fetch-depth: 0`). Without a baseline, new-code conditions end in `error` and the gate fails: Qualor
does not guess.

## The built-in gate: "Qualor way"

| Condition | Fails when |
|---|---|
| `new_issues` | > 0 |
| `new_coverage` | < 80 % |
| `new_duplicated_lines_density` | > 3 % |

It is every organisation's default, and it is read-only. To change it, press **Copy** in its row of
**Quality gates** or on its page, and edit the copy. Then make the copy the default, or assign it to
single projects (`qualityGateId`).

- On merge requests and branches, only `new_*` conditions count.
- **Small changes:** below 20 new lines, the coverage and duplication conditions on new code are
  ignored. A 5-line fix is not blocked by a coverage percentage.
- A value that cannot be computed, such as coverage without a coverage report, shows as **no
  value**. It does not fail the gate.
- Changing a gate does not re-judge past analyses. Changing an issue's status does ([Issue
  statuses](#issue-statuses)).

To get an email when a project's gate fails, press **Watch** on the project's page ([Project
notifications](./email.md#project-notifications)).

### Metrics you can use in conditions

| Group | Metrics (add `new_` for the new-code version) |
|---|---|
| Issues | `issues`, `blocker_issues`, `high_issues`, `medium_issues`, `low_issues`, `info_issues`, `security_issues`, `reliability_issues`, `maintainability_issues` |
| Licences ([Dependency licences](./dependency-licenses.md#gate-metrics)) | `licensing_issues`, `forbidden_licenses` (the policy's issues, Business and Enterprise), `unknown_licenses_ratio` (overall only: the share of dependencies with an unknown licence, every edition) |
| Ratings (1 = A … 5 = E) | `security_rating`, `reliability_rating` |
| Coverage | `coverage`, `line_coverage`, `branch_coverage`, `lines_to_cover`, `uncovered_lines`, `conditions_to_cover`, `uncovered_conditions` |
| Duplication | `duplicated_lines`, `duplicated_blocks`, `duplicated_lines_density` |
| Triage (overall only) | `accepted_issues` (won't fix), `false_positive_issues` |
| Size and complexity (overall only) | `files`, `lines`, `ncloc`, `comment_lines`, `functions`, `classes`, `statements`, `complexity`, `cognitive_complexity` |
| New-code size | `new_lines` |

A rating is the worst severity among the open issues of that quality: A for none or info only, B for
low, C for medium, D for high, E for blocker.

A condition is a metric, `gt` or `lt`, and a threshold, for example `new_security_rating gt 1`. A
gate has at most one condition per metric. To edit a condition, change its operator or threshold in
its row on the gate's page, and press **Save** or Enter. Escape drops the change. A rating's
threshold shows as its letter: 1 is A.

Common additions:

- `new_security_issues gt 0`: no new vulnerabilities, secrets or vulnerable dependencies, even when
  you relax `new_issues`.
- `new_blocker_issues gt 0` and `new_high_issues gt 0` instead of `new_issues gt 0`: a softer start
  on a noisy codebase.
- `security_rating gt 3` on the main branch: an overall floor.
- `new_forbidden_licenses gt 0`: no new dependency under a licence your organisation's policy
  forbids, even when you relax `new_issues` (Business and Enterprise).

## Quality profiles: which rules count

A **quality profile** decides which analyzer rules become issues, and at which severity. There is
one per language (`typescript`, `javascript`, `java`, `csharp`, `python`, `html`, `css`, `kotlin`,
`swift`, `php`, `ruby`, `go`, `c`, `cpp`), plus `*` for everything else: secrets, dependencies,
OpenGrep, external SARIF and files without a language. The built-in profiles are called "Qualor
way".

- To change one, press **Copy** in its row of **Quality profiles**. In the copy, turn rules on or
  off and override severities, then make the copy the default.
- A profile can **inherit** from a parent of the same language, up to 3 levels, and change only the
  rules it names.
- **Rules it does not set** (**Not set here** in a profile's rules) follow its `unknownRules`
  setting: `activate` (the default) or `ignore`. With `activate`, a new ESLint plugin rule shows up
  without anyone editing the profile. The analysis warnings count the findings a profile drops.
- A profile change applies **from the next analysis**.

Your analyzer configuration still decides what runs: the ESLint config, PMD ruleset, `.editorconfig`
or `.gitleaks.toml`. The profile filters and re-grades what the analyzers report.

**Rules** lists every rule the organisation has met, with its engine, language, quality and default
severity.

### Rule scope: main code, test code or all code

Every rule has a **scope**. A rule with the scope **Main code** reports nothing in test files, a
rule with **Test code** reports nothing in main files, and **All code** reports everywhere. **Rules**
shows each rule's scope. A rule is **All code** unless its analyzer says otherwise. Most of the
bundled `sonarjs` rules are **Main code** (262 of 328). The rules of your own ESLint, including
`eslint:sonarjs/*`, have no scope. Qualor's own security rules (`qualor:*`) see main files only, so
a scope of **Test code** or **All code** changes nothing for them. A scanner before 0.13 sends no
scope: its findings count in all code unless a quality profile sets the scope.

- To change a rule's scope, open the profile (an organization admin can), then pick **Main code**,
  **Test code** or **All code** in the rule's **Scope** column. **Rule's default** shows when this
  profile sets no scope of its own, with the scope in force beside it, and removes the profile's own
  scope again.
- A child profile inherits the scope its parent sets, and can set its own.
- Setting a scope on a profile copies its activation into a row of its own. A child with no row for
  the rule follows that row: when the two profiles differ in their setting for rules they do not
  set, the rule turns on or off in the child.
- A change of scope alone also pins the activation and severity the profile inherits. **Inherit
  again** undoes it.
- Test files are the ones `tests.include` matches ([Languages and
  analyzers](./languages-and-analyzers.md)). A finding without a file, or in a file the report does
  not list, is never dropped for its scope.
- When an analysis drops findings for their scope, it warns, for example "3 finding(s) were dropped
  because their rule does not apply to test code" (or "… to main code").

## Severities and qualities

| Severity | Meaning |
|---|---|
| blocker | must fix before merging: a real vulnerability, a leaked secret, a certain crash |
| high | very likely a bug or a security problem |
| medium | a probable problem, or a significant maintainability issue |
| low | a minor issue |
| info | information only |

Each rule also has a **quality**: security, reliability, maintainability or licensing. **Licensing**
holds the issues of the organisation's [licence policy](./dependency-licenses.md) (Business and
Enterprise). It has no rating, and its issues never count as security issues.

Qualor's C# taint engine marks some findings **Possible**: the path it followed goes through stored
data, a lookup or a call it could not narrow down ([C#](./languages-and-analyzers.md#c)). Check the
path before you act. The mark does not change the severity, the gate or the counts.

## Issue statuses

| Status | Set by | Meaning |
|---|---|---|
| open | system / user | an active problem |
| resolved | user | "fixed". If the next analysis still finds it, it reopens |
| won't fix | user, **comment required** | accepted as is. It stays so across analyses |
| false positive | user, **comment required** | the analyzer is wrong. It stays so across analyses |
| closed | system | no longer detected. If it comes back within 30 days, its earlier won't fix or false positive is restored |

Won't fix and false positive issues do not count in the gate. A status change re-judges the branch's
latest gate result **without a new scan**. It also updates the merge request comment, the commit
status or the check run. The issue's changelog records every change.

The [AI assistant](./ai-assistant.md) can suggest whether an issue looks like a false positive.
Marking the issue still takes a person and their own comment, and the changelog records that the
suggestion was shown.

An issue keeps its identity when code moves. Its fingerprint is the rule, the path and the
surrounding code, and it tolerates line shifts. When two analyzers report the same finding, Qualor
shows one issue.

Merge requests and branches inherit the target branch's statuses. A false positive marked on `main`
stays a false positive in every merge request.

## Browsing the code

A project's **Code** tab lists the analysed files by directory, with lines of code, complexity,
coverage, duplication and open issues. Press a column heading to sort. The branch picker switches to
another branch or a merge request. **Browse code** on a branch's overview opens the tab for that
branch.

A file's page shows its measures, duplicated blocks and issues, and a **Line map** of the whole file
with four lanes: **Coverage**, **New code**, **Duplicated blocks** and **Issues, by severity**.

- Point at the map to read what is on each line. Or press Tab to focus it and move line by line with
  the arrow keys. Page Up and Page Down jump further, Home and End go to the first and last line,
  and Escape lets go.
- Click an issue's mark, or press Enter on its line, to open the issue.
- Links from the issue list or the duplicated blocks jump to a line: the address ends in `#L<line>`.

**Source code stays in your repository.** Qualor keeps measures, line numbers and messages, never
the text of your files. Read the code in your repository's own viewer.

## Related locations

Some analyzers report the other places that explain an issue, such as the line that assigned a bad
value. SARIF calls them related locations, and Qualor keeps the ones in the SARIF reports it
receives. The issue's page lists them under **Related locations**, in the analyzer's order, each
with its message and a link to that line in the **Code** tab. Beyond five, the rest wait behind **N
more**.
