# Quality gates, profiles and issues

## The idea: judge new code

Legacy code is what it is. A quality gate that fails on old problems gets switched off within a week.
Qualor's default gate therefore looks only at **new code**, meaning the lines a change adds or
modifies. It asks three questions:

- Did the change add any issue?
- Is the new code covered by tests?
- Is the new code duplicated?

The overall numbers stay visible in the UI, and you can add conditions on them too.

## New code

New code is always "the lines changed between a **baseline** and the analysed revision". The
baseline depends on what is analysed:

| Analysis of | Baseline |
|---|---|
| a merge request / pull request | `merge-base(revision, target branch)` |
| another branch | `merge-base(revision, reference branch)`, by default the main branch |
| the main branch | the project's **new-code definition**, below |

New-code definitions for the main branch (`newCodeDefinition` of the project, set through the API):

| Definition | Baseline |
|---|---|
| `{ "type": "days", "value": 30 }` (default) | the oldest analysis of the last 30 days |
| `{ "type": "previous_version" }` | the latest analysis with another `project.version`, for example `${CI_COMMIT_TAG}` |
| `{ "type": "analysis", "analysisId": "…" }` | a fixed analysis |

An issue is **new** when its line lies in new code. So a newly enabled rule that flags old lines does
not suddenly fail merge requests.

The baseline comes from git, so CI jobs need the **full history** (`GIT_DEPTH: 0`, `fetch-depth: 0`).
If the baseline cannot be found, new-code conditions end in `error`, and Qualor fails the gate rather
than guess.

## The built-in gate: "Qualor way"

| Condition | Fails when |
|---|---|
| `new_issues` | > 0 |
| `new_coverage` | < 80 % |
| `new_duplicated_lines_density` | > 3 % |

It is the default for every organisation, and it is read-only. To change it, press **Copy** in its
row of **Quality gates** (or on the gate's own page), edit the copy, and make it the default, or
assign it to single projects (`qualityGateId`).

Rules of evaluation:

- On merge requests and branches, only `new_*` conditions count.
- **Small changes:** below 20 new lines, the coverage and duplication conditions on new code are
  ignored. So a 5-line fix is not blocked by a coverage percentage.
- A value that cannot be computed, such as coverage when no coverage report was imported, is shown as
  **no value**. It does not fail the gate.
- Changing a gate does not re-judge past analyses. Changing an issue's status does re-judge the
  branch's latest analysis at once.

### Metrics you can use in conditions

| Group | Metrics (add `new_` for the new-code version) |
|---|---|
| Issues | `issues`, `blocker_issues`, `high_issues`, `medium_issues`, `low_issues`, `info_issues`, `security_issues`, `reliability_issues`, `maintainability_issues` |
| Ratings (1 = A … 5 = E) | `security_rating`, `reliability_rating` (from the worst severity among open issues of that quality) |
| Coverage | `coverage`, `line_coverage`, `branch_coverage`, `lines_to_cover`, `uncovered_lines`, `conditions_to_cover`, `uncovered_conditions` |
| Duplication | `duplicated_lines`, `duplicated_blocks`, `duplicated_lines_density` |
| Size and complexity (overall only) | `files`, `lines`, `ncloc`, `comment_lines`, `functions`, `classes`, `statements`, `complexity`, `cognitive_complexity`, `accepted_issues`, `false_positive_issues` |
| New-code size | `new_lines` |

A condition is `metric`, `gt` or `lt`, and a threshold, for example `new_security_rating gt 1`. A gate
has at most one condition per metric. On a gate's page, change a condition's operator or threshold in its row and
press **Save**, or Enter; Escape drops the change. A rating's threshold shows its letter: 1 is A.

Common additions:

- `new_security_issues gt 0`: no new vulnerabilities, secrets or vulnerable dependencies, even when
  you relax `new_issues`.
- `new_blocker_issues gt 0` and `new_high_issues gt 0` instead of `new_issues gt 0`, for a softer
  start on a noisy codebase.
- `security_rating gt 3` on the main branch: an overall floor.

## Quality profiles: which rules count

A **quality profile** decides which analyzer rules become issues, and at which severity. There is one
profile per language (`typescript`, `javascript`, `java`, `csharp`, `python`, `html`, `css`,
`kotlin`, `swift`, `c`, `cpp`) plus `*` for everything else: secrets, dependencies, OpenGrep, external SARIF,
and files without a language. The built-in profiles are called "Qualor way".

- Press **Copy** in a built-in profile's row of **Quality profiles**, then turn rules on or off in
  the copy, override a severity, and make the copy the default.
- A profile may **inherit** from a parent of the same language (up to 3 levels), and changes only the
  rules it names.
- **Rules it does not set** (shown as **Not set here** in a profile's rules) follow the profile's
  `unknownRules` setting: `activate` (the default) or `ignore`. With `activate`, a new ESLint plugin rule shows up
  without anyone editing the profile. Findings the profile drops are counted in the analysis warnings.
- A profile change applies **from the next analysis**.

The analyzers' own configuration still decides what runs: your ESLint config, PMD ruleset,
`.editorconfig`, `.gitleaks.toml`. The profile filters and re-grades what the analyzers report.
Qualor keeps the team's configuration in the repository, where reviewers see it.

**Rules** lists every rule the organisation has met, with its engine, language, quality and default
severity.

## Severities and qualities

| Severity | Meaning |
|---|---|
| blocker | must fix before merging: a real vulnerability, a leaked secret, a certain crash |
| high | very likely a bug or a security problem |
| medium | a probable problem, or a significant maintainability issue |
| low | a minor issue |
| info | information only |

Each rule also has a **quality**: security, reliability or maintainability.

## Issue statuses

| Status | Set by | Meaning |
|---|---|---|
| open | system / user | an active problem |
| resolved | user | "fixed". If the next analysis still finds it, it reopens |
| won't fix | user, **comment required** | accepted as is. It stays so across analyses |
| false positive | user, **comment required** | the analyzer is wrong. It stays so across analyses |
| closed | system | no longer detected. If it comes back within 30 days, its earlier won't fix or false positive is restored |

Won't fix and false positive issues do not count in the gate. Changing a status re-evaluates the
branch's latest gate result and updates the merge request comment, the commit status or the check
run, **without a new scan**. Every change is recorded in the issue's changelog.

With the optional [AI assistant](./ai-assistant.md), a person can ask a model whether an issue looks
like a false positive. The answer is only a suggestion: marking the issue still takes a person and
their own comment, and the changelog records that the suggestion was shown.

Issues keep their identity when code moves. The fingerprint is the rule, the path and the surrounding
code, and it tolerates line shifts. When two analyzers report the same finding, only one issue is
shown.

Merge requests and branches inherit the statuses of the target branch. A false positive marked on
`main` stays a false positive in every merge request.
