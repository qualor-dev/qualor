# Compliance reports

A compliance report maps the security findings of a project branch, a project version or an
organisation to five security standards, at one point in time. It needs an enterprise licence
listing `compliance-export`, which only the Enterprise plan lists ([Plans and
prices](./enterprise.md#plans-and-prices)). Without it, the **Compliance** tab and **Settings →
Compliance reports** are not shown.

## What a report is

A report covers one **project branch** (the main branch unless you choose another), one **project
version** (a released version, which holds its dependencies only), or a whole **organisation** (the
main branch of each of its projects). It holds:

- the open findings, mapped to five security standards;
- secrets and vulnerable dependencies, listed on their own;
- every triage decision, with who made it, when and why;
- each project's quality gate and a short security trend.

Qualor builds the report once, when you ask for it. Later scans, triage and upgrades never change
it. You download it as JSON, CSV or PDF, and its SHA-256 lets anyone check a copy. A report of a
branch or version that has a dependency inventory also attaches its
[SBOM](#the-attached-sbom).

## Which findings count

A report counts the **security-relevant** issues of the branch as they are when the report is built:

- every issue whose rule has a CWE id (Gitleaks secrets count as CWE-798);
- every issue of the **security** quality;
- every security hotspot.

The issues of a [licence policy](./dependency-licenses.md) (the **licensing** quality) are not
security findings and never count.

An issue's status decides where it appears:

| Status | In the report |
|---|---|
| open | the findings, counted in the standards |
| false positive, won't fix | the triage decisions: who set the status, when, and the comment (the first 1 000 characters) |
| resolved, closed | left out |

An issue that Qualor marks as the duplicate of another (the same problem on the same line, found by
a second analyzer) counts once, as the issue it duplicates.

Findings are split into three sections, each counted on its own: **secrets** (Gitleaks),
**dependencies** (Trivy) and **code** (every other analyzer).

## Dependencies and vulnerabilities

Each dependency finding and each dependency triage decision names its vulnerability. The facts come
from the server's own vulnerability data for the same branch or version
([Dependency vulnerabilities](./dependency-vulnerabilities.md)):

| Field in the JSON | What it holds |
|---|---|
| `vulnerability.id` | the vulnerability id, for example `CVE-2026-0001` |
| `vulnerability.packageName` | the affected package |
| `vulnerability.fixedVersions` | the versions that fix it, sorted, without duplicates; empty when none does |
| `vulnerability.kev` | `{ "dateAdded": … }` when CISA lists the vulnerability as exploited, else `null` |
| `vulnerability.epss` | `{ "score": …, "percentile": … }` from FIRST EPSS, else `null` |

- **`vulnerability` is `null`** for code findings and secrets, when vulnerability monitoring is off
  for the project, and for a branch the project does not track, because its vulnerability rows are
  frozen.
- **`kev` and `epss` are `null`** without `vuln.priority`, which Business and Enterprise include.
- **`firstSeenAt`** is the date the issue was first found on a branch, and the earliest date of the
  version's rows on a version.

**Reasons.** A dependency triage decision carries `reason`, the reason of the decision that
applies to it: one of the five VEX justifications of
[Statuses and reasons](./dependency-vulnerabilities.md#statuses-and-reasons), or `null` for a
decision without one. Other triage decisions have `null`. The CSV has the column
`triage_reason`, and the PDF's triage table has a **Reason** column.

**Dataset dates.** `datasets` says which data the report was built from:

| Field | Meaning | Without |
|---|---|---|
| `vulnerabilityDatabase` | when the vulnerability database was built, and its digest | `null` while monitoring is off |
| `kev` | when the KEV list was refreshed, and its digest | `null` without `vuln.priority` |
| `epss` | the day of the EPSS data, when it was refreshed, and its digest | `null` without `vuln.priority` |

The PDF cover lists the dates.

## The standards

| Standard | Id in the report | Where the CWE lists come from | Licence |
|---|---|---|---|
| OWASP Top 10 2021 | `owasp-top10-2021` | the "List of Mapped CWEs" of each category, [owasp.org/Top10/2021](https://owasp.org/Top10/2021/) | CC BY-SA 4.0, by the OWASP Foundation |
| OWASP Top 10 2025 | `owasp-top10-2025` | the same, for the 2025 edition, [owasp.org/Top10/2025](https://owasp.org/Top10/2025/) | CC BY-SA 4.0, by the OWASP Foundation |
| CWE Top 25 2025 | `cwe-top25-2025` | MITRE's [2025 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html), one category per CWE, in rank order | MITRE CWE Terms of Use. Copyright © 2006–2026, The MITRE Corporation. CWE is a trademark of The MITRE Corporation |
| OWASP ASVS 4.0.3 | `asvs-4.0.3` | the CWE column of the [ASVS 4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3) requirements, grouped by chapter (V1 to V14) | CC BY-SA 4.0, by the OWASP Foundation |
| PCI DSS 4.0.1 requirement 6.2.4 | `pci-dss-4.0.1-6.2.4` | **Qualor's own mapping** of CWE ids to the six kinds of attack the requirement names | part of Qualor Enterprise |

How a finding is matched:

- **By exact CWE id.** A finding belongs to every category whose list holds one of its rule's CWE
  ids. A child CWE does not count in its parent's category. In the CWE Top 25, a finding with
  CWE-564 (SQL injection through Hibernate, a child of CWE-89) does not count under CWE-89.
- **A finding can count in more than one category.** A standard's category totals can therefore add
  up to more than its number of findings. The standard's total counts each finding once.
- **Not mapped.** A finding that matches no category of a standard counts in that standard's **Not
  mapped** row, so every standard accounts for every open finding.
- **PCI DSS 6.2.4 is Qualor's mapping, not the PCI Security Standards Council's.** The requirement
  names kinds of attack, not CWE ids, so Qualor maps CWE ids to them itself. The category titles
  paraphrase the requirement. The last of the six categories, **High-risk vulnerabilities**, takes
  every **blocker** and **high** finding, whatever its CWE. Treat the mapping as a starting point
  for your assessor, not as their verdict.
- **ASVS is 4.0.3**, not 5.0: ASVS 5.0 publishes no CWE mapping.

## Creating a report

| Report of | Who can create it | Who can see it and download it |
|---|---|---|
| a project branch or version | Organization admins and Project admins (the permission `project.compliance.create`) | everyone who can read the project |
| an organisation | Organization admins (`org.compliance.manage`) | every member of the organisation, whatever their role |

Instance admins can do everything. Someone with a role only on some projects of an organisation, and
none in the organisation itself, sees the reports of their projects but not the organisation's.
**Settings → Compliance reports** tells them that only members of the organisation can see those.

- **A project:** open **Project → Compliance**, choose the **Branch** (the main branch is selected;
  merge requests have no report) and press **Create report**. The branch needs at least one
  successful analysis.
- **A version:** on the same page, choose a version under **Target** and press **Create report**.
  The report holds the version's dependencies only, because a version has no code analysis: no
  code findings, no secrets, no quality gate and no trend. Two conditions apply:
  - vulnerability monitoring is on for the project, else 409 `MONITORING_OFF`;
  - the version has been checked for vulnerabilities, else 409 `NOT_CHECKED`. Wait for the next
    check.
- **An organisation:** open **Settings → Compliance reports** for the organisation chosen in the
  header's organisation switcher, and press **Create report**. A project that was never analysed is
  in the report as **Never analysed**. An organisation report covers at most **2 000** projects.
  Above that, the report fails with "too many projects for one report".

The report is built in the background. It shows as **Pending**, then as **Ready**, without a page
reload.

- While a report of a project (a branch or a version) or an organisation is pending, you cannot
  create another report of the same project or organisation.
- Qualor builds one report at a time for the whole installation, so a report may wait for another.
- A report that fails shows **Failed** with a reason: create a new one. A report still not ready an
  hour after it was created is marked failed with "the build did not finish".

Each report in the list shows when it was created, by whom, the branch or version, its
status, the number of open findings, and the start of its SHA-256 with **Copy** for the full value.

**Summary** shows the report on the page: the category table of each standard (pick it under
**Standard**), then the counts of the open findings, the findings in new code, the secrets, the
vulnerable dependencies and the triage decisions. The lists themselves are in the PDF, the CSV and
the JSON. Each project's gate is in the PDF and the JSON.

A report holds at most **50 000** findings and **50 000** triage decisions. Above that, the lists
stop and the counts stay exact. The page, the PDF and the JSON (`summary.truncated`) say so.

## The formats

Every report downloads as **JSON**, **CSV** and **PDF**, with the links next to it. A report that
attaches an SBOM adds an **SBOM** link. The file is named
`qualor-compliance-<project or organisation key>-<yyyymmdd>-<first 8 characters of the id>`, with
`.json`, `.csv`, `.pdf` or `.cdx.json`.

**JSON is the canonical record.** It is the report exactly as Qualor built and stored it, and the
CSV and the PDF are made from it. It holds:

- the scope, the time, who created it and the server version;
- the standards with their sources;
- the dataset dates and the attached SBOM's hash;
- each project with its last analysis, its gate (with the failed conditions) and up to 12 points of
  security trend;
- the summary counts;
- every finding, with its categories in each standard;
- every triage decision.

**CSV** is UTF-8 with a byte-order mark, so Excel reads it, and its lines end in CRLF.

- The columns are `section`, `project`, `path`, `line`, `rule`, `rule_name`, `engine`, `severity`,
  `kind`, `cwe`, `status`, `in_new_code`, `first_seen_at`, one column per standard, then
  `triage_by`, `triage_at`, `triage_comment`, `triage_reason`, `vulnerability_id`, `fixed_versions`,
  `kev_date_added`, `epss_score` and `epss_percentile`. A standard's column is named by its id, and
  holds the finding's category ids, separated by `;`. `fixed_versions` separates versions by `;`.
  The last five columns are empty for a row without vulnerability facts.
- The open findings come first, then the triage decisions (`status` is `false_positive` or
  `wont_fix`).
- A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so a
  spreadsheet never runs it as a formula.

**PDF** is A4. Every page has the scope at the top, and "Page n of m" with the report id at the
bottom. The sections:

1. the cover: the scope, when the report was built and by whom, the server version, the report id,
   the **SHA-256 of the JSON export**, the dataset dates, the attached SBOM and the standards with
   their sources and licences. The SBOM line reads "SBOM: CycloneDX 1.6, <n> components, SHA-256
   <hex>". A report of a version says "Version <label>. A version has no code analysis, so this
   report holds its dependencies only.";
2. the executive summary: the open findings by severity, the dependencies, the findings in new code,
   the secrets, the triage counts, each project with its gate, and the failed gate conditions. A
   report of one project adds its security trend;
3. one page or more per standard: each category with its open findings, by severity, in new code,
   the number of rules and the oldest finding, then **Not mapped**;
4. secrets and dependencies, rule by rule;
5. the triage decisions: the **2 000** newest, with their **Reason**;
6. the findings: the first **2 000**, by severity.

A list cut at 2 000 points to the CSV and JSON exports for the rest. In a report cut at 50 000
findings or triage decisions, the "first n of m" and "newest n of m" lines give the exact totals,
and the secrets and dependencies tables cover only the listed findings ("Rules among the listed
findings").

In the executive summary, a project's **Security issues** is the `security_issues` measure of its
last analysis. It can differ from the report's findings, which are counted when the report is built
([Which findings count](#which-findings-count)).

The PDF's font, Noto Sans, covers **Latin, Cyrillic and Greek**. Text in other scripts (Chinese,
Japanese, Korean, Arabic, Hebrew and others) prints as a missing-glyph box, for example in a file
path or a triage comment. The JSON and the CSV keep such text as it is.

### The attached SBOM

A report of a project branch or version attaches the software bill of materials (SBOM) of its
target, as it was when the report was built.

| | |
|---|---|
| Which reports | a project report, branch or version, whose target has a dependency inventory, while the licence lists `sbom` (Business and Enterprise include it) |
| Which do not | an organisation report: one file for up to 2 000 projects would be too large. Download each project's report, or use the [SBOM export](./dependency-vulnerabilities.md#export-sbom-and-vex-business-and-enterprise) |
| Format | CycloneDX 1.6 JSON, `application/vnd.cyclonedx+json; version=1.6`, file name ending `.cdx.json` |
| Serial number | `urn:uuid:<the report id>` |
| Hash | the SHA-256 of the file is in the report's JSON as `sbom.sha256`, with `sbom.format` and `sbom.components`; the PDF cover prints it |

The SBOM is stored with the report, so it downloads the same bytes for a year, whatever happens to
the dependencies later. A report without one has `"sbom": null`, and its **SBOM** link is not shown.

It answers two common audit questions: the list of software components that PCI DSS 4.0.1
requirement 6.3.2 asks for, and the component inventory that the EU Cyber Resilience Act expects of
a product. Check a copy with `sha256sum`, as for the JSON ([Verifying a
report](#verifying-a-report)).

### When a download fails

You can have one download running at a time. The links are plain downloads, so a refusal shows up
only as a failed download in your browser, with no message on the page:

| Answer | Meaning |
|---|---|
| 429 `RATE_LIMITED` | another of your downloads is still running: wait for it |
| 503 `REPORT_RENDER_TIMEOUT` | the PDF took longer than 60 seconds to make. The JSON and the CSV of the same report still download |
| 409 `REPORT_NOT_READY` | the report is pending or failed |
| 404 `NOT_FOUND` | the SBOM of a report that attaches none |
| 403 `FEATURE_NOT_LICENSED` | the licence no longer lists `compliance-export` |

Downloads are sent with `Cache-Control: no-store`, so no proxy or browser keeps a copy.

## Verifying a report

The SHA-256 on the PDF's cover, in the list and in the API (`sha256`) is the SHA-256 of the JSON
download. To check a copy of the report, compare them:

```sh
sha256sum qualor-compliance-payments-api-20271012-0192a3b4.json
# the same 64 hex characters as "SHA-256 of the JSON export" on the PDF's cover
```

On Windows, `Get-FileHash <file> -Algorithm SHA256` in PowerShell gives the same value, in capitals.

The JSON is stored as it was built, so it always downloads the same bytes. The server makes the CSV
and the PDF from it the same way every time, though a later Qualor release may lay them out
differently. The SBOM has its own hash, `sbom.sha256` in the JSON.

`schemaVersion` is 2 for every new report. A report built before Qualor 0.15 has `schemaVersion`
1: it downloads as it was built, and its CSV and PDF show the new columns empty. Version 2 adds:

- `datasets`, `sbom` and `scope.version`;
- `vulnerability` on every finding and triage decision, and `reason` on every triage decision.

Read the JSON by `schemaVersion`, and treat a field that version 1 lacks as `null`.

When the licence lists `audit-log`, the [audit log](./roles-and-audit.md#what-is-recorded) records
creating, downloading and deleting reports. Each download is recorded with its format and the
SHA-256 of the file (the SBOM's own for `sbom`).

## Retention

A report is kept for **one year** from when it was created, then deleted automatically. An
Organization admin can delete one sooner with **Delete**, in **Settings → Compliance reports** or on
the project's **Compliance** tab. A pending report cannot be deleted. Deleting a project or an
organisation deletes its reports.

**When the licence lapses** or no longer lists `compliance-export`:

- the reports are kept, and nothing is deleted, not even reports older than a year;
- the **Compliance** tab and **Settings → Compliance reports** are not shown;
- every `/api/v0/ee/compliance` route answers 403 `FEATURE_NOT_LICENSED`;
- a report that was being built is not finished. After the renewal it shows as failed: create it
  again.

With a renewed key, everything is back, and reports past their year are deleted at the next hourly
clean-up.

## How the standards are updated

The standards ship with Qualor. The server never downloads them, so it works in air-gapped networks,
and the standards never change between releases. A new edition of a standard, such as a new CWE Top
25, comes with a Qualor release, as a new standard beside the previous one. Each standard keeps its
two newest editions.

A report carries its own categories, titles and the SHA-256 of the standard data it used, so an
upgrade does not change it. New reports use the standards of the running release.

## The API

The routes are under `/api/v0/ee/compliance`, described in
[`enterprise/openapi.json`](../../enterprise/openapi.json). Reading needs a personal token with the
**Read** scope. Creating and deleting need **Admin**.

| Route | What it does |
|---|---|
| `POST /ee/compliance/reports` with `{"projectId": "…", "branchId": "…"}` (`branchId` optional, the main branch without it), `{"projectId": "…", "versionId": "…"}` or `{"organizationId": "…"}` | creates a report; answers 202 with the report, `"status": "pending"`. `branchId` with `versionId` is 422. 404 `NOT_FOUND` for a version of another project; 409 `MONITORING_OFF` and 409 `NOT_CHECKED` (version); 409 `REPORT_PENDING` while another report of the same scope is pending; 409 `NO_ANALYSIS` if the branch has no successful analysis |
| `GET /ee/compliance/reports?projectId=…` or `?organizationId=…` | the reports of a project, or the organisation reports of an organisation, newest first, 20 at a time (`limit` up to 100; pass `nextCursor` as `cursor`) |
| `GET /ee/compliance/reports/{id}` | one report: its status, `sha256`, `sbom` (`{ "sha256": … }` or `null`), size, error and summary counts |
| `GET /ee/compliance/reports/{id}/download?format=json` (or `csv`, `pdf`, `sbom`) | the file. 409 `REPORT_NOT_READY` while it is pending or failed; 404 `NOT_FOUND` for `sbom` when the report attaches none |
| `DELETE /ee/compliance/reports/{id}` | deletes a ready or failed report (Organization admins); 204 |

A report you cannot see answers 404, as everywhere in the API.

```sh
H="Authorization: Bearer $QUALOR_TOKEN"
R="$QUALOR_URL/api/v0/ee/compliance/reports"

curl -fsS -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"projectId":"<project id>"}' "$R"                     # → {"id":"<report id>","status":"pending",…}
curl -fsS -H "$H" "$R/<report id>"                             # repeat until "status":"ready"
curl -fsS -H "$H" -o report.json "$R/<report id>/download?format=json"
sha256sum report.json                                          # equals the report's "sha256"
```
