# Portfolio reports

The portfolio shows the quality of many projects at once. It answers how many pass their quality
gate, how they are rated, and how much code there is and how well it is tested. It also shows how
many findings are open, how that has moved, and which projects need attention first.

The portfolio needs an enterprise licence listing `portfolio`, which only the Enterprise plan lists
([Plans and prices](./enterprise.md#plans-and-prices)). Without it, **Portfolio** is not in the top
bar.

## What the portfolio shows

**Portfolio**, in the top bar after **Quality gates**, has a row for each project of one
organisation, or of every organisation. Every signed-in user can open it, whatever their role.

The page works the numbers out each time you open it, from the analyses, measures and issues Qualor
already has. Nothing is stored, so the portfolio is as current as the last scan. You can download
the same view as **CSV** (one row per project) or **PDF** (for management).

## Who sees what

The portfolio counts **exactly the projects you can read**: the projects that **Projects** (and
`GET /api/v0/projects`) list for you. Two people looking at the same organisation can see different
numbers.

| You are | You see |
|---|---|
| an instance admin | every project of every organisation |
| a member of an organisation (any role) | every project of that organisation |
| someone with a role on single projects only | those projects (their organisations appear under **All organisations**) |

Switch the scope with **This organisation** and **All organisations** in the page header:

- **This organisation** is the organisation chosen in the header's organisation switcher.
- **All organisations** covers every organisation in which you can read at least one project. It
  adds the **Organisations** table, one row per organisation, sorted by key.

The page's address keeps the scope and the period, for example
`/portfolio?scope=all&granularity=month`. A link to **All organisations** opens the same view for
whoever opens it, with the projects they can read. A link to **This organisation** opens the
organisation chosen in the recipient's header.

## How the numbers are worked out

**One branch per project.** Each project is measured on its **main branch**. Other branches and
merge requests count only in the number of analyses per period (see [Trends](#trends)).

**The last successful analysis.** A project's state is that of the newest **successful** analysis of
its main branch: its quality gate and the measures recorded with it. Failed and queued analyses are
skipped. A project with no successful analysis of its main branch is **never analyzed**: it counts
in the number of projects, but has no gate, no ratings and no measures. "Last analysis" is when
Qualor received the upload, not the commit date the scanner reports.

**What each project contributes:**

- the quality gate: **Passed**, **Failed**, **Error** or **No gate**;
- the security and reliability ratings, A to E (the measures `security_rating` and
  `reliability_rating`, 1 = A to 5 = E; see [Quality gates, profiles and
  issues](./quality-gates.md));
- lines of code (`ncloc`), coverage and duplication (`duplicated_lines_density`);
- the open issues, by severity (blocker, high, medium, low, info), by quality (security,
  reliability, maintainability) and in new code;
- secrets (open Gitleaks findings) and vulnerable dependencies (open Trivy findings);
- vulnerable releases and exploited vulnerabilities, when [vulnerability
  monitoring](./dependency-vulnerabilities.md) is on.

The issues of a [licence policy](./dependency-licenses.md) (the **licensing** quality) are left out
of every count.

The issue counts and the ratings are the measures recorded with the last analysis, so triage since
then shows at the next scan. Secrets and vulnerable dependencies are counted from the main branch's
open findings as they are now, leaving out those Qualor marks as the duplicate of another. They have
no trend.

**Vulnerable releases** is the number of the project's tracked versions with at least one open
vulnerability (not ignored). **Exploited** is the number of distinct vulnerabilities that are open,
listed in CISA KEV and not delisted, on the main branch or a tracked version. Both are current state
with no trend. A project whose monitoring is off, or any project while the instance switch is off,
has neither number: they show as a dash and stay out of the totals. KEV needs Business or
Enterprise (`vuln.priority`, which Enterprise includes). Without it, **Exploited** is not shown
anywhere: not on the page, in the CSV values, or in the PDF.

**Adding projects up:**

- **Projects** counts every project. **analyzed** counts those with a successful analysis.
- **Gate pass share** is the share of the analyzed projects whose gate passed. Projects with
  **Error** or **No gate** count against it. Projects never analyzed do not count at all.
- **Ratings** show how many projects are rated A, B, C, D and E.
- **Lines of code** and the issue counts are sums.
- **Coverage** and **duplication** are weighted by lines of code: a project of 100 000 lines weighs
  a hundred times more than one of 1 000. Only projects with both the value and a line count take
  part.
- A measure a project does not have, such as coverage, is left out of every total. It never counts
  as zero.

**Abandoned** means no successful analysis of the main branch in the **last 30 days**, or never
analyzed. The threshold is fixed.

## Trends

**Weeks** and **Months** in the page header set the trend's period: the last **12 weeks** or the
last **12 months**, oldest first.

- A week is an ISO week, from Monday 00:00 UTC. A month is a calendar month in UTC.
- The last point is the **current**, unfinished week or month, up to the moment you opened the page.
- Each point shows the portfolio as it was at the **end** of its period: every project at its newest
  successful main-branch analysis uploaded before that moment. A project created after the end of a
  period is not in that point. A project counts as abandoned at a point when it had no successful
  main-branch analysis in the 30 days before the point's end.
- Two counts cover the whole period instead of its end:
  - **Analyses**: the successful analyses of every branch and merge request of the projects,
    uploaded in the period;
  - **Triage decisions**: how many times a finding of the projects was marked false positive or
    won't fix in the period.

The page draws six charts: gate pass share, coverage, lines of code, open issues, analyses and
triage decisions. **Show as a table** under each chart gives the same numbers as a table.

## Needs attention

Five lists of up to **10 projects** each, every project linked to its page. The first needs
`vuln.priority`:

| List | Which projects | Order |
|---|---|---|
| **Exploited vulnerabilities** | at least one exploited vulnerability | the most first |
| **Failing quality gates** | the gate failed | the most blocker and high issues first |
| **Worst security ratings** | rated B to E (A-rated projects never appear) | the worst rating first, then the most security issues |
| **Most blocker and high issues** | at least one blocker or high issue | the most first |
| **Not analyzed in 30 days** | abandoned | never analyzed first, then the oldest last analysis |

Ties are broken by project key. Keys compare character by character, by their code, so `API` comes
before `api`.

## The page

From the top:

1. **Totals**, as cards. The ratings show as stacked bars.
2. The **trend** charts.
3. **Organisations** (all organisations only): each organisation's projects, gate pass share, lines
   of code, coverage, duplication, open issues and abandoned projects.
4. **Needs attention**: the five lists.
5. **Projects**: every project you can read in the scope, 50 at a time (**Load more** for the next
   ones), each linked to its page. A column header sorts the table:

   | Column | Order |
   |---|---|
   | Project | the organisation key, then the project key, A to Z |
   | Quality gate (the first sort) | Failed, Error, No gate, Passed, then never analyzed; within each, the worst security rating first (E to A, then unrated) |
   | Security, Reliability | E first, then D to A, then unrated |
   | Issues, Lines of code | the highest first, then the projects without a value |
   | Coverage | the lowest first, then the projects without a value |
   | Vulnerable releases, Exploited | the highest first, then the projects without a value (**Exploited** needs `vuln.priority`) |
   | Last analysis | never analyzed first, then the oldest |

When the scope holds no project, the page says "No projects you can read yet."

## Downloads

**CSV** and **PDF** in the page header download the scope on screen.

**CSV** is UTF-8 with a byte-order mark, so Excel reads it, and its lines end in CRLF. It has one
row for every project you can read in the scope, sorted by organisation key, then project key.

- The columns are `organization_key`, `organization`, `project_key`, `project`, `last_analysis_at`,
  `abandoned`, `gate`, `security_rating`, `reliability_rating`, `ncloc`, `coverage`, `duplication`,
  `issues`, `blocker`, `high`, `medium`, `low`, `info`, `new_issues`, `secrets`,
  `vulnerable_dependencies`, `vulnerable_releases` and `exploited_vulnerabilities`.
- `last_analysis_at` is a UTC time such as `2027-10-12T09:30:00.000Z`. `abandoned` is `true` or
  `false`. `gate` is `passed`, `failed`, `error` or `none`. The ratings are `A` to `E`. `coverage`
  and `duplication` are percentages.
- `exploited_vulnerabilities` is always a column. Without `vuln.priority` its cells are empty.
- A value the project does not have is an empty cell, and so is every measure of a project never
  analyzed.
- A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so a
  spreadsheet never runs it as a formula.
- The CSV has no trend, so **Weeks** or **Months** does not change it.

**PDF** is A4. Every page has the scope at the top, and "Page n of m" with the time it was made at
the bottom. The sections:

1. the cover: the scope, when it was made and by whom, the server version and the trend period;
2. the totals, as cards, with the gate and rating counts, the vulnerable releases and, with
   `vuln.priority`, the exploited vulnerabilities;
3. the trend: line charts of the gate pass share, coverage, lines of code and open issues, and the
   tables of every point, with the analyses and triage decisions per period;
4. the organisations (all organisations only);
5. the attention lists, **Exploited vulnerabilities** first (with `vuln.priority`);
6. the projects, with their vulnerable releases and exploited vulnerabilities: the first **50** by
   quality gate (Failed first, then the worst security rating).
   With more projects, the PDF says that the CSV lists every one.

The PDF's font, Noto Sans, covers Latin, Cyrillic and Greek. A project name in another script prints
as a missing-glyph box. The CSV keeps it as it is.

The file is named `qualor-portfolio-<organisation key>-<yyyymmdd>`, or `qualor-portfolio-all-…` for
all organisations, with `.csv` or `.pdf`. The date is the day of the download in UTC. In the file
name the key is lower-cased, and characters outside `a`–`z`, `0`–`9` and `-` become `-`. A key with
nothing left becomes `organization`.

The portfolio is not a stored record: every scan changes the numbers, so two downloads at different
times can differ. Downloads are sent with `Cache-Control: no-store`, so no proxy or browser keeps a
copy. The [audit log](./roles-and-audit.md#what-is-recorded) does not record opening or downloading
the portfolio.

## Limits

- **20 seconds** for each database query behind the portfolio. Above that, the page says "The
  portfolio took too long to compute; try one organisation.", and the API answers 503
  `PORTFOLIO_TIMEOUT`. One organisation is less work than all of them.
- **One download at a time** per person.
- **60 seconds** to make a PDF. A PDF that takes longer is refused.

The links are plain downloads, so a refused download shows up only as a failed download in your
browser, with no message on the page. The answers are in [The API](#the-api).

## When the licence lapses

When the licence lapses or no longer lists `portfolio`, **Portfolio** leaves the top bar. The page
at `/portfolio` says that it needs an enterprise licence with the portfolio feature, and every
`/api/v0/ee/portfolio` route answers 403 `FEATURE_NOT_LICENSED`. Nothing is lost: the portfolio
keeps no data of its own, and a renewed key brings it back as it was.

## The API

The routes are under `/api/v0/ee/portfolio`, described in
[`enterprise/openapi.json`](../../enterprise/openapi.json). They need a session or a personal token
with the **Read** scope. A project analysis token is refused. Every route takes the scope as
`scope=organization&organizationId=…` (the organisation's id, from `GET /api/v0/organizations`) or
`scope=all`.

| Route | What it does |
|---|---|
| `GET /ee/portfolio?scope=…&granularity=week` (or `month`; `week` without it) | the view: `generatedAt`, `totals`, `organizations` (all scope; `null` otherwise), the 12 `trend` points (each with `start`, `end`, the totals at `end`, `analyses` and `triage`) and the four `attention` lists |
| `GET /ee/portfolio/projects?scope=…&sort=gate&limit=50` | a page of project rows. `sort` is `key` (without it), `gate`, `security`, `reliability`, `issues`, `ncloc`, `coverage`, `lastAnalysis`, `vulnerableReleases` or `exploited`, in the orders of the projects table; `limit` is 1 to 100, 50 without it; pass `nextCursor` as `cursor` for the next page |
| `GET /ee/portfolio/export?scope=…&format=csv` (or `pdf`, with `granularity`) | the file, as described in [Downloads](#downloads) |

| Answer | Meaning |
|---|---|
| 422 `VALIDATION_FAILED` | a query that is not valid: `organizationId` missing with `scope=organization` or given with `scope=all`, an unknown parameter or value, a `limit` above 100, a `cursor` that is not one Qualor gave out |
| 404 | the organisation does not exist or you cannot see it |
| 403 `FEATURE_NOT_LICENSED` | the licence does not list `portfolio` |
| 429 `RATE_LIMITED` | another of your exports or downloads is still running: wait for it |
| 503 `PORTFOLIO_TIMEOUT` | the numbers took longer than 20 seconds, or the PDF longer than 60 seconds: try one organisation |

In the JSON, shares are fractions: `passedShare` is `0.8` for 80 %. `coverage` and `duplication` are
percentages. A value with nothing to count (no project analyzed, no project with coverage) is
`null`, and so is each value a project does not have.

```sh
H="Authorization: Bearer $QUALOR_TOKEN"
P="$QUALOR_URL/api/v0/ee/portfolio"

curl -fsS -H "$H" "$P?scope=all&granularity=month"           # the view, by month
curl -fsS -H "$H" "$P/projects?scope=all&sort=security"      # the worst security ratings first
curl -fsS -H "$H" -o portfolio.csv "$P/export?scope=all&format=csv"
```
