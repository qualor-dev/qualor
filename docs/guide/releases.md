# Releases and versions

Qualor records each release of a project as a **version**: a label and the release's dependency
list. A scan in a tag pipeline records it. The GitLab component and the GitHub workflow templates
run that scan on every tag.

A project's rules decide which of its versions are tracked. The settings panel, the
**Dependencies** tab and the API show which ones are. Qualor does not check versions for
vulnerabilities yet.

## Record a version on each tag

### GitLab

The job of the [CI/CD component](./gitlab.md#with-the-cicd-component-recommended) runs on tags. A
[job without the component](./gitlab.md#without-the-component) needs this rule among its `rules`:

```yaml
rules:
  - if: $CI_COMMIT_TAG
```

### GitHub

The workflows of [GitHub](./github.md#2-the-workflow) run on tags. If your workflow has no `tags`
under `push`, add them:

```yaml
on:
  push:
    tags: ['**']
```

The tag scan uses the job's token and settings. It needs nothing else.

### Other CI systems

Pass the tag with `--tag`:

```sh
qualor scan --tag "$TAG_NAME"
```

- `--tag` cannot be combined with `--branch` or `--mr`.
- The name has at most 255 characters, and git must accept it as a tag name.

### Releases you shipped earlier

Check out each release tag and scan it, as in [A local scan](./other-ci.md#a-local-scan):

```sh
for tag in v2.1.4 v2.2.3 v2.3.1; do
  git checkout --quiet "$tag"
  docker run --rm -v "$PWD":/src -w /src -e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY \
    qualor/scanner:0.15 scan --tag "$tag"
done
```

Scan the oldest first, because Qualor orders versions by the date of their scan.

## What a tag scan does

A tag scan collects only the dependency list.

| | Scan of a branch or merge request | Tag scan |
|---|---|---|
| Analyzers, metrics, duplication and coverage | run | do not run |
| SARIF files and coverage reports | read | not read. The analysis shows the warning `TAG_SCAN_IGNORES_INPUTS` |
| The dependency list (Trivy's licence pass) | unless `analyzers.trivy.licenses: false` | always |
| Issues, measures and the quality gate | yes | no |
| Comments, commit status, webhooks and emails | yes | no |

- A tag scan is quick, because no code analyzer runs.
- It applies no quality gate. The release's code was already checked on its branch and in merge
  requests.
- It needs Trivy. With `analyzers.trivy.enabled: false`, it exits 2.
- When Trivy is not installed, the scan warns `LICENSE_SCAN_FAILED`. A new version then has no
  packages, and a version scanned before keeps its own. The scanner images include Trivy.
- A server older than 0.15 cannot record versions. The scanner then uploads nothing, warns, and
  exits 0, so the release pipeline does not fail.
- With C#, the job still runs `qualor dotnet begin` and your build. `qualor dotnet end` then
  records the version and reads no Roslyn log.
- To run the full scan with the quality gate in a tag pipeline, pass `--branch <name>`. The
  analysis then belongs to that branch.

## The version label

A version's label is `project.version` from `qualor.yml` when it is set. Otherwise it is the tag's
name, such as `v2.3.4`.

- A label has at most 100 characters. A longer tag needs a shorter `project.version`. Without one,
  the scanner exits 2 before the upload.
- Scanning the same label again replaces that version's packages. A scan without a dependency list
  leaves them as they are. The version keeps its pin or unsupported mark.
- A tag scan that started before the stored tag scan of its label fails with `STALE_ANALYSIS`. The
  stored packages stay.

## Exit codes

| Code | When |
|---|---|
| 0 | the server recorded the version, and the scanner logged `Recorded version <label>`. With `--no-wait` or `gate.wait: false`, the scanner exits 0 right after the upload. With a server older than 0.15, it uploads nothing and exits 0 with a warning |
| 2 | `--tag` with `--branch` or `--mr`, a tag name git does not accept, a label longer than 100 characters, or `analyzers.trivy.enabled: false` |
| 4 | the server did not record the version. The scanner prints the server's code and message, such as `STALE_ANALYSIS`. Also when the server has not confirmed the version within `gate.timeoutSeconds`: the scanner says the version was uploaded but not confirmed |

Codes 2, 4 and 5 also have their usual causes ([CLI reference](./cli.md#exit-codes)). A tag scan
never exits 1 or 3: it has no quality gate and no required analyzer.

## Which versions are tracked

The rule is set under **Released versions** in [the settings panel](#the-settings-panel).

A label is a **version number** when it has two to four numbers separated by dots, with an optional
`v` in front, such as `2.3`, `2.3.4` or `v2.3.4`. Its **line** is its first two numbers: `2.3.4` is
in line `2.3`. A **pre-release** is a version number with a part after a `-`, such as `2.4.0-rc.1`
or `2.4.0-SNAPSHOT`.

| Rule | Tracked versions |
|---|---|
| **The newest version of each line** (the default) | the highest version of each of the newest N lines. `2.3.4` replaces `2.3.0` to `2.3.3`. N is 1 to 20, and 5 by default |
| **Every version** | every version |
| **None** | none |

- **The newest version of each line** tracks labels that are not version numbers by date: the N
  scanned most recently.
- No rule tracks a pre-release.
- **Now tracked** lists the tracked labels, the most recently scanned first, up to 50.
- A version that is not tracked keeps its packages.

A version's mark decides whether the rule applies. You set it through the API
([The API](#the-api)):

| Mark | Effect |
|---|---|
| `pinned` | the version is tracked, whatever the rule says |
| `unsupported` | the version is never tracked |
| `auto` | no mark: the rule decides |

An unsupported version still counts as the newest of its line. Its line's older versions stay
untracked.

## The settings panel

**Project → Settings → Vulnerability monitoring** holds these settings. Organization admins and
project admins change them.

| Setting | Meaning |
|---|---|
| **Track vulnerabilities in this project** | on by default. Versions are recorded whether it is on or off |
| **Branches** | the tracked branches: the main branch, always, and those that match **And branches matching** |
| **Released versions** | the rule of [Which versions are tracked](#which-versions-are-tracked) |
| **Also take versions from branch analyses that carry project.version** | off by default. See [Version labels on branch analyses](#version-labels-on-branch-analyses) |

- **And branches matching** takes up to 10 patterns, such as `release/*`, separated by commas.
- **Matches now** lists the branches that match them.

While the project has no version, the panel shows the two CI snippets of
[Record a version on each tag](#record-a-version-on-each-tag).

## Version labels on branch analyses

With **Also take versions from branch analyses that carry project.version** on, an analysis of a
tracked branch records a version too. The tracked branches are those of the panel's **Branches**.
The version's label is `project.version`, and its packages are that analysis's.

Turn it on only when `project.version` changes once per release, not with every build. Otherwise
each analysis records a new version.

- Merge request analyses never record a version.
- Pre-release labels, such as `2.4.0-SNAPSHOT` or `2.4.0-rc.1`, are skipped.
- A later analysis with the same label replaces the version's packages.
- A branch analysis never replaces a version that a tag scan recorded. A tag scan with the same
  label replaces a version taken from a branch.
- An analysis without a dependency list records no version, for example with
  `analyzers.trivy.licenses: false`.

## A version's packages

**Project → Dependencies** shows a version's packages. Choose the version under **Versions** in the
**Branch** picker ([The Dependencies tab](./dependency-licenses.md#the-dependencies-tab)).

## The API

```sh
# the versions, the latest scan first, with their tracking
q "$QUALOR_URL/api/v0/projects/<project id>/versions"

# pin a version ("unsupported" marks it unsupported, "auto" removes the mark)
q -X PATCH "$QUALOR_URL/api/v0/projects/<project id>/versions/<version id>" \
  -d '{"tracking":"pinned"}'

# a version's packages
q "$QUALOR_URL/api/v0/projects/<project id>/dependencies?version=<version id>"

# the panel's settings, read and saved
q "$QUALOR_URL/api/v0/projects/<project id>/vulnerability-monitoring"
q -X PUT "$QUALOR_URL/api/v0/projects/<project id>/vulnerability-monitoring" -d '{"enabled":true,
  "branchPatterns":["release/*"],"versionRule":{"kind":"lines","lines":5},"labelVersions":false}'
```

`q` is the helper of [Webhooks and REST API](./webhooks-and-api.md#rest-api).

- `GET /projects/{id}/versions` pages with `limit` (1 to 100, 50 by default) and `cursor`. Each
  version has:
  - `id`, `label`, `tag` and `analyzedAt`, the date of its scan;
  - `source`: `tag`, or `label` for a version taken from a branch analysis;
  - `tracking`: the mark, `auto`, `pinned` or `unsupported`;
  - `tracked` and `trackingReason`, below;
  - `prerelease`, and `packages`, the number of packages.
- `PATCH /projects/{id}/versions/{versionId}` takes `{"tracking": …}` and answers the version.
- `GET /projects/{id}/vulnerability-monitoring` answers the four settings, plus `mainBranchName`,
  `matchingBranches` (up to 50), `trackedVersions` and `versionCount`. `trackedVersions` holds up
  to 50 labels, the most recently scanned first.
- `PUT /projects/{id}/vulnerability-monitoring` takes all four settings:
  - `enabled`, true or false;
  - `branchPatterns`, up to 10 patterns of 1 to 255 characters. A pattern that is not a valid glob
    answers 422 `VALIDATION_FAILED`;
  - `versionRule`: `{"kind":"lines","lines":N}` with N from 1 to 20, `{"kind":"all"}` or
    `{"kind":"none"}`;
  - `labelVersions`, true or false.
- The two reads need read access to the project. `PATCH` and `PUT` need the right to change project
  settings, and a personal token needs the **Admin** scope for them.
- `GET /analyses/{id}` of a tag scan answers `version` (`id` and `label`), `"branch": null`, and
  the gate status `none`.
- With `audit-log`, changes are recorded as `project.vulnerability_monitoring_updated` and
  `project_version.updated` ([Roles and the audit log](./roles-and-audit.md#what-is-recorded)).

| `trackingReason` | Tracked | Why |
|---|---|---|
| `pinned` | yes | the version is pinned |
| `unsupported` | no | the version is marked unsupported |
| `prerelease` | no | a pre-release |
| `newest_in_line` | yes | the highest version of one of the newest N lines |
| `replaced` | no | its line has a higher version |
| `older_line` | no | its line is not among the newest N |
| `recent` | yes | not a version number, and among the N scanned most recently |
| `older` | no | not a version number, and scanned before the most recent N |
| `rule_all` | yes | the rule is **Every version** |
| `rule_none` | no | the rule is **None** |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `BRANCH_REQUIRED` in a tag pipeline | the scanner is older than 0.15, or the server is older than 0.15 and did not report its version | upgrade both to 0.15 or later |
| exit 0 and no version, with the warning "The server is older than 0.15 and cannot record versions; upgrade the server to record releases" | the server is older than 0.15. The scanner uploaded nothing | upgrade the server to 0.15 or later, then scan the tag again |
| exit 2, "A version label is at most 100 characters; set project.version" | `project.version` is not set, and the tag is longer than 100 characters. The scanner refuses the label before the upload. The server would fail it with `VERSION_LABEL_INVALID` | set `project.version` to a label of at most 100 characters |
| exit 4, `STALE_ANALYSIS` | a newer tag scan of the same label was stored first | none needed: the newer packages stay |
| the version has no packages, and the scan warned `LICENSE_SCAN_FAILED` | Trivy did not run | use the scanner image ([Dependencies (Trivy)](./languages-and-analyzers.md#dependencies-trivy)) |
| the version has no packages, and no `LICENSE_SCAN_FAILED` | the repository has no lockfile Trivy reads | see [Which ecosystems give licences](./dependency-licenses.md#which-ecosystems-give-licences) |
| a tag pipeline does not run the job | the job has no rule or trigger for tags | add the [snippet](#record-a-version-on-each-tag) |
