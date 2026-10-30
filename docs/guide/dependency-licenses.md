# Dependency licences

Every analysis records which dependencies a project uses, and under which licences. A project's
**Dependencies** tab shows this inventory in every edition.

With the Business or Enterprise plan, an organisation admin can also set a **licence policy**, such
as "no strong or network copyleft". A dependency that breaks it becomes an ordinary issue: it shows
on the merge request, is judged as new code, can be accepted with won't fix, and fails the quality
gate.

| | Community | Business | Enterprise |
|---|---|---|---|
| The dependency inventory and the **Dependencies** tab | yes | yes | yes |
| The share of packages with an unknown licence (`unknown_licenses_ratio`) | yes | yes | yes |
| A licence policy, its issues and the gate metrics `forbidden_licenses` and `licensing_issues` | no | yes, feature `license-policy` | yes, feature `license-policy` |

## What the scanner collects

When Trivy runs, as it does in the `qualor/scanner` image ([Languages and
analyzers](./languages-and-analyzers.md#dependencies-trivy)), the scanner adds a licence-only Trivy
pass after the analyzers. It reads the licences the packages declare, in the lockfile or the
installed packages. It runs offline, with no vulnerability database.

Each package is recorded with its name, version, ecosystem (`npm`, `pnpm`, `yarn`, `gomod`, `nuget`,
`composer` and so on), lockfile and line, and licences. When the lockfile says so, it is marked
direct or transitive.

- **Development dependencies are left out**, as in vulnerability scanning: they usually do not ship
  with your product.
- Your project's own package is not listed.
- Lockfiles the scan does not analyse are left out, such as one in a gitignored or excluded folder
  (a Go module cache inside the repository, say).
- Licences are written as [SPDX](https://spdx.org/licenses/) identifiers. Common spellings are
  translated: `GPLv3` becomes `GPL-3.0-only`, `GPL-2.0+` becomes `GPL-2.0-or-later`, `Apache 2.0`
  becomes `Apache-2.0`, and a bare `BSD` becomes `BSD-3-Clause`. Text that names no licence, such as
  `SEE LICENSE IN LICENSE.txt`, is kept as written.
- At most 50 000 packages are recorded per analysis, the direct ones first. Above that, the analysis
  shows the warning `DEPENDENCIES_TRUNCATED`.

The report carries package names, versions and licences, never the text of your files.

## Which ecosystems give licences

Some lockfiles carry their packages' licences. For the others, Trivy reads the installed packages,
so **install your dependencies in the scan job, before `qualor scan`**.

| Ecosystem | From the lockfile alone | With the dependencies installed in the job |
|---|---|---|
| npm (`package-lock.json`) | yes | yes |
| Composer (`composer.lock`) | yes | yes |
| pnpm (`pnpm-lock.yaml`) | no | yes, from `node_modules` |
| Yarn, classic and Berry (`yarn.lock`) | no | yes, from `node_modules` (for Berry, `nodeLinker: node-modules`: Plug'n'Play installs no `node_modules`) |
| Go (`go.mod`) | no | yes, from the Go module cache (`go mod download`) |
| NuGet (`packages.lock.json`) | no | yes, from the NuGet package folder (`~/.nuget/packages`, or `NUGET_PACKAGES`) |
| Maven (`pom.xml`) | no | yes, for the packages whose POM file the build downloaded into the local Maven repository (`~/.m2/repository`) |
| Gradle (`gradle.lockfile`) | no | partly, even with the Gradle cache (`~/.gradle`, or `GRADLE_USER_HOME`): Trivy reads only a package's own POM, so a licence inherited from a parent POM is missed |
| pip (`requirements.txt`) | no | no, even with a virtual environment installed |
| Cargo (`Cargo.lock`) | no | no |
| Bundler (`Gemfile.lock`) | no | no |

A package without a licence is listed as **Unknown**.

Where the scanner finds installed packages:

- **Go:** the module cache in `GOPATH` or `GOMODCACHE`, or in `~/go` when neither is set. That is
  where `go mod download` puts it.
- **Maven:** the local repository in `~/.m2`, under the scan job's `HOME`. If your job keeps that
  repository inside the project (for example `-Dmaven.repo.local=.m2/repository`, to cache it), set
  `HOME` to the folder that holds `.m2` for the scan, or keep the repository outside the project.
- **C#:** a build in the `qualor/scanner-dotnet` image restores its packages into
  `~/.nuget/packages`, so `qualor dotnet end` reads them with no extra step.

### Install your dependencies before the scan

GitLab CI, in the `qualor/scanner` image. Keep the lines for the package managers your repository
uses:

```yaml
qualor:
  stage: test
  image: { name: qualor/scanner:<version>, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }
  script:
    - npm ci                                      # npm
    - corepack pnpm install --frozen-lockfile     # pnpm
    - corepack yarn install --immutable           # Yarn Berry (Yarn 1: yarn install --frozen-lockfile)
    - go mod download                             # Go, in each module directory
    - qualor scan
```

The image has npm, Yarn 1 and corepack, which fetches the pnpm or Yarn version that `package.json`
names in `packageManager`.

GitHub Actions, in the workflow of [GitHub](./github.md#2-the-workflow):

```yaml
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - run: corepack pnpm install --frozen-lockfile   # or npm ci, go mod download …
      - run: qualor scan
        env:
          QUALOR_URL: ${{ vars.QUALOR_URL }}
          QUALOR_TOKEN: ${{ secrets.QUALOR_TOKEN }}
```

The JavaScript, TypeScript and Go analyzers need the same install step.

### Settings

```yaml
analyzers:
  trivy:
    licenses: auto                # auto (default), true or false
    licenseTimeoutSeconds: 300
```

- `auto` runs the licence pass whenever Trivy runs. `true` does the same, and also warns
  (`LICENSE_SCAN_FAILED`) when Trivy is not installed. `false` skips the pass, and the analysis
  records no inventory. `analyzers.trivy.enabled: false` turns off both Trivy passes.
- A tag scan runs the pass whatever `licenses` says
  ([What a tag scan does](./releases.md#what-a-tag-scan-does)).
- The pass reads every installed package, so a large `node_modules` takes time: about 100 seconds
  for 800 MB. `licenseTimeoutSeconds` (default 300) bounds this pass on its own.
- A pass that fails or times out never fails the scan. The vulnerability findings are kept, the
  analysis shows the warning, and the **Dependencies** tab keeps the previous inventory.

The analysis lists the pass as the engine `trivy-licenses`, with its status.

## The Dependencies tab

**Project → Dependencies** lists the packages of a branch or a merge request, chosen in the
**Branch** picker. Each row shows the package, version, ecosystem, lockfile (a link to that line in
the **Code** tab), licences, and **Direct** or **Transitive**. The header says how many packages
have a known licence.

The picker also lists the project's [versions](./releases.md) under **Versions**: the 100 most
recently scanned, with **(tracked)** after each tracked one. For a version, the lockfiles are not
links, and forbidden packages do not link to issues.

Filter by **Licence**, **Licence group** or ecosystem, tick **Unknown only** or **Direct only**, or
search by package name. Until a scan of the branch has recorded an inventory, the tab says so.

With a licence policy (Business or Enterprise), the tab adds a **Policy** column (**Allowed**,
**Forbidden** or **Unknown**) and the **Forbidden only** filter. A forbidden package links to its
issues. The column always shows the current policy, so a policy change shows at once.

## The licence policy (Business and Enterprise)

An organisation admin sets the policy in **Settings → Licence policy**. It applies to every project
of the organisation, and nobody can weaken it from a `qualor.yml` in their own merge request. There
is no policy until an admin saves one.

- **Mode.** **Forbid listed licences** (a deny list) forbids the licences of the forbidden groups
  and of the **Forbidden licences** list. **Allow only listed licences** (an allow list) forbids
  every licence that is not in **Allowed licences**.
- **Forbidden groups.** Qualor's licence groups, below. Expand a group to see its licences.
- **Forbidden licences** and **Allowed licences.** SPDX identifiers, such as `GPL-3.0-only`, or
  terms such as `GPL-2.0-only WITH Classpath-exception-2.0`. Each list holds at most 500 entries.
  - In deny-list mode, an allowed licence is allowed even when a forbidden group lists it. For
    example, forbid **Weak copyleft** and allow `LGPL-2.1-only`.
  - In allow-list mode, only **Allowed licences** counts. The groups and the forbidden list do not
    apply.
- **Warn about dependencies with unknown licences.** Each package whose licence the scan could not
  read becomes an issue of severity Info. It is off by default.
- **Remove policy.** The next analysis of each project closes its licence issues.

A policy change applies **from each project's next analysis**, like a quality profile change.

### The licence groups

The groups are a starting point, not legal advice. Qualor reviews them by hand and updates them with
its releases. Permissive licences, such as MIT, Apache-2.0 or BSD-3-Clause, belong to no group.

| Group | What its licences have in common | Licences |
|---|---|---|
| **Network copyleft** (`network-copyleft`) | the duty to share the source also applies when the software is only offered over a network | `AGPL-1.0-only`, `AGPL-1.0-or-later`, `AGPL-3.0-only`, `AGPL-3.0-or-later`, `SSPL-1.0`, `OSL-1.0`, `OSL-1.1`, `OSL-2.0`, `OSL-2.1`, `OSL-3.0`, `EUPL-1.1`, `EUPL-1.2`, `CPAL-1.0`, `RPL-1.1`, `RPL-1.5` |
| **Strong copyleft** (`strong-copyleft`) | software combined with the code must be released under the same terms | `GPL-1.0-only`, `GPL-1.0-or-later`, `GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `Sleepycat`, `QPL-1.0` |
| **Weak copyleft** (`weak-copyleft`) | changes to the licensed files or library must be shared, but not the programs that use them | `LGPL-2.0-only`, `LGPL-2.0-or-later`, `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later`, `MPL-1.0`, `MPL-1.1`, `MPL-2.0`, `MPL-2.0-no-copyleft-exception`, `EPL-1.0`, `EPL-2.0`, `CDDL-1.0`, `CDDL-1.1`, `CPL-1.0`, `MS-RL`, `GPL-2.0-only WITH Classpath-exception-2.0`, `GPL-2.0-or-later WITH Classpath-exception-2.0` |
| **Non-commercial or source-available** (`non-commercial-or-source-available`) | they restrict commercial use or competing services, so they are not open source in the usual sense | `CC-BY-NC-1.0`, `CC-BY-NC-2.0`, `CC-BY-NC-2.5`, `CC-BY-NC-3.0`, `CC-BY-NC-4.0`, `CC-BY-NC-ND-1.0`, `CC-BY-NC-ND-2.0`, `CC-BY-NC-ND-2.5`, `CC-BY-NC-ND-3.0`, `CC-BY-NC-ND-3.0-DE`, `CC-BY-NC-ND-3.0-IGO`, `CC-BY-NC-ND-4.0`, `CC-BY-NC-SA-1.0`, `CC-BY-NC-SA-2.0`, `CC-BY-NC-SA-2.0-DE`, `CC-BY-NC-SA-2.0-FR`, `CC-BY-NC-SA-2.0-UK`, `CC-BY-NC-SA-2.5`, `CC-BY-NC-SA-3.0`, `CC-BY-NC-SA-3.0-DE`, `CC-BY-NC-SA-3.0-IGO`, `CC-BY-NC-SA-4.0`, `BUSL-1.1`, `Elastic-2.0`, `Commons-Clause`, `PolyForm-Noncommercial-1.0.0`, `PolyForm-Small-Business-1.0.0` |

- `Commons-Clause` is not an SPDX licence but a condition added to one, as in
  `Apache-2.0 WITH Commons-Clause`. Any licence with it belongs to the non-commercial group.
- The Classpath exception moves the GPL into weak copyleft.
- Deprecated spellings count as their current ones: `GPL-2.0` is `GPL-2.0-only`, and `GPL-2.0+` is
  `GPL-2.0-or-later`.

Qualor checks policy entries against the SPDX licence list it ships (version 3.29.0 of 2026-09-16),
updated with each release.

### How a package's licences are judged

A package is **allowed**, **forbidden** or **unknown**:

- **Several licences** on one package all apply: it is forbidden when any of them is.
- **`A OR B`** (a choice of licences) is forbidden only when every alternative is. So
  `MIT OR GPL-2.0-or-later` passes a policy that forbids strong copyleft.
- **`A AND B`** is forbidden when either is forbidden.
- **`A WITH exception`** is judged as the whole term first, then as `A`. So
  `GPL-2.0-only WITH Classpath-exception-2.0` is weak copyleft, not strong copyleft.
- **No licence** at all is unknown.
- **Text that names no licence** (`SEE LICENSE IN LICENSE.txt`, `Public Domain`) is unknown in
  deny-list mode. In allow-list mode it is forbidden, since it is not on the allowed list.

## Licence issues

With the feature active, each analysis judges the inventory against the policy and reports:

| Rule | Severity | When |
|---|---|---|
| `license:forbidden` | high | the package's licence is forbidden, for example "gpl-money 2.1.0 is licensed GPL-3.0-only, which the organisation's licence policy forbids (Strong copyleft)." |
| `license:unknown` | info | the package has no licence Qualor could read, only with **Warn about dependencies with unknown licences** |

Both rules have the engine `license` and the quality **Licensing**, which has no rating. A forbidden
licence never lowers the security rating and never counts as a security issue. Quality profiles do
not apply to these rules: the policy decides which packages are reported.

- The issue sits on the package's line in the lockfile. It is **new code** when that line is, that
  is, when the change added the package or changed its version. A forbidden package that was there
  before the policy does not fail merge requests, but it is counted on the branch.
- When the scanner could not find the package's line in the lockfile, the issue is never new code.
  `new_*` gate conditions then do not catch it on a merge request, but branch-level conditions do.
- A package at a new version is a new issue.
- Licence issues appear on the merge request like any other issue. They are not in the GitLab report
  artifacts the scanner writes (`--gitlab-code-quality` and the others), because the server makes
  them.
- Compliance reports and portfolio reports leave them out.

**Making an exception.** To accept one package, set its issue to **won't fix**, with a comment that
says why, such as the legal team's approval. It stays won't fix across analyses, until the package
changes version. To accept a licence everywhere, add it to **Allowed licences**.

**With `warnUnknown` on**, install your dependencies before the scan. A project scanned without
them, such as a pnpm project without `node_modules`, gets an Info issue for every package.

## Gate metrics

| Metric | Meaning |
|---|---|
| `licensing_issues`, `new_licensing_issues` | open licence issues (`license:forbidden` and `license:unknown`) |
| `forbidden_licenses`, `new_forbidden_licenses` | open `license:forbidden` issues |
| `unknown_licenses_ratio` | the share of the inventory, in percent, whose licence is unknown (overall only; no value without an inventory; every edition) |

Licence issues also count in `issues`, `high_issues` and `info_issues`. The built-in "Qualor way"
gate, with `new_issues > 0`, therefore already fails a merge request that adds a forbidden licence.
To check licences on their own, add `new_forbidden_licenses gt 0` to your gate (see [Quality
gates](./quality-gates.md#metrics-you-can-use-in-conditions)).

## When the licence lapses

Without `license-policy`, the inventory and the **Dependencies** tab keep working. The policy is
kept but no longer applied: analyses neither add licence issues nor close the open ones, and
`forbidden_licenses` keeps counting the open ones. **Settings → Licence policy** shows a note that
the policy needs the Business plan. With a renewed key, the next analysis applies the policy again.

## Who can change the policy

Organisation admins, through the permission `org.licenses.manage`. A personal token needs the
**Admin** scope. Every member of the organisation can read the policy. With `audit-log`, each change
is recorded as `organization.license_policy_changed`, with the policy before and after ([Roles and
the audit log](./roles-and-audit.md#what-is-recorded)).

## The API

```sh
# the inventory of the main branch (or ?branch=<name>, ?mr=<number>, ?version=<version id>),
# forbidden packages only
q "$QUALOR_URL/api/v0/projects/<project id>/dependencies?verdict=forbidden&pageSize=100"

# the policy, the groups with their licences, and the SPDX ids a policy may name
q "$QUALOR_URL/api/v0/organizations/<org id>/license-policy"

# set the policy (an organisation admin; "policy": null removes it)
q -X PUT "$QUALOR_URL/api/v0/organizations/<org id>/license-policy" -d '{"policy":{
  "mode":"denylist","forbiddenGroups":["network-copyleft","strong-copyleft","weak-copyleft"],
  "forbidden":["CC-BY-SA-4.0"],"allowed":["LGPL-2.1-only","MPL-2.0"],"warnUnknown":false}}'
```

`q` is the helper of [Webhooks and REST API](./webhooks-and-api.md#rest-api).

- `GET /projects/{id}/dependencies` reads the main branch by default. `branch`, `mr` or `version`
  names another branch, a merge request or a version. `version` is a version's id from
  `GET /projects/{id}/versions` ([Releases and versions](./releases.md#the-api)), and cannot be
  combined with `branch` or `mr`.
- It filters by `license`, `group`, `ecosystem`, `unknown=true|false`, `direct=true|false`, `q`
  (the package name), and `verdict` (`allowed`, `forbidden` or `unknown`; only with a policy).
  It pages with `page` and `pageSize` (at most 500). The answer holds:
  - `rows`, `page`, `pageSize` and `total`;
  - `summary`, for the whole inventory: `total`, `known`, `unknown` and the 20 most frequent
    licences;
  - `inventory`, false until a scan recorded one;
  - `verdicts`, true when the rows carry the policy's `verdict`.
- `GET /organizations/{id}/license-policy` returns `available` (false without `license-policy`),
  `policy` (or `null`), `groups` and `spdxIds`.
- `PUT /organizations/{id}/license-policy` stores entries in their canonical spelling.
  `{"policy":null}` removes the policy, even one that can no longer be read. Errors:
  - 403 `FEATURE_NOT_LICENSED` without `license-policy`;
  - 400 `INVALID_LICENSE_ID` for an entry that is not an SPDX identifier or `id WITH exception`
    term. `details.invalid` lists them;
  - 409 `LICENSE_POLICIES_UNREADABLE` when the stored policies of all organisations (the instance
    setting `licensePolicy`) cannot be read. Nothing changes until that row is fixed or deleted.

## Warnings

| Warning | Meaning | What to do |
|---|---|---|
| `LICENSE_SCAN_FAILED` | the licence pass could not run, or failed; with `licenses: true`, also when Trivy is not installed | read the scan log; the vulnerability findings are not affected |
| `LICENSE_SCAN_TIMEOUT` | the pass took longer than `licenseTimeoutSeconds` | raise `analyzers.trivy.licenseTimeoutSeconds`, or exclude directories you do not ship |
| `DEPENDENCIES_TRUNCATED` | more than 50 000 packages; the direct ones are kept first. Licence issues are still opened, but none is closed while the inventory is cut | exclude lockfiles you do not ship (`sources.exclude`) |
| `DEPENDENCIES_OUT_OF_SCOPE` | lockfiles in folders the scan does not analyse (gitignored, such as an in-repository package cache) were left out of the inventory; lockfiles under `sources.exclude` or the built-in excludes (such as a .NET build's `bin/Debug/`) are left out without it | none needed; add the folder to `sources.exclude` to silence it and let the pass skip it |
| `DEPENDENCIES_SKIPPED` | packages whose name, version or lockfile path is too long for the report | none needed; they are left out of the inventory |
| `DEPENDENCY_LICENSES_SKIPPED` | licence strings longer than 256 characters, or beyond 16 for one package, were left out | check those packages' licences by hand |
| `LICENSE_POLICY_INVALID` | the organisation's stored licence policy could not be read, so the licences were not judged; open licence issues stay as they are | set the policy again in **Settings → Licence policy**, which shows it as missing, or remove it (`PUT … {"policy":null}`); if saving answers `LICENSE_POLICIES_UNREADABLE`, an operator must fix or delete the instance setting `licensePolicy` first |
| `DEPENDENCY_PATHS_INVALID` | the server could not place some flagged packages, because their lockfile path is not a repository path | only a report written by another tool can cause it; check that tool's lockfile paths |
