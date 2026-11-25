# Fix merge requests

Qualor opens a merge request that bumps a vulnerable dependency to a version that fixes it. Your
package manager regenerates the lockfile, so the merge request's own pipeline passes. You review and
merge it.

It works with GitLab, GitHub and Azure DevOps, and it is in every edition. On GitHub and Azure
DevOps, read "pull request" for "merge request" and "PR" for "MR" throughout.

The fix is computed by a **fix job** in your CI. It runs `qualor fix` with your package manager and
your registry access, then uploads only the changed manifests and lockfiles. The Qualor server never
runs a package manager: it commits those files to a branch of its own and opens the merge request.

## What it does

| Qualor does | Qualor does not |
|---|---|
| open one merge request per package, into the main branch, on a `qualor/fix/…` branch | merge anything, or push to your main branch |
| fix every vulnerability of that package that a version fixes, in every lockfile of its ecosystem | bump a direct parent to fix a transitive package: it pins the transitive package |
| choose the smallest safe version, and call out a major jump | group several packages in one merge request |
| keep the merge request current, and close it when the vulnerability is gone | touch a branch a person pushed to |
| stop at the cap of fix MRs in progress | add reviewers, labels or assignees, or trigger a pipeline |
| fix vulnerabilities seen on the main branch | fix vulnerabilities seen only on other branches or on versions |

Supported: npm, pnpm, Yarn (classic and Berry), Go modules, Maven, uv and Poetry
([Ecosystems](#ecosystems-and-how-each-is-fixed)). Other kinds of package show "no automatic fix" in
Qualor.

## Turning it on

| Step | Who | Where |
|---|---|---|
| 1. Map the project to its repository | Organization admin | **Settings → Repositories** ([GitLab](./gitlab.md), [GitHub](./github.md), [Azure DevOps](./azure-devops.md#map-a-repository)) |
| 2. Allow fix MRs on the connection | Organization admin | **Settings → GitLab**, **Settings → GitHub** or **Settings → Azure DevOps**, the switch **Allow fix MRs** (on Azure DevOps, **Allow fix pull requests**). It is off, also for connections that existed before |
| 3. Give the connection's token the permissions below | whoever manages the token | GitLab, GitHub or Azure DevOps |
| 4. Turn fix MRs on for the project | Project admin | **Project → Settings → Fix MRs**, **Enabled** |
| 5. Add the [fix job](#the-fix-job) to CI | whoever owns the CI | the repository |
| 6. Keep vulnerability monitoring on | Project admin | the project's settings ([Dependency vulnerabilities](./dependency-vulnerabilities.md)) |

The panel names the first step that is missing. Until the fix job has asked for work once, it shows
"Waiting for the fix job"; afterwards it shows when the job last ran. It counts the project's fix
MRs: "2 open, 3 of 5 in progress", where in progress is requested, preparing, committing and open.

The connection's token needs:

| Provider | Needs |
|---|---|
| GitLab | the `api` scope, and the Developer role or higher on the project |
| GitHub | the App's permissions `contents: write` and `pull_requests: write` |
| Azure DevOps | on the repository, for the connection's identity: **Contribute**, **Create branch**, **Force push** and **Contribute to pull requests**. **Force push** is there because Qualor moves and deletes its own `qualor/fix/…` branches. A member of the project's **Contributors** has it on the branches it created, and needs nothing more. A personal access token also needs **Code: Read & write** |

The permissions the connection already needs for [comments](./gitlab.md#3-merge-request-comments-and-commit-status)
and [CI setup](./github.md#set-up-ci-with-a-pull-request) cover them on GitLab and GitHub. On Azure
DevOps, [add the fix rights](./azure-devops.md#fix-pull-requests). If the first commit fails with
`scm_permission`, the token lacks one.

### The project settings

| Setting | Meaning |
|---|---|
| **Enabled** | off by default. Off stops new requests, claims and uploads. Open merge requests stay open: Qualor still records when they are merged, declined, taken over or no longer needed, but does not rebuild them. Their rows keep **Cancel** |
| **Request fix MRs for new vulnerabilities** | the [automatic mode](#the-automatic-mode): **Off**, **Critical**, **High and above**, **Medium and above**, **Low and above** |
| **Exploited vulnerabilities (CISA KEV)** | adds exploited vulnerabilities to the automatic mode. It needs Business or Enterprise, as in [Jira](./jira.md#the-automatic-rule) |
| **Fix MRs in progress at most** | 1 to 20, 5 by default. It counts requested, preparing, committing and open fixes |

### Asking for a fix

A person who may triage issues (Maintainer and above) asks for a fix:

- On the **Vulnerabilities** tab, with the main branch selected: **Create fix MR** on a row.
- On a Trivy issue of the main branch: the **Fix MR** card.

The row then shows the state:

| State | What you see | What you can do |
|---|---|---|
| Requested | **Waiting for the fix job** | **Cancel** |
| Preparing | **Preparing** (the job is working, or Qualor is writing the branch) | **Cancel** (not while Qualor writes the branch: try again in a few seconds) |
| Open | the merge request, as **MR !12**, **PR #12** or **PR !12**, and "to 4.17.21". **updating** while it is rebuilt | **Cancel** closes the merge request and deletes its branch |
| Failed, no fix | the reason | **Retry**, and the [troubleshooting table](#troubleshooting) |
| Merged, Fixed, Declined, Taken over, Cancelled | what happened | **Create again** |

The tab's header says "3 of 5 fix MRs in progress". A package that has no version fixing it, or that
Qualor cannot fix, shows no **Create fix MR**; the API answers `NOT_FIXABLE` or
`FIX_ECOSYSTEM_UNSUPPORTED`.

A request fails at once with a message when fix MRs are off for the project (`FIXES_DISABLED`), the
project has no repository (`SCM_NOT_BOUND`), the connection does not allow them
(`FIX_MRS_NOT_ALLOWED`), monitoring is off (`MONITORING_OFF`) or the cap is reached
(`FIX_LIMIT_REACHED`).

### The automatic mode

The automatic mode requests fixes for new vulnerabilities, without a click.

| Rule | Behaviour |
|---|---|
| What counts | vulnerabilities on the main branch **first found after you save**, at or above the threshold, as [the Jira rule](./jira.md#the-automatic-rule) counts them. Saving never requests the backlog |
| Pace | oldest first, never beyond **Fix MRs in progress at most** |
| A package | requested when it has no fix yet, or its last fix is merged or fixed and a vulnerability it did not handle is new |
| Never again | a package whose fix failed, has no fix, was cancelled, declined or taken over waits for a person |
| Needs | vulnerability monitoring on for the project |

No audit entry records an automatic request, because Qualor acts, not a person.

## The fix job

The fix job runs `qualor fix` in CI, in a checkout of the **main branch**. It asks the server for
requested fixes, prepares each in a scratch copy of the checkout, and uploads the result. It never
changes the checkout.

A fix waits for the next job run. Add a **daily schedule** to the job, so a request is served within
a day without a push.

### GitLab

Add three inputs to the [component](./gitlab.md#with-the-cicd-component-recommended). It needs
`QUALOR_URL` and `QUALOR_TOKEN` as the scan does, with a **project analysis token**:

```yaml
include:
  - component: gitlab.com/qualor/qualor/qualor@0.17
    inputs:
      image-tag: '0.17'
      fix: true
      fix-image: node:22-bookworm   # your build image: your package manager, glibc
```

| Input | Default | Meaning |
|---|---|---|
| `fix` | `false` | adds the jobs `qualor-fix-cli` and `qualor-fix` |
| `fix-image` | the scanner image | the image `qualor-fix` runs in. It must hold your package manager, and be glibc-based |
| `fix-args` | empty | more `qualor fix` options, such as `--max 3`. Split at blanks |

`qualor-fix-cli` saves the `qualor` binary from the scanner image, so the fix image needs no
download. `qualor-fix` runs on pipelines and schedules of the default branch, and may fail without
failing the pipeline. Add a daily pipeline schedule under **Build → Pipeline schedules**, on the
default branch.

The scanner image has npm, Yarn classic and Go. For pnpm, Yarn Berry, Maven, uv or Poetry, name an image that has them.

### GitHub

Use the `fix` action of [`qualor-dev/scan-action`](https://github.com/qualor-dev/scan-action#fix-pull-requests),
after your own setup steps (`setup-node`, `setup-java`, `setup-go`, a registry login). It runs on the
runner, so it uses your package manager and registry credentials.

```yaml
name: qualor-fix
on:
  push:
    branches: [main]          # your default branch
  schedule:
    - cron: '17 3 * * *'      # daily
permissions:
  contents: read
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-node@v5
        with:
          node-version: 22
      - uses: qualor-dev/scan-action/fix@v0.17
        with:
          server-url: ${{ vars.QUALOR_URL }}
          token: ${{ secrets.QUALOR_TOKEN }}
```

The workflow needs no write permission: the GitHub App opens the pull requests. The action copies
the `qualor` binary out of the scanner image, so the runner needs Docker, and a glibc system
(`ubuntu-latest`, not Alpine). Its other inputs are `project-key`, `scanner-image` and `args`.

### Azure Pipelines

Add a second pipeline next to the scan. Copy one file to `azure-pipelines-fix.yml`.

| File | Use it for |
|---|---|
| [`integrations/azure-devops/qualor-fix.yml`](../../integrations/azure-devops/qualor-fix.yml) | The `Qualor@0` task with `command: fix` |
| [`integrations/azure-devops/qualor-fix-docker.yml`](../../integrations/azure-devops/qualor-fix-docker.yml) | The same, with `docker run` and no extension |

Both run on a push to the main branch and on a daily schedule. They need `QUALOR_URL` and the
secret `QUALOR_TOKEN`, a **project analysis token**, as the
[scan pipeline](./azure-devops.md#variables) does. The task form needs the
[extension](./azure-devops.md#pick-a-pipeline).

The scanner image has npm, Yarn classic and Go. For other package managers, use the docker form with
your own image, as [Other CI](#other-ci) describes.

### Other CI

Run `qualor fix` in a job of the main branch, in an image with your package manager. Take the binary
from the scanner image:

```sh
id=$(docker create qualor/scanner:0.17)
docker cp "$id:/usr/local/bin/qualor" ./qualor-bin
docker rm "$id"
QUALOR_URL=https://qualor.example.com QUALOR_TOKEN=… \
  ./qualor-bin fix --project-key acme/payments-api
```

Outside GitLab, GitHub and Azure Pipelines, check out the branch by name: a detached HEAD, or a tag pipeline, exits 2.
Schedule the job daily. [Other CI systems](./other-ci.md#fix-merge-requests) has the rest, and the
[CLI reference](./cli.md#qualor-fix) lists the options and exit codes.

### What the job needs

| Need | Detail |
|---|---|
| The main branch, at the CI revision | `qualor fix` refuses another branch, a tag, or a commit other than the job's, with exit 2 |
| A project analysis token | a personal token answers 403 `TOKEN_NOT_ALLOWED` |
| A glibc image | Debian, Ubuntu or the RHEL family. The binary refuses a musl system such as Alpine, with exit 2 |
| Your package managers on `PATH` | the job serves the families whose managers it finds, and logs the ones it lacks |
| Windows hosts | npm, pnpm and Yarn installed globally as npm-style `.cmd` shims work. Tools only under `node_modules/.bin`, and Maven's `mvn.cmd`, do not. glibc Linux is the main target |

### Registry credentials

The package managers run with the job's own configuration: its `.npmrc`, `pip.conf`, `settings.xml`
and `GOPROXY`. They reach the registries that job configures, and Qualor's own code still calls only
your Qualor server and your repository host.

The tool environment drops Qualor's and CI's credentials: `QUALOR_*`, `CI_JOB_TOKEN`,
`GITHUB_TOKEN`, `ACTIONS_*`, and any `CI_`, `GITHUB_` or `RUNNER_` variable whose name has `TOKEN`,
`PASSWORD`, `SECRET`, `JWT` or `KEY`. A registry login in `.npmrc` must therefore use a variable of
the job's own, such as `NPM_TOKEN`, not `CI_JOB_TOKEN`.

### What the job trusts

`qualor fix` runs the package-manager and build configuration as committed on the main branch:
`.pnpmfile.cjs`, Yarn's `yarnPath` and plugins, `.mvn/` and Maven extensions. That is code your own
build already runs. The tool environment drops Qualor's and CI's credentials
([Registry credentials](#registry-credentials)).

Code of the dependencies themselves, by manager:

| Manager | Dependency code during a fix |
|---|---|
| npm, pnpm, Yarn classic | none: install scripts are off (`--ignore-scripts`) |
| Yarn Berry | none: scripts are off and git is blocked. An https tarball that a registry package depends on is fetched, never built |
| Go, Maven | none: they run no dependency code. Maven runs your project's own build configuration |
| uv | none: `--no-build`. A fix whose lock needs a source build fails as `package_manager` |
| Poetry | Poetry may build a dependency's source distribution to read its metadata, which runs that package's build code |

Package-manager output in a failure is scrubbed of tokens and passwords, and cut to 2 KiB. Use a fix
job without deploy credentials, and run it on the main branch only.

## Ecosystems and how each is fixed

Qualor fixes by **family**. One merge request per package covers every lockfile of the family in the
repository, and each lockfile is regenerated by its own manager.

| Family | Managers | A direct dependency | A transitive dependency |
|---|---|---|---|
| JavaScript | npm, pnpm, Yarn classic, Yarn Berry | its range is raised in `package.json`, keeping its style (`^1.2.3` becomes `^1.2.4`) | pinned in the root manifest: `overrides` (npm), `pnpm.overrides`, `resolutions` (Yarn) |
| Go | `go` | `go get <module>@<version>` | the same, as the `// indirect` requirement |
| Maven | `mvn` | the `<version>`, or the `${property}` it names | a `<dependencyManagement>` entry in the root `pom.xml` |
| Python | uv, Poetry | the requirement in `pyproject.toml` is raised | uv: an `override-dependencies` entry. Poetry has no overrides: a `^<version>` constraint in `[tool.poetry.dependencies]`, with a comment |

The merge request says whether each lockfile is a direct upgrade or a transitive pin, and when to
remove the pin.

How the lockfile is regenerated:

| Manager | Command |
|---|---|
| npm | `npm install --package-lock-only --ignore-scripts` |
| pnpm | `pnpm install --lockfile-only --ignore-scripts` |
| Yarn classic | `yarn install --ignore-scripts --non-interactive` |
| Yarn Berry | `yarn install --mode=update-lockfile` |
| Go | `go get`, then `go mod tidy`, in each module |
| Maven | no lockfile. `mvn dependency:tree` verifies the result |
| uv, Poetry | `uv lock`, `poetry lock` |

Edits keep the file's layout. The job then re-reads the lockfiles, and requires every vulnerable
resolution of the package to reach its target and nothing else to change. The server checks the
upload again against the base files, by content.

### What is not supported

| Where | Not supported |
|---|---|
| JavaScript | `peerDependencies` are not edited: a package that is only a peer is pinned through overrides. A neighbouring lockfile that changes without a vulnerable version fails the fix |
| Yarn Berry | every lockfile entry and manifest spec must come from the npm registry, a workspace, or a patch of those. Git, `exec:`, `file:`, `link:`, `portal:`, tarball URLs and nested workspaces are not supported. Berry refuses unknown `YARN_*` variables in the job's environment |
| Go | a tracked `vendor/` folder, and a `replace` of the package in `go.mod` or a governing `go.work`. A module that is untidy on main fails the fix. `testdata/` and folders starting with `_` or `.` are skipped. The job's `GOFLAGS` are kept, except `-mod` |
| Maven | `mvn` from `PATH` only, never `./mvnw`. A property defined only in a parent pom |
| Python | a folder with both `uv.lock` and `poetry.lock`, `tool.uv.sources` for the package, and `dev-dependencies` listings |

Where several versions of a package are installed, each gets its target on its own release line. A
manager that cannot pin each line separately (Yarn classic, a Maven property that several modules
share, a transitive package in uv or Poetry) ends with the no-fix reason `several_lines`. A Maven
version property shared with artifacts that have no release at the target, such as Jackson
micro-patches, ends as no fix too.

The job logs a line naming the families the repository has and the job cannot serve, with the tool
it misses.

## Which version

For each vulnerability, Qualor takes its fixed versions and chooses:

1. the smallest fixed version above the installed one **on the same release line** (the same major;
   for `0.x`, the same minor);
2. else the smallest fixed version above it.

The target is the greatest of those choices, so one merge request fixes them all. A vulnerability
with no fixed version is listed in the merge request as not fixable. A major jump is called out. A
version declined before is never proposed again.

Versions are ordered as the ecosystem orders them: SemVer for JavaScript and Go, PEP 440 for Python
and Maven's own rules for Maven.

## The merge request's life

The title is `Bump <package> from <installed> to <target>`. On GitLab the package and the versions
are code, so a scope such as `@all` mentions no one. The body lists the vulnerabilities
fixed, those that have no fix, how each lockfile is fixed, a major-jump warning, and a link to the
project's Vulnerabilities tab when the server has `QUALOR_PUBLIC_URL`. Every 15 minutes Qualor reads
its merge requests:

| What happens | Result |
|---|---|
| The merge request is current | nothing |
| It has a conflict, or a vulnerability now needs a higher version | the next fix job rebuilds it from the current main, and Qualor force-updates its branch. The card shows **updating**. If the rebuild fails, the merge request stays open with the reason, and **Retry** asks again |
| The vulnerability is gone from main | Qualor comments "Qualor no longer finds a vulnerable `<package>` on `<main>`", closes the merge request and deletes the branch: **Fixed**. A branch your rules keep from deletion stays |
| You merge it (Azure DevOps: complete it) | **Merged** |
| Someone closes it without merging (Azure DevOps: abandons it) | **Declined**. Qualor never proposes that version again; **Create again** can propose a higher one |
| Someone deletes it (GitLab) | **Declined**, as a close. **Fixed** when the vulnerability is gone |
| Someone pushes to its branch | **Taken over**. Qualor never touches that branch or merge request again |
| You ask again after a takeover | a new branch `qualor/fix/<family>/<package>-2`, then `-3`, and so on |

Azure DevOps computes a conflict when the pull request changes, not when only main moves.
A rebuild can wait longer there.

While vulnerability monitoring is off, Qualor neither closes nor requests merge requests. When fix
MRs are switched off for the project, Qualor still tracks its open merge requests: it records them
merged, declined, taken over or fixed, but no longer rebuilds them. An upload in flight is refused,
so no new merge request appears.

### Limits

| Limit | Value |
|---|---|
| Fix MRs in progress per project | 1 to 20, 5 by default. The count includes requested, preparing, committing and open fixes |
| A claim | one fix at a time, at most `--max` (1 to 10) per job run |
| A fix job's time | `--timeout`, 2 minutes to 6 hours, 30 by default. Fixes not yet claimed are left for the next run. A fix ready with less than a minute left is handed back |
| One fix | 10 minutes. A claimed fix's lease is 30 minutes, then it goes back to requested, or, with a merge request, to open with a rebuild |
| An upload's answer | the job waits up to 10 minutes for the server, never past `--timeout` |
| One upload | 50 files and 32 MiB, each UTF-8 text |
| A pull request description on Azure DevOps | 4 000 characters. Qualor shortens its description to fit, by whole lines, and keeps the closing sentence |
| A failure message | the last 2 KiB |

## Troubleshooting

A failed fix shows its reason on the row. **Retry** asks again for the next job run. The job's log
names the file or the tool where a message is short.

### A fix failed

| Code | Shown as | Cause and next step |
|---|---|---|
| `manifest_unsupported` | Qualor cannot edit this project's dependency files automatically, then the job's message (which file, which layout) | a layout the editor refuses: [What is not supported](#what-is-not-supported). Fix the dependency by hand |
| `missing_tool` | The fix job's image does not have the package manager this fix needs, then the job's message | install the manager the message names in the fix image, or fix the dependency by hand |
| `package_manager` | the manager's own output | the manager failed: an unreachable registry, a login that used a dropped variable ([Registry credentials](#registry-credentials)), a lockfile out of sync, an untidy Go module. Fix it in the repository, then **Retry** |
| `verify_failed` | The package manager's result still holds a vulnerable version, then the job's message | a constraint or an override of yours keeps the old version, or the manager changed no file. Fix it by hand |
| `unplanned_change` | the rule the result broke | the result changed more than planned, or gained a credential (`secret_in_file`). The [rules](#upload-rules) say which |
| `secret_in_file` (in the `unplanned_change` message) | the result would put a credential into a file or lockfile | remove the credential from the file or the lockfile, and keep tokens in CI variables. Then **Retry** |
| `timeout` | The fix job ran out of time, then the job's message | a manager took more than 10 minutes. Warm its cache or use a mirror, then **Retry** |
| `upload_refused` | the server's rule | the server refused the files: the [rules](#upload-rules) |
| `scm_permission` | The connection's token may not write to the repository | check the [permissions](#turning-it-on) |
| `scm_refused` | The repository refused the change, for example because of a protected branch | allow `qualor/fix/*` branches, or the connection's account, in the branch rules |
| `scm_unavailable` | The repository could not be reached | **Retry** later |
| `scm_not_bound` | The project is no longer mapped to a repository | map it again |
| `fixes_disabled` | Fix MRs were switched off for the project or its connection | turn them on again |

### No fix

| Reason | Shown as | Next step |
|---|---|---|
| `no_fixed_version` | No released version of this package fixes the vulnerabilities yet | wait for a release, or replace the package |
| `declined` | The proposed version was declined. Qualor does not propose it again | a person closed the merge request. Fix by hand, or wait for a higher fixed version and **Create again** |
| `several_lines` | The package is on several release lines that cannot all be moved to a fixed version in one change | the manager cannot pin each line separately (Yarn classic, a Maven property shared by modules, a transitive package in uv or Poetry): move the dependents to one line, or fix by hand |
| `not_installed` | The vulnerable version is no longer installed | the dependency changed since Qualor last read it. The next analysis of the main branch updates the list |
| `unresolvable` | The package manager found no way to install the fixed version | the dependents do not allow it, or the registry lacks it. The message holds the manager's output |

### Upload rules

The server checks every upload by content, against the files at the base commit. A refused upload
fails the fix as `upload_refused`, with the rule and the file. Nothing is written to the repository.

| Rule | Meaning | Next step |
|---|---|---|
| `path_not_allowed` | a file is not a manifest or lockfile of the family, or its path is not relative and normalised | report it: the job sent a file it should not |
| `duplicate_path` | a file is uploaded twice | report it |
| `too_many_files` | more than 50 files | a repository with that many lockfiles needs a fix by hand |
| `too_large` | more than 32 MiB together | fix by hand |
| `not_utf8` | a file is not UTF-8 text | fix by hand |
| `new_file` | a file does not exist on main at the base commit | **Retry**: the next run starts from main |
| `base_not_on_main` | the base commit is not the head of main or one of its ancestors | the job ran on another branch: run it on the main branch |
| `base_outdated` | main changed this file after the fix was prepared | **Retry**: the next run starts from the new main |
| `no_targets` | the upload names no target version | report it |
| `target_mismatch` | the targets do not match the upload: a target is not above its installed version, the target version is not the greatest target, or a lockfile has no target | report it |
| `not_vulnerable` | no installed version of a target has a vulnerability on main | the vulnerability is gone: nothing to fix |
| `unparsable` | a changed file cannot be read in its format | check that the file is valid, then **Retry** |
| `other_change` | the change touches more than the package's version and its pin | use the manager version that wrote your lockfile (`packageManager`, a pinned Yarn, the Go toolchain), then **Retry** |
| `new_dependency` | the change adds a dependency other than the package | as `other_change` |
| `bad_spec` | the new requirement is not a plain version or version range | the dependency is a tag, a URL or a reference: fix by hand |
| `new_source` | a lockfile entry comes from a host the lockfile did not use | the job's registry differs from the one in the lockfile: use the same registry or mirror |
| `source_kind` | a new lockfile entry comes from a git, file, link, path or tarball source | a dependency of the fixed version comes from there: fix by hand |
| `source_kind` (GitHub Packages) | GitHub Packages' npm tarball URLs (`…/download/…`) lack the registry layout `<name>/-/<name>-<version>.tgz`, so they count as tarballs | proxy GitHub Packages through a registry or mirror with that layout, or fix by hand |
| `missing_integrity` | a new lockfile entry has no integrity hash | the registry or mirror sends no hash: use one that does |
| `below_target` | the package still resolves below its fixed version | a constraint holds it back: fix by hand |
| `go_directive` | `go.mod` changes a directive other than `require` | the fixed version needs a newer Go: raise the `go` line by hand |

### Other problems

| Problem | Cause | Fix |
|---|---|---|
| "Waiting for the fix job" stays | the job has not run since the request | run it, or wait for the schedule |
| The job logs "Fix merge requests are off for this project" and ends with exit 0 | a [switch](#turning-it-on) is off, or the project has no repository | turn it on |
| The job exits 2 with "needs a glibc-based image" | an Alpine or other musl image | use a Debian, Ubuntu or RHEL image |
| The job exits 5 | the token is wrong, revoked, of another project, or personal | use a project analysis token |
| The job exits 4 | the server is unreachable or answered an error | check `QUALOR_URL` and the proxy. Uploads wait for `Retry-After` and retry three times |
| There is no **Create fix MR** | the package kind has no automatic fix, or no version fixes it, or you may not triage issues | [What it does](#what-it-does) |
| A `refs/qualor/fix-tmp/*` ref remains in an Azure DevOps repository | a refresh pushes the new commit to `refs/qualor/fix-tmp/<id>` and then moves the branch to it. After a network failure the ref can stay. It is not a branch and starts no pipeline: delete it |
| A merge request is open and old | the branch is current: it only changes on a conflict or a higher target | nothing to do |

More in [Troubleshooting](./troubleshooting.md).
