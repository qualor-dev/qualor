# GitLab

Qualor works with GitLab.com and self-managed GitLab. Setup has two parts:

1. **The CI job** runs `qualor scan`, uploads the analysis and fails the pipeline when the quality
   gate fails. That is enough to block bad merge requests.
2. **A connection** (optional, recommended) lets the Qualor server comment on merge requests: a
   summary comment, a discussion on each new issue on a changed line, and a commit status
   `qualor/<project key>`. With a webhook, Qualor also answers replies and `qualor review` notes at
   once ([AI review](./ai-review.md#replies-and-commands)).

## Before you start

- A Qualor server that the runners reach over HTTPS ([Install the server](./install-server.md)).
- Runners that can pull `qualor/scanner` from Docker Hub, or your own copy of it
  ([Images](./install-server.md#images)).
- A Qualor project whose key is the GitLab project path (`group/subgroup/app`), and a token. A
  project analysis token is best ([Tokens](./users-projects-tokens.md#tokens)).

## 1. CI/CD variables

In GitLab, add these under **Settings → CI/CD → Variables** of the project, or of a group for many
projects at once:

| Variable | Value | Flags |
|---|---|---|
| `QUALOR_URL` | `https://qualor.example.com` | — |
| `QUALOR_TOKEN` | the token | **Masked**, and **not** Protected |

The token must not be protected: GitLab gives protected variables only to pipelines of protected
branches, so merge request pipelines would get no token.

A token on a group has to be a personal token with **Upload analyses**, because a project token
uploads to its one project only. An upload never creates a project: create each one first, or let
[Add repositories](#set-up-ci-with-a-merge-request) do it.

## 2. The CI job

### With the CI/CD component (recommended)

Qualor is in the GitLab CI/CD catalog as
[`gitlab.com/qualor/qualor`](https://gitlab.com/qualor/qualor). On GitLab.com, add to
`.gitlab-ci.yml`:

```yaml
include:
  - component: gitlab.com/qualor/qualor/qualor@0.13
    inputs:
      image-tag: '0.13'
```

The job runs in merge request pipelines and on the default branch. It uploads the analysis, fails
with the quality gate, and keeps GitLab's **Code Quality**, **SAST** and **Dependency Scanning**
reports as artifacts. The Code Quality report lists every finding in the merge request widget, on
every tier. GitLab shows the SAST and Dependency Scanning reports, in the security widget and the
security tab, on GitLab Ultimate only.

| Input | Default | Meaning |
|---|---|---|
| `image-tag` | required | the scanner image tag, such as `0.13` or `0.13.0` |
| `image` | `qualor/scanner` | the scanner image, without the tag |
| `stage` | `test` | the stage of the job |
| `job-name` | `qualor` | the job's name |
| `args` | empty | extra `qualor scan` arguments, for example `--sarif osv.sarif` |
| `allow-failure` | `false` | let the pipeline pass when the gate fails, for a soft rollout |
| `dotnet` | `false` | C#: run `qualor dotnet begin`, the build, then `qualor dotnet end`. Set `image` to `qualor/scanner-dotnet` too |
| `build-command` | `dotnet build --no-incremental` | the build that runs between `begin` and `end` when `dotnet` is true |

Pin the component and the image to the same release. Where every pipeline must run exactly the same
analyzers, use a full version (`@0.13.0`, `image-tag: '0.13.0'`).

The component runs `qualor scan` from the repository root. If your project needs its dependencies
installed (JavaScript, TypeScript) or a build (Java) first, extend the component's job with a
`before_script`, or use the [job without the component](#without-the-component):

```yaml
qualor:            # the component's job-name
  before_script:
    - npm ci
```

### On self-managed GitLab

A self-managed GitLab includes components only from its own instance, never from `gitlab.com`. Copy
the component into a project of your instance once, for example `tools/qualor`:

1. An administrator allows the import source: **Admin → Settings → General → Import and export
   settings**, tick **Repository by URL**. It is off on a new instance.
2. **New project → Import project → Repository by URL**, with
   `https://gitlab.com/qualor/qualor.git`, at `tools/qualor`.
3. Include the component by its full version:

```yaml
include:
  - component: $CI_SERVER_FQDN/tools/qualor/qualor@0.13.0
    inputs:
      image-tag: '0.13.0'
      # image: mirror.acme.internal/qualor/scanner   # your own copy of the image, without the tag
```

On GitLab Free and Community Edition, the import is a one-time copy. To get a new release, import
again or push its tag to the copy. Pull mirroring (**Settings → Repository → Mirroring
repositories**) keeps the copy up to date, but needs GitLab Premium.

A short version such as `@0.13` resolves only in a CI/CD catalog project with releases. To use one,
turn on **Settings → General → Visibility → CI/CD Catalog project** in the copy. Then run a pipeline
for the release tag (**Build → Pipelines → Run pipeline**): it creates the release that the catalog
needs. An import runs no pipeline.

### Without the component

```yaml
qualor:
  stage: test
  image: { name: qualor/scanner:0.13, entrypoint: [''] }
  variables: { GIT_DEPTH: 0 }        # full history: new code is computed from git
  script:
    - npm ci                          # JS/TS: ESLint runs from node_modules. Java: build first.
    - >-
      qualor scan
      --gitlab-code-quality gl-code-quality-report.json
      --gitlab-sast gl-sast-report.json
      --gitlab-dependency-scanning gl-dependency-scanning-report.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
      sast: gl-sast-report.json
      dependency_scanning: gl-dependency-scanning-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

- `entrypoint: ['']`: the image's entrypoint is `qualor`, and GitLab needs a shell.
- `GIT_DEPTH: 0` gives the full history. With a shallow clone the CLI tries to fetch the baseline.
  If that fails, new-code conditions end in `error`, and the gate fails rather than guess.
  [AI review](./ai-review.md#what-your-ci-needs) needs the full history too.
- Run the job in **merge request pipelines** (`merge_request_event`), as the `rules` do. Only there
  does the CLI know the target branch, so the analysis becomes a merge request analysis.

A C# project uses `qualor/scanner-dotnet` and wraps its own build
([C#](./languages-and-analyzers.md#c)). For Go, run `go mod download` before `qualor scan` in the
same job ([Go](./languages-and-analyzers.md#go-staticcheck-go-vet-gosec)).

## 3. Merge request comments and commit status

In Qualor, an **org admin** opens **Settings → GitLab**:

1. **New connection** opens the **New GitLab connection** dialog. Enter the GitLab address, such as
   `https://gitlab.example.com` (a path such as `/gitlab` is allowed), and an access token with the
   scope **`api`** and the role **Maintainer**.
2. In **Settings → Repositories**, pick the connection for each Qualor project, enter the GitLab
   project by its numeric id or its full path `group/project`, and press **Save**. **Check** tests
   that the token can see the project, and warns when the token's role is below Maintainer.
3. Ask the server operator to set `QUALOR_PUBLIC_URL`, so that comments link back to Qualor.

About the token:

- The role **Developer** is enough for the comments, but GitLab refuses a Developer's commit status
  on a protected branch, such as the default branch.
- A **project access token** of the GitLab project is best: it can reach nothing else. For many
  projects, use a **group access token**, or a personal token of a dedicated bot user.
- Never use a person's own token. Every comment would carry their name, and Qualor would take that
  person's replies for its own notes and not answer them
  ([Replies](./ai-review.md#replies-and-commands)).

**Self-managed GitLab on an internal network.** The server calls only hosts that resolve to public
addresses, unless the operator allows the host:

```sh
QUALOR_SCM_INTERNAL_HOSTS=gitlab.corp.example.com            # https on 443
QUALOR_SCM_INTERNAL_HOSTS=gitlab.corp.example.com:8443,10.0.0.12
```

If GitLab's certificate comes from a private CA, give the server that CA with `NODE_EXTRA_CA_CERTS`.

### What reviewers see

- **A commit status** `qualor/<project key>` on every analysed branch, not only merge requests:
  *success* when the gate passes, *failed* with the failed conditions otherwise.
- **One summary comment** per merge request, edited in place on every analysis. It holds the
  verdict, every gate condition with its value and the value it requires (skipped conditions with
  the reason), the new issues by severity, and the ten most severe with their rule and a link to
  each in Qualor. It also links to the branch in Qualor.
- **A discussion on each new issue** on an added line, up to 50 per merge request. The rule's key
  links to its documentation.
- **AI review**, when an organisation admin switched it on for the project
  ([AI review](./ai-review.md)): an **AI review** section in the summary, and a discussion on each
  finding of high or medium severity, up to 20 per merge request on top of the 50. A suggested
  change comes as a GitLab suggestion (`suggestion:-0+N`: the line of the discussion and the N
  lines below it), which a person applies with **Apply suggestion**. The token needs no extra scope.
- **Answers** to a person's reply in one of Qualor's discussions, and to a note that starts with
  `qualor review` (in that note's own discussion), when AI review is on for the project
  ([Replies and commands](./ai-review.md#replies-and-commands)). A reply can mark an AI finding
  won't fix or false positive and resolve its discussion. The answer comes at once with a
  [webhook](#answers-to-replies-and-commands-webhook), otherwise at the next analysis.

GitLab lets only a comment's author edit it. When the token is replaced by one of another user,
Qualor posts a new summary and deletes the old one. With a token below Maintainer the old summary
stays: delete it by hand.

Marking an issue **false positive** or **won't fix** in Qualor re-evaluates the gate at once, with
no new scan. If that was the only new issue, the status turns green.

**Discussions.** Qualor resolves its discussion when the issue is fixed or marked in Qualor, and
reopens it if the issue comes back.

- When a person replied in a discussion, Qualor no longer resolves it. When the issue is fixed,
  Qualor writes one note in it instead, "Fixed in `<sha>`", and leaves it open. A reply does not
  stop Qualor from reopening a discussion it resolved itself.
- Qualor never reopens a discussion that a person resolved.
- AI review's discussions follow the same rules.

**Merged-results and merge-train pipelines.** There the job analyses the merge commit, whose line
numbers are not the merge request's. The analyzers' discussions are not created, and the summary
says so. AI review's discussions are still posted: the review reads the merge request's own last
commit, and a discussion is created only while the merge request is still at that commit.

**Limits.** One run of Qualor's comments makes at most 400 requests to GitLab. It creates at most 50
discussions for the analyzers' issues and 20 for AI review's findings, the most severe first, and
resolves or reopens at most 200 discussions. The summary and the commit status are always written.
The rest waits for the branch's next analysis.

**What reaches GitLab.** Everything a comment quotes from the code is in code spans. No snippet,
rule text or link from the report reaches GitLab, except a rule's documentation link on its key
when it is a plain `https://` address. In AI review's text, Qualor puts every word that could link,
mention or reference something in code spans too.

### Answers to replies and commands (webhook)

Without a webhook, Qualor answers replies and `qualor review` notes at the next analysis of the
merge request. A webhook makes the answer come at once:

1. In Qualor, open **Settings → GitLab**. On the connection, open **Webhook secret**, type a secret
   of 16 to 256 printable ASCII characters without spaces, and press **Set the webhook secret**.
   `openssl rand -hex 32` makes a good one. With `QUALOR_PUBLIC_URL` set on the server, the
   connection then shows its **Webhook URL**:
   `https://qualor.example.com/api/v0/gitlab/webhooks/<connection id>`.
2. In GitLab, open the project's **Settings → Webhooks** (you need the Maintainer role) and add a
   webhook. Paste the URL, paste the secret as the **Secret token**, tick **Comments** and nothing
   else, and save. Add the same webhook to every GitLab project of this connection that has AI
   review.

GitLab 19 recommends a signing token for new webhooks, but Qualor reads only the **Secret token**,
which every version of GitLab sends.

GitLab sends an event for each comment. Qualor takes only the merge request from it and never uses
the delivery's text: it reads the merge request's comments through the API, as a scan does. It
checks two headers: `X-Gitlab-Token`, the secret token, and `X-Gitlab-Event`, of which it reads only
`Note Hook`. A proxy in front of Qualor must pass these headers on unchanged.

GitLab must be able to reach the URL. GitLab.com cannot reach a Qualor that is only on a private
network. A self-managed GitLab sends a webhook to a private address only after its admin allows
requests to the local network from webhooks (**Admin area → Settings → Network → Outbound
requests**). A delivery that GitLab could not make shows as failed under the webhook's **Recent
events**.

GitLab counts any 4xx or 5xx answer, and a timeout, as a failure. It backs a webhook off after four
failures in a row, and disables it after forty. A webhook that GitLab disabled has to be enabled
again in GitLab. Qualor therefore answers 204 to every delivery it can:

| Answer | When |
|---|---|
| 204 | every delivery GitLab really made, whatever Qualor does with it: an event other than `Note Hook`, a delivery sent again with the same `Idempotency-Key`, a project or merge request Qualor does not know, a project without AI review |
| 401 | the secret token is wrong or missing |
| 429 | after 60 wrong secret tokens in a minute from one address |
| 404 | the connection does not exist or has no webhook secret |
| 400 | the body is not JSON |
| 415 | the body's content type is not JSON |
| 413 | the body is over 1 MiB (a very long comment) |
| 500 | a failure inside Qualor |

If **Recent events** shows 401, 429, 404, 400 or 415, fix the URL or the secret. A 413 or a 500 can
reach a real delivery: GitLab counts it as a failure, and the comments are answered at the next
analysis.

## Set up CI with a merge request

**Add repositories** (in **Projects**, [Quick start](./quick-start.md#fastest-path-add-repositories))
can add the Qualor job to each project for you. Qualor opens a merge request. Your pipelines don't
change until you merge it. The CI/CD variables are set right away. The merge request's own pipeline
is the first analysis.

First turn on **Allow Qualor to set up CI (opens merge requests, writes CI/CD variables)** for the
connection, in **Settings → GitLab**. It is off for connections that existed before, and the
new-connection dialog asks. The token already needs the scope `api` and the role Maintainer, which
cover branches, files, merge requests and CI/CD variables. The server also needs
`QUALOR_PUBLIC_URL`.

The merge request is on the branch `qualor/setup`, titled **Add Qualor code analysis**:

- It adds one `include` entry for the component to `.gitlab-ci.yml`, with `image-tag` set to the
  server's minor version, as in [With the CI/CD component](#with-the-cicd-component-recommended).
  Its `args` input passes the project's key (`--project-key <key>`).
  The rest of the file stays as it was. Qualor creates `.gitlab-ci.yml` when it is missing. When the
  file's `stages:` has no `test`, the entry sets `stage` to an existing stage.
- A C# repository gets `dotnet: true` and a build command. Check the command before you merge.
- Qualor sets two CI/CD variables on the project. `QUALOR_TOKEN` is a project analysis token named
  **CI setup**, masked and not protected, so merge request pipelines can read it. `QUALOR_URL` is
  your Qualor address. The token is never in the merge request.

Qualor shows the snippet instead of opening a merge request when the project already has a Qualor
job, include or `QUALOR_TOKEN` variable, keeps its CI configuration at a custom path, has YAML that
Qualor cannot edit without loss, or is empty. It never overwrites a variable.

On self-managed GitLab the component is not available
([On self-managed GitLab](#on-self-managed-gitlab)). Qualor adds a plain `qualor:` job instead, on
`qualor/scanner:<version>` (`qualor/scanner-dotnet` for C#), with `--project-key <key>`. The
runners must be able to pull the image from Docker Hub or your mirror. To upgrade the scanner, edit the version in the file.

### Undo CI setup

1. Close the merge request and delete the branch `qualor/setup`.
2. Delete the CI/CD variables `QUALOR_TOKEN` and `QUALOR_URL` under **Settings → CI/CD →
   Variables**.
3. In Qualor, revoke the project's **CI setup** token in the project's token settings.

## 4. Block merges on the gate

Either:

- keep the job's default `allow_failure: false` and turn on **Settings → Merge requests → Pipelines
  must succeed**; or
- keep the pipeline green (`allow-failure: true` during a soft rollout) and treat the commit status
  as advisory.

If you also turn on **All threads must be resolved**, Qualor's open discussions block the merge.
That includes discussions on issues that pass the gate, and the open discussions of
[AI review](./ai-review.md). Qualor resolves its own as described in
[What reviewers see](#what-reviewers-see), and a person can resolve them too.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Exit 5 | the token is wrong, revoked, or of another project |
| `new code unavailable`, gate `error` | shallow clone: set `GIT_DEPTH: 0` |
| The analysis appears as a branch, not a merge request | the job ran in a branch pipeline. Use `merge_request_event` rules |
| No comments | no connection or mapping, `QUALOR_SCM_INTERNAL_HOSTS` missing, or the token lacks the `api` scope. **Check** on **Settings → Repositories** says which |
| No discussions from the analyzers, and the summary says "The analyzers’ issues are not commented inline" | the pipeline was a merged-results or merge-train pipeline. The analyzers' discussions need a pipeline of the merge request's own commits. AI review's discussions are not affected |
| No **AI review** section in the summary | AI review is not switched on for the project ([Why AI review is off for a project](./ai-review.md#why-ai-review-is-off-for-a-project)), or the pipeline was not a merge request pipeline |
| No discussion on an AI finding | the section says what became of the review ([What the summary says](./ai-review.md#what-the-summary-says)). A low finding without a suggested change gets none, nor does one past the 20, nor one made for a commit the merge request has moved past |
| Replies and `qualor review` notes are answered only at the next analysis | the connection has no webhook secret (**Settings → GitLab** says so), the GitLab project has no webhook with **Comments** ticked, its secret token differs from Qualor's (**Recent events** shows 401), GitLab cannot reach the URL (**Recent events** shows a failed delivery), or GitLab disabled the webhook after repeated failures ([the webhook](#answers-to-replies-and-commands-webhook)) |
| A reply or a `qualor review` note gets no answer at all | see [Why a reply or a command was not answered](./ai-review.md#why-a-reply-or-a-command-was-not-answered) |
| Comments on merge requests, but no commit status on the default branch | the token's role is below Maintainer, and the branch is protected. Give the token the Maintainer role |
| `@0.13` component not found on self-managed GitLab | the copy is not a CI/CD catalog project with a release. Use `@0.13.0`, or see [On self-managed GitLab](#on-self-managed-gitlab) |
| Comments but no links | `QUALOR_PUBLIC_URL` is not set on the server |

More in [Troubleshooting](./troubleshooting.md).
