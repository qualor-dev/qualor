# GitHub

Qualor works with GitHub.com, GHE.com and GitHub Enterprise Server 3.9 or later. Setup has two
parts:

1. **An Actions workflow** runs the Qualor Action. It scans, uploads the analysis and fails when the
   quality gate fails. It needs no GitHub write permission.
2. **A GitHub App** (optional, recommended) lets the Qualor server post a check run, review comments
   on the changed lines and a summary comment on each pull request. With the App's webhook, Qualor
   also answers replies and `qualor review` comments at once
   ([AI review](./ai-review.md#replies-and-commands)).

## Before you start

- A Qualor server that your runners reach over HTTPS.
- Runners that can pull `qualor/scanner` from Docker Hub, or your own copy of it
  ([Images](./install-server.md#images)).
- A Qualor project whose key is `owner/repo`, and a project analysis token
  ([Tokens](./users-projects-tokens.md#tokens)).

## 1. Variables and secret

In the repository or the organisation, open **Settings → Secrets and variables → Actions** and add:

| Kind | Name | Value |
|---|---|---|
| Variable | `QUALOR_URL` | `https://qualor.example.com` |
| Secret | `QUALOR_TOKEN` | the token |

To run [without the Action](#without-the-action-your-own-image-or-a-mirror), also add the variable
`QUALOR_SCANNER_IMAGE`, such as `qualor/scanner:0.13` or `qualor/scanner:0.13.0`. For C#, add
`QUALOR_SCANNER_DOTNET_IMAGE` with `qualor/scanner-dotnet:0.13` instead.

## 2. The workflow

Save this as `.github/workflows/qualor.yml`. It uses the Qualor Action,
[`qualor-dev/scan-action`](https://github.com/qualor-dev/scan-action):

```yaml
name: qualor
on:
  pull_request:
  push:
    branches: [main]          # your default branch
permissions:
  contents: read
jobs:
  qualor:
    # Pull requests from forks get no secrets, so they are skipped.
    if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      # Install dependencies (JS/TS, Go) or build (Java) here, before the scan.
      - uses: qualor-dev/scan-action@v0.13
        with:
          server-url: ${{ vars.QUALOR_URL }}
          token: ${{ secrets.QUALOR_TOKEN }}
```

| Input | Default | Description |
|---|---|---|
| `server-url` | required | your Qualor server |
| `token` | required | a project analysis token, from a secret |
| `project-key` | | the project key. Default: `project.key` in `qualor.yml`, else `owner/repo` |
| `config` | | the path of `qualor.yml`, when it is not at the repository root |
| `wait` | `true` | wait for the quality gate and fail the step when it fails. `false` uploads and passes |
| `args` | | more `qualor scan` options separated by spaces, for example `--sarif osv.sarif` |

The step fails when the gate fails, when an analyzer that `qualor.yml` marks as required fails, or
when the upload is refused because the token is wrong or revoked. It needs a Linux runner with
Docker (`ubuntu-latest` or self-hosted). The scanner cannot write into the checkout: an option that
writes a file, such as `--output`, needs a path under `/tmp`.

The Action's version follows Qualor's. `@v0.13.0` runs `qualor/scanner:0.13.0`, `@v0.13` follows the
0.13 patch releases, and `@v0` follows the latest release. Use the version of your Qualor server, or
pin a full version to control every update.

What the checkout settings do:

- `ref:` checks out the **pull request's head**, so review comments land on the pull request's own
  lines. With the default checkout of GitHub's merge commit, the analyzers' issues get no review
  comments, and the summary says so. AI review's comments are still posted
  ([What your CI needs](./ai-review.md#what-your-ci-needs)).
- `fetch-depth: 0` gives the full history. New code is computed from it, and AI review needs it to
  find where the branch left the target branch.
- `persist-credentials: false` keeps the job's GitHub token out of `.git/config`, where the analysed
  code could read it.
- The `if:` skips pull requests **from forks**, because GitHub gives them no secrets. Never switch
  to `pull_request_target`: it would run a fork's code with your token.

For Go, run `go mod download` in the same job before the Qualor step
([Go](./languages-and-analyzers.md#go-staticcheck-go-vet-gosec)).

### C#

Qualor analyses C# inside your build ([C#](./languages-and-analyzers.md#c)). Use the `dotnet`
Action: it runs `qualor dotnet begin`, your build and `qualor dotnet end` in the
`qualor/scanner-dotnet` image.

```yaml
- uses: qualor-dev/scan-action/dotnet@v0.13
  with:
    server-url: ${{ vars.QUALOR_URL }}
    token: ${{ secrets.QUALOR_TOKEN }}
    build-command: dotnet build MySolution.sln --no-incremental
```

It takes the same inputs, plus `build-command` (default `dotnet build --no-incremental`). Keep
`--no-incremental`. When the build fails, nothing is uploaded.

The token goes only to `qualor dotnet end`, but the build runs your repository's code in the same
container and could read it. If that is not acceptable, use the template
[`integrations/github/qualor-dotnet.yml`](../../integrations/github/qualor-dotnet.yml), which keeps
the token in a separate step.

### Without the Action (your own image or a mirror)

To run your own copy of the scanner image, from a private registry or a mirror, copy the whole of
[`integrations/github/qualor.yml`](../../integrations/github/qualor.yml) to
`.github/workflows/qualor.yml`. It needs the variable `QUALOR_SCANNER_IMAGE` from step 1.

```yaml
name: qualor
on:
  pull_request:
  push:
    branches: [main]          # your default branch
permissions:
  contents: read
jobs:
  qualor:
    if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    container:
      image: ${{ vars.QUALOR_SCANNER_IMAGE }}
      options: --user 1001
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      # Install dependencies (JS/TS) or build (Java) here, before the scan.
      - run: qualor scan
        env:
          QUALOR_URL: ${{ vars.QUALOR_URL }}
          QUALOR_TOKEN: ${{ secrets.QUALOR_TOKEN }}
```

`--user 1001` runs the container as the runner's user, so the checkout is writable. For an image in
a private registry, add `credentials` to `container:`. For GHCR, that is
`username: ${{ github.actor }}` and `password: ${{ secrets.GITHUB_TOKEN }}`, plus `packages: read`
in `permissions`. For C#, copy `integrations/github/qualor-dotnet.yml` instead and replace its build
step with your own.

## 3. The GitHub App

### Create it

On GitHub, in the organisation that owns the repositories, go to **Settings → Developer settings →
GitHub Apps → New GitHub App**. You can also register it from the manifest
[`integrations/github/app-manifest.json`](../../integrations/github/app-manifest.json).

Give it these repository permissions, and nothing else. [CI setup](#set-up-ci-with-a-pull-request)
needs two more:

| Permission | Access | What Qualor uses it for |
|---|---|---|
| Checks | Read and write | the check run |
| Contents | Read and write | resolving and reopening its own review conversations. GitHub lets an App do that only with this permission |
| Issues | Read-only | GitHub sends the **Issue comment** event only to an App that can read issues |
| Metadata | Read-only | reading a person's role in the repository, for replies and commands |
| Pull requests | Read and write | reading and writing the pull request's comments |

Subscribe to these events:

| Event | What Qualor does |
|---|---|
| Check run | the **Re-run** button of Qualor's check run decorates the pull request again |
| Issue comment | a comment on the pull request's page, such as `qualor review`, is answered at once |
| Pull request review comment | a reply in one of Qualor's review conversations is answered at once |

Leave the webhook inactive: you turn it on [below](#turn-on-the-webhook-recommended). Under
**Where can this GitHub App be installed?**, choose **Only on this account**.

Then **generate a private key** (a `.pem` file) and note the **App ID**. **Install** the App on the
repositories that Qualor should comment on.

### Connect it to Qualor

An **org admin** opens **Settings → GitHub → New GitHub App** in Qualor:

- **API address**: `https://api.github.com` for GitHub.com, `https://api.<subdomain>.ghe.com` for
  GHE.com, or `https://<host>/api/v3` for GitHub Enterprise Server.
- **App id**, and the **Private key**: paste the `.pem` file or choose it. Use the unencrypted RSA
  key that GitHub generated.
- **Webhook secret** (optional): a random value, such as the output of `openssl rand -hex 32`. The
  [webhook](#turn-on-the-webhook-recommended) needs it.

On **Settings → GitHub**, **Test** with a repository checks the App. When the test passes, it also
lists what the App lacks of **Contents: Read and write**, **Issues: Read-only** and the three
events, and what each one costs. Qualor works without them, with less.

### Map projects to repositories

In **Settings → Repositories**, pick the GitHub connection for each project, enter the repository
as `owner/repo` and press **Save**. **Check** tests that the App is installed on the repository and
has the permissions it needs.

### Turn on the webhook (recommended)

The webhook makes the **Re-run** button work, and makes Qualor answer replies and `qualor review`
comments at once. Without it, they wait for the next analysis of the pull request.

1. In Qualor, give the App's connection a webhook secret: when you create it, or later under
   **App id and webhook secret** with **Set the webhook secret**. With `QUALOR_PUBLIC_URL` set on
   the server, Qualor then shows the **Webhook URL**:
   `https://qualor.example.com/api/v0/github/webhooks/<connection id>`.
2. On the App's settings page on GitHub, paste that URL and the same secret, keep the content type
   **application/json**, and activate the webhook.
3. Check that the App subscribes to the three events of [Create it](#create-it).

From an event, Qualor takes only the repository, the pull request, the action and whether the
author is a person or a bot. It never uses the comment's text: it reads the comments through the
API. A comment by a bot, Qualor's own App included, starts nothing.

### Update an App you created before

An App keeps the permissions and events it was created with. To add **Contents: Read and write**,
**Issues: Read-only** and the comment events (for the **Workflows** and **Secrets** permissions of
[CI setup](#set-up-ci-with-a-pull-request), see the end of this section):

1. On GitHub, open the App's settings (**Settings → Developer settings → GitHub Apps**, your App,
   **Edit**) and go to **Permissions & events**. Under **Repository permissions**, set **Contents**
   to **Read and write** and **Issues** to **Read-only**. Under **Subscribe to events**, tick
   **Issue comment** and **Pull request review comment**, and keep **Check run**. Save.
2. GitHub asks the owner of each installation (the organisation or account the App is installed on)
   to accept the new permissions on the installation's page. Until they do:
   - Qualor's conversations stay open after a fix or a won't fix.
   - GitHub sends no **Issue comment** event, so a `qualor review` comment waits for the next
     analysis or **Re-run**. Replies in review conversations need only their own event.
3. Make sure the webhook is active with Qualor's URL and secret
   ([above](#turn-on-the-webhook-recommended)). The App's **Advanced** tab lists recent deliveries
   and Qualor's answers.
4. On **Settings → GitHub**, **Test** the App with a repository: it lists what the App still lacks.

To allow [CI setup](#set-up-ci-with-a-pull-request), set two more repository permissions the same
way: **Workflows: Read and write** and **Secrets: Read and write**. The owner of each installation
then accepts them on the installation's page. **Settings → GitHub** shows which of the three
permissions CI setup still lacks (Contents included).

### What reviewers see

- **A check run** `qualor/<project key>` on every analysed commit: *success* or *failure*, with the
  failed conditions in its title and the summary in its body. It has no annotations: findings on
  the changed lines are review comments. Qualor writes it first, so it never waits for the comments.
- **A review comment on each new issue** on a line the pull request added, up to 50 per pull
  request. The rule's key links to its documentation, and with `QUALOR_PUBLIC_URL` set the comment
  links to the issue in Qualor. An analysis posts its new comments as one review, so GitHub notifies
  once. A comment keeps the text it was posted with: a severity changed later in Qualor shows in the
  summary. A Qualor comment you delete comes back at the next analysis. To silence one, mark its
  issue in Qualor.
- **One summary comment** per pull request, edited in place. It holds the verdict, every gate
  condition with its value and the value it requires, the new issues by severity, and the ten most
  severe with their rule and a link to each in Qualor. It also counts the issues commented inline
  and those that could not be placed on the diff, and links to the branch in Qualor.
- **AI review**, when an organisation admin switched it on for the project
  ([AI review](./ai-review.md)): an **AI review** section in the summary, and a review comment on
  each finding of high or medium severity, up to 20 per pull request on top of the 50. They come in
  the same review as the analyzers' comments. A suggested change in one is applied with **Commit
  suggestion**. These comments need no extra permission.
- **Answers** to a person's reply in one of Qualor's conversations, and to a comment on the pull
  request's page that starts with `qualor review`, when AI review is on for the project
  ([Replies and commands](./ai-review.md#replies-and-commands)). A reply can mark an AI finding
  won't fix or false positive, and Qualor then resolves its conversation (with **Contents: Read and
  write**). Who may do that depends on their role in the repository
  ([Who may change a status](./ai-review.md#who-may-change-a-status)).

Marking an issue **false positive** or **won't fix** in Qualor re-evaluates the gate at once, with
no new scan. The check run is updated in place.

**Conversations.** Each review comment is a conversation that people can reply to and resolve.

- Qualor resolves its conversation when the issue is fixed or marked in Qualor, and reopens it if
  the issue comes back. This needs **Contents: Read and write**.
- Without that permission, conversations stay as they are, and the summary says how many. An open
  one stays open, and one that Qualor resolved earlier stays resolved when its issue comes back.
- When someone else replied in a conversation, Qualor no longer resolves it. When the issue is
  fixed, Qualor writes one note in it instead, "Fixed in `<sha>`", and leaves it open. The note
  needs no Contents permission. A reply does not stop Qualor from reopening a conversation it
  resolved itself.
- Qualor never reopens a conversation that someone else resolved.
- AI review's conversations follow the same rules.

**Limits.** GitHub asks integrations to make at most one write a second, and Qualor keeps to that.
An analysis's new comments take one write, but each conversation resolved or reopened takes one
more. When many issues are fixed at once, their conversations can take a minute or more to follow.

One run of Qualor's comments makes at most 350 requests to GitHub. It posts at most 50 analyzer
comments and 20 AI review comments, the most severe first, and resolves or reopens at most 100
conversations. The check run and the summary are always written. The rest waits for the next
analysis.

### GitHub Enterprise Server

When GitHub Enterprise Server is on an internal network, the Qualor server needs its host in
`QUALOR_SCM_INTERNAL_HOSTS` ([Server settings](./install-server.md#server-settings)). When its
certificate comes from a private CA, give the Qualor server that CA with `NODE_EXTRA_CA_CERTS`.

## Set up CI with a pull request

**Add repositories** (in **Projects**, [Quick start](./quick-start.md#fastest-path-add-repositories))
can add the Qualor workflow to each repository for you. Qualor opens a pull request (its pages call
it a merge request). Your workflows don't change until you merge it. The project's token is stored
as an Actions secret right away. The pull request's own run is the first analysis.

The pull request is on the branch `qualor/setup`, titled **Add Qualor code analysis**. It adds one
new file, `.github/workflows/qualor.yml`, and leaves your other workflows alone:

- The workflow is the one from [The workflow](#2-the-workflow), with your Qualor address and the
  project's key written in. The Action is pinned to the server's minor version, such as
  `qualor-dev/scan-action@v0.13`.
- A C# repository gets the workflow of `integrations/github/qualor-dotnet.yml`, with the image tag
  and the project's key written in. The token is in the `qualor dotnet end` step only. Check its build command before you
  merge.
- The token is the Actions secret `QUALOR_TOKEN`, a project analysis token named **CI setup**.
  It is never in the pull request.

Qualor shows the snippet instead of opening a pull request when the repository already has a Qualor
workflow or a `QUALOR_TOKEN` secret, or is empty. It never overwrites either.

### What the App needs

CI setup needs the App to have **Contents**, **Workflows** and **Secrets**, each at **Read and
write**:

| Permission | Access | What Qualor uses it for |
|---|---|---|
| Contents | Read and write | creating the branch and committing the file (already part of the [base setup](#create-it)) |
| Workflows | Read and write | adding the workflow file |
| Secrets | Read and write | storing `QUALOR_TOKEN` |

The server also needs `QUALOR_PUBLIC_URL` ([Server settings](./install-server.md#server-settings)).

- **New App:** register it from
  [`integrations/github/app-manifest-ci-setup.json`](../../integrations/github/app-manifest-ci-setup.json).
  It is the manifest of [Create it](#create-it) plus Workflows and Secrets.
- **Existing App:** add the missing ones (an App created before Contents: Read and write was part
  of the setup lacks it too) as in
  [Update an App you created before](#update-an-app-you-created-before). The owner of each
  installation must accept them.

Without all three on one installation, **Add repositories** still creates the projects and shows
the snippet and the token.

### CI setup on GitHub Enterprise Server

The Action lives on github.com, so a GitHub Enterprise Server cannot use it. There Qualor writes a
plain job that runs `qualor/scanner:<version>` in a container on a runner labelled
`[self-hosted, linux]`. The runner needs Docker and access to Docker Hub or your mirror. To upgrade
the scanner, edit the version in the file. GitHub.com and GHE.com get the Action.

### Undo CI setup

1. Close the pull request and delete the branch `qualor/setup`.
2. Delete the Actions secret `QUALOR_TOKEN` under **Settings → Secrets and variables → Actions**.
3. In Qualor, revoke the project's **CI setup** token in the project's token settings.

## 4. Block merges on the gate

Add a branch protection rule or a ruleset on the default branch that requires the status check
**`qualor`** (the workflow job), **`qualor/<project key>`** (the App's check run), or both.

If the rule also requires conversations to be resolved, Qualor's open comments block the merge. That
includes comments on issues that pass the gate, such as low and info ones, and the comments of
[AI review](./ai-review.md). Qualor resolves its own as described in
[What reviewers see](#what-reviewers-see), and a person can resolve them too. Without **Contents:
Read and write**, a person has to resolve each one.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The job is skipped | the pull request comes from a fork, by design |
| Exit 5 | the `QUALOR_TOKEN` secret is wrong or revoked |
| Gate `error`, new code unavailable | `fetch-depth: 0` is missing |
| No check run | no App connection or mapping, the App is not installed on the repository, or it lacks a permission |
| No review comment on an issue | the workflow checked out GitHub's merge commit, and the summary says "The analyzers’ issues are not commented inline": use the `ref:` of [the workflow](#2-the-workflow). Or the issue is not on a line the pull request added, or is past the 50 per pull request. The summary counts these |
| No **AI review** section in the summary | AI review is not switched on for the project ([Why AI review is off for a project](./ai-review.md#why-ai-review-is-off-for-a-project)), or the workflow did not run for a pull request |
| No comment on an AI finding | the section says what became of the review ([What the summary says](./ai-review.md#what-the-summary-says)). A low finding without a suggested change gets none, nor does one past the 20 per pull request, nor one made for a commit the pull request has moved past. The summary counts them and lists those it can |
| Replies and `qualor review` comments are answered only at the next analysis | the webhook is not set up or not active, its secret differs from Qualor's (the App's **Advanced** tab shows 401), or the App does not subscribe to **Issue comment** and **Pull request review comment**. For `qualor review` only: the App lacks **Issues: Read-only**, or an installation's owner has not accepted it ([Update an App you created before](#update-an-app-you-created-before)) |
| A reply or a `qualor review` comment gets no answer at all | see [Why a reply or a command was not answered](./ai-review.md#why-a-reply-or-a-command-was-not-answered) |
| Conversations stay open after a fix or a won't fix | the App lacks **Contents: Read and write**, or an installation's owner has not accepted it ([Update an App you created before](#update-an-app-you-created-before)). The summary counts these conversations, and **Test** on **Settings → GitHub** lists what the App lacks |
| A conversation stays open after the issue is fixed or marked | someone else replied in it, so Qualor leaves it to people. For a fixed issue it writes "Fixed in `<sha>`" in it |
| The summary says "Inline comments could not be updated this time." | GitHub failed or refused a request for the review comments. After an outage or a rate limit, Qualor tries again on its own. After a missing permission, it tries again at the next analysis. The server log's `GitHub decoration retried` or `GitHub decoration stopped` line says why |
| `The GitHub repository was not found` after a rename | update the mapping to the new `owner/repo` |

More in [Troubleshooting](./troubleshooting.md).
