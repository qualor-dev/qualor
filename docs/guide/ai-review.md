# AI review

AI review has a model of your choice review GitLab merge requests and GitHub pull requests. It
comments in threads on the changed lines, answers replies, and reviews again after each push. It is
in every edition and **off by default**. On GitHub, read "pull request" wherever this page says
"merge request".

AI review uses the provider of the [AI assistant](./ai-assistant.md): a hosted model with your own
key, or a local model on your network. **Your code goes to that provider.** For each merge request
of the projects you choose, the scanner uploads a copy of the repository to your Qualor server. The
model gets the diff, the thread of a reply it answers, and any file it chooses to read. Choose the
projects with that in mind.

## How it works

1. An organisation admin chooses the projects in **Settings → AI**, switches AI review on and
   confirms a warning that names the provider.
2. After the scan of a merge request, the scanner uploads a **snapshot**: the repository at the
   merge request's last commit, with its changes, secrets masked.
3. The server reviews it in the background, without holding up the scan, the quality gate or the
   analyzers' comments.
4. The review adds a section to Qualor's summary comment and a thread on each finding, with a
   suggested change where one fits. The findings are also issues in Qualor, marked **AI**.
5. Qualor answers replies in its threads and `qualor review` notes. A reply can mark an AI finding
   won't fix or false positive.
6. Each push is reviewed again, and only its new changes raise new findings.
7. Qualor deletes the snapshot when the merge request is merged or closed.

Only merge request scans send a snapshot, and only for projects with AI review on. A scan of the
main branch or of any other branch never does.

AI review never changes the quality gate, the measures or the scan's exit code, and a failed review
never fails the analysis. It never approves or rejects a merge request and never commits: a person
applies a suggestion.

## Switch it on

### What has to be in place

- An instance admin has connected a provider in **Settings → AI provider** and allowed the
  organisation to use AI ([Configuration](./ai-assistant.md#configuration)). The assistant's own
  features (Explain, Suggest triage, Suggest a fix) need not be on.
- The model can call tools ([Models that work](#models-that-work)).
- The project is mapped to its GitLab or GitHub repository, where the review is posted
  ([GitLab](./gitlab.md), [GitHub](./github.md)).
- Your CI scans merge requests with the full history ([What your CI needs](#what-your-ci-needs)).
- Optional: a webhook on the SCM connection, so that replies and commands are answered at once
  ([At once, or at the next analysis](#at-once-or-at-the-next-analysis)).

Without a provider, **Settings → AI** says "AI isn't set up on this server yet.". For an
organisation that may not use AI, it says "Acme may not use AI yet." (for an organisation named
Acme). If AI review was on before, it adds "AI review was switched on before, and is stopped." with
**Switch off AI review**.

### In Qualor

Organisation admins (permission `org.ai.manage`) and instance admins switch AI review on in
**Settings → AI**, for the organisation chosen in the header. The **Status** card shows whether AI
review is on, how many projects it reviews and today's use. The **AI review** section below it
holds the projects and the budgets. For an organisation named Acme:

1. Under **Projects to review**, choose **All projects of Acme**, or **Selected projects** and then
   **Add projects**. By default no project is selected, so nothing is reviewed. **Remove** takes a
   project off the list.
2. Open **Budgets** if the [defaults](#budgets-and-todays-usage) do not suit you.
3. Press **Save AI review**. Saving works while AI review is off, so you can prepare first.
4. Press **Switch on AI review…** on the **AI review** line of the Status. The box shows
   [the warning](#the-warning) and what will be reviewed. Confirm with **Switch on and send code
   to** and your provider's host, which also saves unsaved changes. If the instance admin's last
   Test found a model that cannot call tools, the box warns that reviews would fail.

The Status then says **On**, how many projects are reviewed, and who confirmed the warning, when,
for which provider and models. The **Reviewed?** column of each chosen project says:

- **Yes**: it is reviewed;
- **Not linked**: the project has no GitLab or GitHub repository, so it is not reviewed or counted.
  Link it in **Settings → Repositories**;
- **Excluded**: an instance admin excluded it from AI, so it is never reviewed, whatever you choose.

A project's **AI** panel (**Project → Settings → AI**) shows whether AI review runs for it and, if
not, the reason and who can change it.

To switch AI review off, press **Switch off AI review**, then **Switch off**. A running review stops
at its next step, and Qualor deletes the snapshots of the projects no longer reviewed. Switching on
again asks for the warning again.

### The warning

Whoever switches AI review on confirms this text, which the API returns too:

> AI review sends the merge request's diff and any repository file the model chooses to read to
> `<host>` (`<models>`). The scanner uploads a copy of the repository to this Qualor server for each
> merge request; Qualor keeps it until the merge request is closed (at most `<days>` days). Secrets
> the analyzers found are masked; credentials files are never sent.

`<host>` is the provider's address with its port, such as `ollama:11434`. `<models>` lists every
model the review uses, sorted: one, or up to three with a strong and a fast model
([Model tiers](./ai-assistant.md#model-tiers)). `<days>` is 14. No masking finds every secret
([How secrets are masked](#how-secrets-are-masked)).

Qualor records who confirmed the warning, when, and for which provider. With the audit log
(`audit-log`), each change of these settings is recorded as `organization.ai_review_changed`
([Roles and the audit log](./roles-and-audit.md#what-is-recorded)).

**A confirmation covers one provider and its models.** If an instance admin changes the provider's
address or host, or adds, drops or changes a model, AI review stops until an organisation admin
confirms again. The instance admin is asked first ("Pause AI review in Acme?"). The Status then
says **Paused**, "The AI provider changed", with what was confirmed and what the provider uses now.
**Review and confirm…** opens the new warning. If the provider changes while the box is open,
saving is refused and the box shows the new warning.

## What your CI needs

- **A scanner of the server's release.** A scanner from before AI review sends no snapshot and logs
  nothing about it. Pin the CI component
  ([GitLab](./gitlab.md#with-the-cicd-component-recommended)), the action
  ([GitHub](./github.md#2-the-workflow)) or the scanner image to the server's release.
- **Merge request pipelines on GitLab CI or GitHub Actions**: `merge_request_event`
  ([GitLab](./gitlab.md#2-the-ci-job)) or `pull_request` ([GitHub](./github.md#2-the-workflow)).
  Other CI systems, such as Jenkins, Bitbucket, TeamCity or a laptop, send no snapshot, even with
  `--mr` and `--mr-target`: the scanner reads the merge request, last commit, title and description
  only from these two (table below).
- **The full history**: `GIT_DEPTH: 0` on GitLab, `fetch-depth: 0` on GitHub. A shallow clone that
  cannot be deepened sends no snapshot.
- **The last commit in the clone.** GitHub's default checkout is a merge commit, so the scanner
  fetches the last commit from `origin` with the checkout's credentials. On a private repository
  with `persist-credentials: false` that fails: check out the pull request's head, as the
  [GitHub workflow](./github.md#2-the-workflow) does. With `scm.autoFetch: false` in `qualor.yml`
  nothing is fetched, and a clone without the last commit sends no snapshot.
- **A scan that does not exit 3.** If a required analyzer fails, no snapshot is sent.
- **`--mr` only for this merge request.** If `--mr` and `--mr-target` name another merge request
  than the one CI runs for, no snapshot is sent.
- **Time.** Masking runs at about 1.8 MB of text a second on a developer machine: about 15 seconds
  for a 25 MB repository, about five minutes near the 500 MiB limit. The job does not wait for the
  server to unpack the snapshot. A snapshot not built within **10 minutes** (a stalled fetch, say)
  is not sent, and the job goes on to the quality gate.

| | GitLab | GitHub (the event's) |
|---|---|---|
| Last commit | `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` in a merged-result or merge-train pipeline, `CI_COMMIT_SHA` otherwise | `pull_request.head.sha` |
| Title | `CI_MERGE_REQUEST_TITLE` | `pull_request.title` |
| Description | `CI_MERGE_REQUEST_DESCRIPTION` | `pull_request.body` |

**The snapshot never changes the scan's result.** A failure while it is built or sent is a warning
in the log, and the exit code stays the quality gate's.

## Models that work

- **Tool calling is required.** The model reads the repository through tools. If the server refuses
  tools, the review fails. If the model ignores them, it reviews only what it is shown up front. In
  **Settings → AI provider**, the Test (**Save and test**, **Test again**) checks each model: its
  line ends `can call tools` or `cannot call tools, so AI review would fail`, or neither when it
  could not tell.
- **OpenAI's newest models need the Responses API** for tools with reasoning. `gpt-6.1-sol`,
  `gpt-6.1-terra` and `gpt-6-luna` were checked. Choose **Responses** under **API** in the
  **Connection options** of **Settings → AI provider**
  ([The current models](./ai-assistant.md#the-current-models)). On Chat Completions the review
  fails, and the Test tells you to choose Responses. vLLM, Ollama and Azure deployments stay on Chat
  Completions.
- **Anthropic's current models** (Claude 4.7 and later) take no temperature, and Qualor sends none.
  An organisation-wide key that is not scoped to a workspace needs the **Workspace ID**
  (`wrkspc_…`). Without it the Test says "This key is not scoped to a workspace: give its workspace
  ID above.", and a review ends with `PROVIDER_WORKSPACE_REQUIRED`.
- **Use a strong model.** Small local models miss problems, report ones that are not there, and
  more often fail to answer in the form the review needs.
- **Allow time.** A reviewer may write 12 288 tokens in one answer and the judge 16 384, and a
  reasoning model can think for minutes first. So review and reply calls **stream**, and a gateway
  that cuts idle connections does not cut a long answer. Qualor waits for each piece as long as the
  provider's **Timeout** (in **Connection options**, 60 seconds by default, up to 600) or 5 minutes,
  whichever is longer. A call has 15 minutes in all. A review usually takes a few minutes, a big
  merge request 15 or more. A review has 45 minutes in all. The reviewers stop at 60 % of them, so
  the judge has time to answer. When the time is up, a reviewer answers with what it has, and the
  summary says so. A call that has started is not cut. A review whose judge cannot answer in time
  fails, and the next push reviews again. The operator sets another time with
  `QUALOR_AI_REVIEW_MAX_MINUTES` ([Snapshot limits and workers](#snapshot-limits-and-workers)).
- **Servers that do not stream** work too. One that refuses a streamed request (a 400 that names
  `stream`) is asked again without streaming, and Qualor remembers that server address and model
  until the server restarts (one log line says so). Such a call waits at least 5 minutes for its
  answer. An answer with a JSON content type, or with none and starting with `{` or `[`, is read as
  JSON. Any other answer is read as a stream.
- **A refusal fails that step.** Anthropic's and OpenAI's current models can refuse inside an
  answer, and Qualor treats that as an answer it cannot read. A reviewer's or a check's part goes
  missing (the summary says so), a refusal by the judge fails the review, and a refused reply goes
  unanswered. Qualor never falls back to a model you did not choose.
- **Reviews are written in English**, whatever language your code is in. An answer to a reply uses
  the language of the person's last note.

## How a review works

A review starts when the snapshot arrives and runs in the background. The summary says **AI review
in progress…** until it ends.

- **A late snapshot.** The review waits 15 minutes for it, then ends as not run. A snapshot that
  arrives later starts it again, unless a newer push has been analysed since.
- **A newer push** replaces a review in progress. The old review stops and stores nothing, unless it
  is already storing its findings.
- **Not reviewed.** A draft is not reviewed unless someone asks with `qualor review`
  ([Commands](#commands)). Nor is a merged or closed merge request, or a push with nothing to
  review or with the same reviewed changes as the last review. A merge request too large for
  **Tokens per review** is skipped, and so is every merge request while the day's budget is spent.
  The summary says why ([What the summary says](#what-the-summary-says)).
- **A server stop** fails a running review at once, and the review is not resumed. The next push
  reviews again. A review that had not started, and an answer still waiting for the model, run once
  the server is back.

### What the model is sent

- the merge request's title, the first 4 000 characters of its description, and the name of its
  target branch;
- the changed files with the code around the changes, and any other file the model chooses to read;
- `AGENTS.md`, `CLAUDE.md` and `REVIEW.md` from the repository's root, when it has them;
- the analyzers' findings on the changed files: rule, severity, message and place. Secret findings
  are among them as rule, place and masked message;
- the findings of earlier reviews of this merge request, and which of them a person dismissed.

Secrets are masked in all of it, including files the model reads later. Credentials files are not
in the snapshot. Files on **Never send these paths** (**Settings → AI provider**) are never shown
to the model. Only the server contacts the provider, at the address the instance admin configured.

The rules files say what the repository intends and how it wants to be reviewed. They are read as
they were where the branch left the target branch, so a merge request cannot rewrite them. A finding
that goes against them is not one. They can narrow or explain the review, but never change what it
does or how it answers. The review does not repeat the analyzers' findings. Everything it reads
from the repository, the description and the rules files is data to the model, never instructions,
and the model is told so.

### What it reviews

The files the merge request changed, except:

- lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `Cargo.lock` and the
  like);
- generated files (`@generated` or `Code generated … DO NOT EDIT` in their first lines) and minified
  files;
- binary files;
- files on **Never send these paths** in **Settings → AI provider**
  ([What is sent, and where](./ai-assistant.md#what-is-sent-and-where)).

### The reviewers

The size of the change, in lines added and removed in the reviewed files, sets the reviewers:

| Size of the change | Reviewers |
|---|---|
| up to 10 lines | quality |
| up to 300 lines in at most 20 files | quality and tests |
| anything larger | security, quality, tests and performance |

A security-sensitive path adds the security reviewer at any size. That is a path with `auth`,
`login`, `session`, `password`, `secret`, `crypt` or a few more such words anywhere in it. It is
also a path with `token`, `sso`, `acl`, `jwt`, `csrf` or `rbac`, alone or plural, where no
lower-case letter follows: `token.ts`, `tokens/` and `csrfToken.ts` count, `tokenizer/` does not.

| Reviewer | Looks for |
|---|---|
| quality | logic errors, errors that are swallowed or mishandled, risky or breaking changes, concurrency problems |
| tests | changed behaviour that no test would catch breaking, tests that cannot fail, documentation the change makes wrong |
| security | injection, missing or wrong authorisation, secrets in code or logs, misused cryptography, server-side request forgery, path traversal, unsafe deserialisation |
| performance | work that grows faster than it should, a query or request per item, memory with no bound, blocking calls on hot paths |

The reviewers run one after the other. Each reads the change with the code around it, and can read
more through three read-only tools over the snapshot: read a file, search for a piece of text (not
a pattern), and list files. The tools run nothing and reach nothing outside the snapshot.

The reviewers run on the standard model. The quality reviewer of a change of 10 lines or fewer uses
the fast model when one is set ([Model tiers](./ai-assistant.md#model-tiers)).

### The judge

Reviewers report everything they suspect. A judge then checks their findings against the code. It
keeps what the code shows, merges findings about one problem, and drops the rest. It also re-checks
earlier findings ([Re-reviews](#re-reviews)) and writes the summary's verdict and walkthrough. If
its answer cannot be read, the review fails and posts nothing. The judge runs on the strong model
when one is set.

### The second check of security findings

Each security finding that the judge keeps as high or medium is checked again, in a separate
conversation that sees only that finding and decides from the code whether it is real. At most five
are checked, the most severe first. A rejected finding is dropped. A confirmed one says so on the
issue. One that cannot be settled stays as a possible finding, marked **Needs validation**. This
check runs on the strong model too.

### What counts as a finding

A finding is a problem the merge request brings in or makes worse, in code it adds or changes or
whose behaviour it changes. The reviewers and the judge are told not to report:

- unchanged code that the merge request does not affect;
- advice to use another library, framework or tool;
- formatting or style that a formatter or linter fixes, and matters of taste;
- defence in depth where the main defence holds;
- a risk that the code rules out.

A finding must be on a changed line or within three lines of one, or it is dropped. A review keeps
at most 40 findings. Each has:

- **a category:** logic, error handling, compatibility, concurrency, security, performance, tests or
  documentation. Its rule is `ai:logic`, `ai:error-handling`, `ai:compatibility`,
  `ai:concurrency`, `ai:security`, `ai:performance`, `ai:tests` or `ai:docs`.
- **a severity:** **High** is an outage, lost or corrupted data, or an exploitable flaw. **Medium**
  is a concrete risk: a wrong result, a crash or a leak on inputs that occur, or a broken contract.
  **Low** is worth considering, but nothing goes wrong yet. You can change it as for any issue.
- **a confidence:** _likely_ when the review read the code involved and the problem follows from it.
  _possible_ when it follows only if an assumption holds that the review could not check, and the
  finding states the assumption. A suspicion the code did not confirm is not reported.

## What you see in the merge request

### The summary

AI review adds an **AI review** section to Qualor's summary comment. Until the review ends it says
"AI review in progress…". Then it shows:

- the judge's one-sentence verdict;
- the open findings by severity, such as `Findings: 1 high · 2 medium · 0 low`, or "No findings.";
- a walkthrough of what the merge request changes, in up to six points;
- under **Not on changed lines**, findings that have no thread: those far from any changed line,
  and those past the thread cap or whose merge request moved on. Up to ten are listed, the most
  severe first, with links to Qualor, and the rest are counted. A low finding on a changed line
  without a suggested change has no thread and is only counted;
- notes where the review fell short, such as its token limit
  ([What the summary says](#what-the-summary-says));
- the commit it reviewed, and the latest commit when that differs;
- when there is room, a collapsed **Prompt for an AI agent** with up to 20 open findings, to paste
  into a coding agent.

When the review did not run or failed, the section says so in one sentence. AI findings are not in
the summary's count of new issues.

### Threads

A high or medium finding gets a thread on its line in the diff: a discussion on GitLab, a review
comment on GitHub. A low finding gets one only with a suggested change that applies. The thread's
first comment has:

- a header with the severity, the category, _likely_ or _possible_, and the rule key;
- the title in bold, then what is wrong, why it matters and how to fix it;
- **Assumes:** with the finding's assumption, and **Needs validation** when the second check could
  not settle it;
- the suggested change, if any;
- a link to the finding in Qualor.

A merge request gets at most **20 AI threads**, beside the analyzers' 50, the most severe first.
Threads are posted only while the merge request is still at the reviewed commit; after a newer push,
that push's review posts its own. Threads are never deleted.

The threads need no extra GitLab scope or GitHub App permission. Only answering `qualor review` at
once on GitHub needs the App's Issues: Read-only permission
([GitHub](./github.md#turn-on-the-webhook-recommended)). **On GitHub, Qualor resolves or reopens a
thread only when the App has Contents: Read and write**
([What reviewers see](./github.md#what-reviewers-see)). That holds wherever this page says Qualor
resolves or reopens a thread.

If merging requires all threads to be resolved, open AI threads block it like the analyzers' do
([GitLab](./gitlab.md#4-block-merges-on-the-gate),
[GitHub](./github.md#4-block-merges-on-the-gate)).

### Suggested changes

When the fix replaces up to 15 lines that the merge request added, the thread carries it as a
GitLab suggestion or GitHub suggested change. A person applies it with a click, which commits in
that person's name. Qualor never commits, pushes or opens a branch.

The suggestion is posted only if the lines it replaces are still exactly the added lines the review
read, and it passes the checks of the AI assistant's fix suggestions: no secret, no control
character, no GitLab quick action. Otherwise the thread says in words how to fix the problem.

### The text

The model's prose reaches GitLab and GitHub as plain text. Anything that could become a link, a
mention, a reference or markup goes in code formatting: addresses, `@name`, `#1`, `!1`, commit
hashes, issue keys such as `ABC-123`, file paths and HTML. Hidden and direction-reversing characters
are removed. So the model cannot mention a person, run a GitLab quick action or add a link. Qualor's
own labels and links are fixed text.

One exception: plain words that match an issue tracker you set up can still become links to that
tracker. Examples are `bug 12` (GitLab's EWM integration), `CU-abc` (ClickUp), `TICKET-abc` (a
custom autolink of a GitHub repository) and whatever a GitLab project's `jira_issue_regex` matches.

### The findings in Qualor

- Each finding is an issue of the engine `ai`, with an **AI** badge in the issue list and on the
  file page of the **Code** tab. Filter the issue list by the engine **AI review**.
- The issue page has an **AI review** card: the text, the assumption, the second check's result,
  the suggested change and the reviewed commit. It ends "Found by AI review. It may be wrong, and it
  never counts in the quality gate."
- Findings are outside the measures, the quality gate and the counts of new issues.
- **False positive** and **Won't fix** dismiss a finding, and the review never raises it again. A
  reply in the thread can do the same ([What a reply can change](#what-a-reply-can-change)).
- The issue's history says the review raised it and, when a later review closes it, whether the
  problem was fixed or its file deleted.
- The `ai:*` rules are in the rules list and in profiles, but profiles do not affect them:
  deactivating one does not stop the review. To keep AI review off a project, leave the project out
  of **Projects to review**.
- In [MCP](./mcp.md), `qualor_issues` marks findings `AI`, and `qualor_issue` gives the review's
  text, assumption, suggested change and reviewed commit.

When an issue is fixed or marked in Qualor, Qualor resolves its thread, unless a person replied in
it. Then, for a fix, Qualor writes one note instead: "Fixed in `<sha>`". Resolving a thread on
GitLab or GitHub only hides it. To dismiss the finding, mark the issue in Qualor or say so in a
reply.

## Replies and commands

Qualor answers replies in its own threads, and notes that start with `qualor review`, `qualor fix`
or `qualor stop`. It does so for projects with AI review on, in open merge requests it has
analysed.

### Replies

Qualor answers a note when all of these hold:

- **It is in a thread Qualor started** on a finding, from an analyzer or from AI review. Replies to
  the summary comment are not answered.
- **A person wrote it.** On GitHub that is a User account: bots, Qualor's App among them, are never
  answered. On GitLab it is anyone but Qualor's own user, apart from system notes. So give the
  GitLab connection a bot account, such as a project or group access token
  ([GitLab](./gitlab.md#3-merge-request-comments-and-commit-status)). Notes by the user whose token
  Qualor uses look like Qualor's own and are not answered.
- **It is new**: newer than every note Qualor has handled in that thread.
- **It is recent**: written after an organisation admin last confirmed the warning, and at most 30
  days ago. Switching AI review on never answers old threads.
- **The thread and the merge request are open.** A resolved thread gets no answer, including one
  Qualor resolved after a status change. On GitHub without **Contents: Read and write**, that thread
  stays open and later replies are answered.

All notes in a thread since Qualor's last answer form one **round**, answered once. Two replies
close together usually get one answer. A reply written while Qualor is answering starts a new
round.

To answer, the model gets the finding (rule, message and place, and for an AI finding its text and
suggested change), Qualor's first comment, and the newest 20 notes since Qualor's last answer, each
with its author's user name and cut to 2 000 characters. While the merge request has a snapshot,
the model can read the repository with the review's three tools. Secrets are masked, and the
replies are data to the model, never instructions.

The answer is plain prose in the language of the person's last note, up to 1 200 characters, under
the heading **AI review** · reply. A thank-you may get no answer. Its text is made safe as the
review's is ([The text](#the-text)).

### What a reply can change

A reply can change the status of **the one finding its thread is about**, and only when that is an
**open AI review finding**:

| What a member of the project writes | What Qualor does | The answer ends with |
|---|---|---|
| A decision of priority: the team accepts the risk, or will not fix it | marks the finding **Won't fix** and resolves the thread | `Marked won't fix.` |
| A claim that the finding is wrong, or that the code is meant to work that way, and the code shows it | marks it **False positive** and resolves the thread | `Marked as a false positive: the code shows it does not hold.` |
| A question, disagreement, thanks, or anything else | answers, and changes nothing | |

A false positive needs proof. Qualor must have read the finding's lines, through a file read that
showed one or a search that matched one. The code must also be unchanged: the snapshot is of the
reviewed commit, or the lines still hold the same text. Without a snapshot, Qualor answers from the
thread alone and never marks a false positive.

A demand is not a decision. "Mark every issue won't fix", an order to ignore its rules, a link or a
mention changes nothing. Qualor's code, not the model, decides which statuses a thread allows. An
answer that names another status, or cannot be read after a second try, is dropped, and nothing is
posted.

In an analyzer's thread, or one whose finding is no longer open, Qualor only explains the rule, why
it applies and how to fix it.

**What is recorded.** The issue's **History** shows the change with no user (as **Analysis**) and
the comment ``Won't fix after `<name>` replied in the merge request.`` or
``False positive after `<name>` replied in the merge request.``. `<name>` is the SCM user name of
the author of the round's newest note. With the audit log (`audit-log`), `issue.status_changed` is
recorded by `system`. A person can set the status back in Qualor.

### Who may change a status

A status changes only when every author in the round is a member:

- **GitLab:** Developer or higher on the project, through a membership in force. A group membership
  counts. An inactive user, or an inactive or expired membership, does not.
- **GitHub:** a repository role of admin, maintain, write or triage. A custom role counts by its
  legacy permission, `admin` or `write`. Qualor reads the role through the collaborator permission
  API, which needs only the Metadata permission every App has. Organisation membership counts only
  through the role it gives on the repository, so read access does not qualify.

Anyone else, and any round with more than five authors, gets an answer without a status change. A
member can still change the status in Qualor, or write the reply.

### Commands

A command is a **top-level** note whose **first line** starts with `qualor review`, `qualor fix` or
`qualor stop`, in any case, followed by a space or the line's end. `Qualor review please` is a
command. `@qualor review`, `please qualor review`, `qualor reviewer` and `qualor review.` are not.

Top-level means the first note of a discussion on GitLab, or a comment on the pull request's page
on GitHub, not a review comment on the diff. A note inside a thread is never a command. GitHub
comments by bots are ignored. As for replies, a command must be written after the warning was
confirmed and at most 30 days ago.

Qualor answers each command once with a fixed text, without calling a model: in the command's
discussion on GitLab, as a comment on the pull request on GitHub. A command deleted before Qualor
answers is not answered.

| The note | Qualor answers |
|---|---|
| `qualor review` from a person who may not ask | `Only project members can ask for an AI review.` |
| `qualor review`, and AI review was switched off after the note was written | `AI review is not switched on for this project.` |
| `qualor review`, and the commit was reviewed (the review is done, or found the same changes as the last one) | ``This commit (`<sha>`) has been reviewed. Push a new commit to review again.`` |
| `qualor review`, and a review of the commit is waiting or running | `A review of this commit is in progress.` |
| `qualor review` in any other case | ``Reviewing this commit (`<sha>`).`` |
| `qualor fix` or `qualor stop` | `Auto-fix is not switched on for this project.` |

`<sha>` is the commit's first 12 characters. Only `qualor review` does anything. `qualor fix` and
`qualor stop` are reserved for an automatic fixing of findings that does not exist yet, and anyone
gets the answer above.

- **Who may ask:** the members who may change a status (GitLab: Developer or more; GitHub: triage
  or more). A refusal is still posted.
- **What it starts:** a review of the newest analysis, if none has run for it or the last one ended
  without a result: skipped for any reason but "unchanged", failed, or replaced. The summary says
  "AI review in progress…" at once.
- **Drafts:** `qualor review` reviews a draft. The next push starts an ordinary review, which skips
  drafts, so a draft needs a new `qualor review` after each push.
- **It needs the snapshot** of that commit. Without one it waits 15 minutes and ends skipped, and
  the summary says no snapshot came.
- **One review per analysis.** A second note while it runs gets "in progress", one after it "has
  been reviewed". The day's budgets and **Tokens per review** apply.
- **In a monorepo,** every Qualor project mapped to the repository answers the command and starts
  its own review.
- **Only projects with AI review on answer.** Elsewhere a command gets no answer at all.

### At once, or at the next analysis

- **With a webhook**, GitLab or GitHub tells Qualor that someone commented. Qualor reads the
  comments through the API, never trusting the webhook's text, and answers as soon as the model has
  decided. Set it up on [GitLab](./gitlab.md#answers-to-replies-and-commands-webhook) (Comments
  events) or [GitHub](./github.md#turn-on-the-webhook-recommended) (Issue comment and Pull request
  review comment events, and the Issues permission).
- **Without one**, Qualor reads a merge request's comments when it updates its own: when the merge
  request is analysed again, when a review ends, when an issue's status changes in Qualor, and on
  GitHub when someone presses **Re-run**. A reply waits until then.

A failed webhook delivery does no harm: the next update finds the same notes. A note found both
ways is answered once. Answers run on the review worker
([Snapshot limits and workers](#snapshot-limits-and-workers)).

### What replies cost, and who can ask

Anyone who can comment on the merge request can write a reply or a command; on a public repository,
anyone with an account. These limits bound what they can spend:

- An answer keeps to 60 000 tokens and counts in AI review's budgets for the day
  ([Answers to replies](#answers-to-replies)).
- Only members can ask for a review, and an analysis has one review however often it is asked.
- Qualor queues at most 50 replies and 20 commands of a merge request at a time. The rest wait for
  the next time it looks.
- Qualor answers at most 5 rounds of one thread per UTC day. A later reply is answered on a later
  day, when Qualor next looks at the comments, together with the notes written meanwhile. So a
  reply bot or a noisy public thread cannot spend the day's budget.

### What Qualor keeps

Each handled reply and command is one record: the ids of the note and its thread, the author's SCM
user name, what came of it, Qualor's answer (up to 1 200 characters), the model, and the tokens and
cost. The text of the note is not kept. Records are deleted 90 days after they finish, or with
their merge request or project. Every model call is recorded too
([How long copies live](#how-long-copies-live)).

## Re-reviews

Each new scan of a merge request is reviewed again, at its latest commit.

- **Only new changes raise new findings**: on the lines changed since the last reviewed commit, or
  within three of them. After a rebase, or whenever the last reviewed commit has left the branch,
  the whole merge request counts as changed.
- **Earlier findings are re-checked.** The judge sees up to 50 earlier findings, open ones first,
  and says of each open one whether its problem is still there. One it does not see stays as it is.
- **Fixed findings close**, and their threads are resolved. A thread with a person's reply stays
  open and gets one note, "Fixed in `<sha>`". A finding in a deleted file closes too. One still
  there, or that the review could not judge, stays open.
- **A dismissed finding is never raised again** in the same place.
- **Threads follow their finding.** A thread Qualor resolved reopens if its finding opens again. A
  thread a person resolved stays resolved.
- **A push that changes nothing the review reads**, such as one touching only left-out files, is
  not reviewed again, and the findings stay.

## The repository snapshot

### What the scanner uploads

The snapshot is read from git at the merge request's **last commit**, not from the job's working
directory. Files your CI generated or changed after the checkout are not in it. It holds:

- **the repository's text files** at that commit: up to 50 000 files of up to 1 MiB each;
- **the changes**: for each changed file, whether it was added, modified, renamed or deleted, and
  its diff against where the branch left the target branch. A diff over 256 KiB is not sent. After
  a first review, also the lines changed since the last reviewed commit;
- **the rules files** `AGENTS.md`, `CLAUDE.md` and `REVIEW.md` of the repository's root, up to
  64 KiB each, as they were where the branch left the target branch;
- **the title and description**, cut to 255 and 12 000 characters. GitLab gives the job only the
  first 2 700 characters of a description.

**Left out**, and noted in the snapshot with the reason:

- files that the built-in excludes or your `sources.exclude` match, such as `node_modules`, `dist`,
  `build`, `vendor` and minified files ([Built-in excludes](./configuration.md#built-in-excludes)).
  To keep a file out of the snapshot, list it in `sources.exclude`;
- **credentials files**, as for the AI assistant: `.env` files, keys and certificates, `id_rsa`,
  `credentials*`, `.npmrc`, Docker and Kubernetes configs, Terraform variables and state
  ([What is sent, and where](./ai-assistant.md#what-is-sent-and-where)). Files renamed from them are
  left out too, and their diffs are not sent;
- binary files, files that are not UTF-8, and files over 1 MiB after masking;
- symbolic links and submodules;
- the scan's Gitleaks configuration at the scan root: `.gitleaks.toml`, other `.gitleaks.*` files
  and `.gitleaksignore`. If a merge request edits one, the snapshot shows only that it changed;
- paths that cannot be stored safely: over 1 024 bytes, with a control character, a backslash, an
  empty segment (`//`), a `.` or `..` segment or a leading `/`, not valid UTF-8, or holding a
  secret. The scan log counts them but never names them.

**Never send these paths** is a server setting the scanner does not read. Those files are uploaded,
and the review never shows them to the model.

The snapshot is sent compressed. When it is over the server's
[limits](#snapshot-limits-and-workers), the scanner sends the changed files first, then the rest by
nearness to the changes (same directory first), and marks the snapshot **partial**. If the changed
files and their diffs alone are over the limits, no snapshot is sent.

### How secrets are masked

Every text in the snapshot (files, diffs, rules files, title and description) is masked before it
leaves the CI job:

1. **Secrets the scan found.** What Gitleaks found in this scan, and the secret findings of
   OpenGrep or Semgrep and of [Qualor's own rules](./languages-and-analyzers.md), becomes
   `«redacted»` wherever it appears. That covers a secret over several lines, each of its lines in
   a diff, and a whole private key block. The CI job's Qualor token is masked too.
2. **Built-in patterns**, the AI assistant's
   ([What is sent, and where](./ai-assistant.md#what-is-sent-and-where)): private keys, cloud and
   SCM tokens, API keys, JSON Web Tokens, passwords in URLs, `Authorization` headers, and values of
   names such as `password`, `secret`, `token` or `api_key`. They catch what no analyzer found, and
   mask some ordinary text that looks like a secret.
3. **Removed lines.** The scan read the checkout, but a diff also shows removed lines, and the rules
   files come from where the branch left the target branch. So the scanner runs Gitleaks, with your
   configuration, over those older versions too. If it cannot (Gitleaks is off, or cannot run over
   them as in the scan), removed lines are **not sent**: each run of them becomes a line such as
   `-[3 removed lines not sent]`. The rules files are then masked with the built-in patterns only.
4. **Files the scan did not see as they are.** A GitLab merged-result pipeline and GitHub's default
   pull request checkout check out a merge commit, not the last commit, and a CI step can edit
   files. The scanner runs Gitleaks over the last commit's version of each file that differs from
   the checkout.

The server masks each file again with the built-in patterns before showing it to the model.

No masking is complete: a secret no analyzer found and no pattern matches can still be sent. Add
Gitleaks rules for your own secret formats (`analyzers.gitleaks.configFile` in `qualor.yml`). The
scan and the snapshot both use them.

#### When the secret scan stops the snapshot

The scanner sends no snapshot when it cannot trust the secret scan. The scan log says
`AI review: no snapshot sent, …` with one of these reasons:

- **A secret scan that is on did not complete.**
  - Gitleaks is on by default (`enabled: true`). If it fails, the scan exits 3 and sends no
    snapshot.
  - With `enabled: auto`, a Gitleaks that failed, timed out or is not installed stops the snapshot
    too, and so does one skipped because its `configFile` does not exist or is not a regular file.
  - OpenGrep or Semgrep (`analyzers.semgrep`) and Qualor's rules (`analyzers.qualor`) also mask
    secrets, and stop the snapshot the same way, unless they had **nothing to run**. That is Semgrep
    on its defaults (`configs: [qualor-default]`, as the scanner image ships no rule files), or
    Qualor's rules without their pack or without a file in their languages.
  - Qualor's rules with a pack that cannot run do stop it: OpenGrep is missing, the pack is
    damaged, the run failed, or `QUALOR_RULES_DIR` is a missing directory, a relative path or inside
    the checkout. Fix them, or set `analyzers.qualor.enabled: false`.
- **Rule files you named never ran.** Once `analyzers.semgrep.configs` names your own file or
  directory, a Semgrep that did not run stops the snapshot. Causes are a wrong path, neither
  OpenGrep nor Semgrep installed, or a failed run. A file that does not exist stops the snapshot
  too, even when your other files ran (the scan warns `SEMGREP_CONFIG_MISSING`). Fix the path or
  the tool, or set `analyzers.semgrep.enabled: false`.
- **The secret scan's output could not be read.**
- **The files that differ from the checkout could not be scanned** (item 4 above).

If you **switch Gitleaks off** (`analyzers.gitleaks.enabled: false`), the snapshot is still sent.
The built-in patterns mask it, with any secrets OpenGrep or Qualor's rules found if they ran (on
their defaults they find none), and removed lines are not sent. The scan log says "AI review: the
secret scan is off in qualor.yml; only built-in patterns mask secrets in the snapshot", even when
those two engines ran. Switch Gitleaks off only for code you are content to send.

### How long copies live

The snapshot is a copy of your repository in Qualor's database, unpacked by a server job into one
record per file in seconds. Qualor deletes it at the first of these:

- **A newer analysis.** A merge request keeps only its newest analysis's snapshot. Once the next
  analysis is processed, older snapshots go.
- **Merge or close.** Qualor deletes the copy when it sees the merge request merged or closed: when
  it posts comments, when a review reads the merge request, and in an hourly check of every merge
  request that holds a snapshot. So the copy is gone within an hour. If the check cannot reach
  GitLab or GitHub, it tries again an hour later.
- **AI review stops covering the project.** The project's copies go at once when:
  - you switch AI review off, or leave the project out of **Projects to review**;
  - an instance admin stops allowing the organisation to use AI, excludes the project from AI, or
    removes or changes the provider (until an organisation admin confirms again);
  - the project is unmapped from its repository or mapped to another repository or connection, or
    its SCM connection is deleted.
- **14 days.** A daily job deletes every snapshot older than 14 days, whatever its state. A snapshot
  the server refused (a damaged upload) is deleted after one day.

Qualor does not encrypt the snapshot, and no page or API shows it. It sits in the database like
reports and issue code snippets: treat the database and its [backups](./install-server.md#backups)
as you treat the code.

Allow for its size: about the repository's text, compressed by PostgreSQL, for each open merge
request with a recent push. Copies of failed or stale analyses stay until the branch's next
successful analysis, or for 14 days.

Other records of a review:

- **The findings** are issues, kept like any issue. A closed one is deleted after 30 days.
- **Each model call** is recorded like an AI assistant request, for 90 days: the feature `review`
  or `review-reply` (an answer to a reply), the model, the token counts, the estimated cost and a
  hash of what was sent. The server log has one line per call, without content:
  `AI review call finished`, or `AI review reply call finished`. With **Keep a copy of what is
  sent** on, the prompts are kept for the days set there (1 to 90, 7 by default), and the model's
  answers stay with the record. They can quote the code the model was shown and, for a reply, the
  thread ([Retention and audit](./ai-assistant.md#retention-and-audit)).
- **Replies and commands**: one record each, for 90 days after they finish
  ([What Qualor keeps](#what-qualor-keeps)).

### Snapshot limits and workers

The scanner asks the server for its limits before it builds the snapshot. Set them with server
variables ([Server settings](./install-server.md#server-settings)): with Docker Compose in the
`environment` of the `server` service, with Helm in `extraEnv`.

| Variable | Default | Meaning |
|---|---|---|
| `QUALOR_REVIEW_SNAPSHOT_MAX_COMPRESSED_BYTES` | 50 MiB | largest snapshot upload, as sent |
| `QUALOR_REVIEW_SNAPSHOT_MAX_DECOMPRESSED_BYTES` | 500 MiB | largest snapshot once inflated, from 1 MiB to 500 MiB |
| `QUALOR_REVIEW_WORKER_CONCURRENCY` | 2 | reviews and answers to replies that run at once, at most 8 |
| `QUALOR_AI_REVIEW_MAX_MINUTES` | 45 | a review's time in all, from 5 to 240 minutes |

Fixed limits: 1 MiB per file, 50 000 files, 256 KiB per diff, 64 MiB of diffs in all, 1 024 bytes
per path.

- **Reverse proxy:** raise `client_max_body_size` with the compressed limit
  ([Reverse proxy and TLS](./install-server.md#reverse-proxy-and-tls)).
- **Upload slots:** snapshots share them with reports (`QUALOR_MAX_CONCURRENT_UPLOADS`, 4 by
  default), but never take the last free slot, which stays for reports. With one slot, both share
  it. When no slot is free, the server answers 503 and the scanner retries.
- **Unpacking:** each merge request analysis with AI review on adds an unpack job to the analysis
  worker. With the default `QUALOR_WORKER_CONCURRENCY=1`, it can delay other projects' quality
  gates by a few seconds: set 2 or more on a busy server.
- **Reviews** run on their own worker, so they never delay an analysis or an AI assistant answer.
  Answers to replies and commands share it and take a free slot before a waiting review, but wait
  while every slot is busy with a review.
- **Memory:** each review, and each answer while the model decides, holds a masking worker of up
  to 512 MiB of heap. Add that per slot to the server's memory: 1 GiB at the default of 2. On a
  small server, set `QUALOR_REVIEW_WORKER_CONCURRENCY` to 1.

## Budgets and today's usage

AI review has budgets of its own, apart from the AI assistant's, so a large review cannot use up
the day's explanations, or the reverse. They cover reviews and answers to replies, per organisation
and UTC day. An organisation admin sets them in the **Budgets** fold of **Settings → AI**. Closed,
the fold shows their values, by default "2,000,000 tokens a day", "300,000 per review", "No limit
per project" and "No cost limit".

| Budget | Default | Meaning |
|---|---|---|
| Tokens per day | 2 000 000 | the most tokens, input and output, that all the organisation's reviews and answers may use in a day |
| Tokens per review | 300 000 | the most one review may use, from 1 to 10 000 000. An answer to a reply has its own limit of 60 000 tokens |
| Tokens per project per day | off (**Limit tokens per project**) | the most one project's reviews and answers may use in a day |
| Cost per day | off (**Limit the cost**) | in US dollars. It needs the model prices that the instance admin enters in **Settings → AI provider**, for the standard model and for a strong or fast model ([Model tiers](./ai-assistant.md#model-tiers)). Without them the switch is disabled, with "No prices are set on this server, so a cost limit would count nothing. An instance admin enters model prices in Settings → AI provider." |

**Instance ceiling.** The instance admin can cap every organisation with **Cap the tokens an
organization may give AI review**, in the **Limits** of **Settings → AI provider**. An
organisation's tokens per day are then the smaller of its own value and the ceiling. When the
ceiling is the smaller, **Settings → AI** says so under **Tokens per day**, such as "This server
caps AI review at 1,000,000 tokens a day per organization, so Acme gets 1,000,000."

**Today's usage** is the **AI review** meter on the **Today** line of the Status: tokens used since
UTC midnight against the day's budget, such as `120,000 of 2,000,000`, the number of reviews, such
as `3 reviews`, and `· $1.23` when prices are set. Tokens and cost include answers to replies; the
number of reviews does not, and skipped reviews are not counted. The API gives the same figures as
`usage` ([API](#api)). The **Assistant** meter beside it is the AI assistant's
([Budgets and limits](./ai-assistant.md#budgets-and-limits)).

### How a review spends its tokens

Before a review starts, Qualor sets what it may spend: the smallest of **Tokens per review**, what
the organisation has left of its day, what the project has left of its day (with a project
budget), and what the cost budget has left. Cost is counted at the dearest price a token of your
models can have, since the next call's model is not known ahead: the highest of 1.25 times the
input price (Anthropic's cache-write price), the cached input price and the output price.

If the day has too little left for a review of this size, the review is skipped and the summary says
the day's token budget is spent. If **Tokens per review** or the model's context window is too small
for the merge request, the summary says that instead ([Big merge requests](#big-merge-requests)).

Otherwise the review shares that amount between its stages: 55 % for the reviewers in equal parts,
35 % for the judge and 10 % for the second check. What a stage leaves passes on: a reviewer also
gets what the reviewers before it left, the judge what the reviewers left, the second check what
the judge left. A stage that overspends takes nothing from the others.

A stage that has used its tokens answers with what it has, and the summary says "The review reached
its token limit, so it may have missed problems." Qualor stops asking the model when it expects the
next answer not to fit, but cannot know an answer's length, so a review can end somewhat over its
limit. A stage also stops after reading code for 16 turns, whatever tokens are left, and the summary
says "A reviewer reached its limit of 16 turns, so it may have missed problems."

The day's budget is checked as each review starts. Reviews of the organisation already running count
as having spent what each may still spend, up to Tokens per review. So reviews running together
cannot overrun the day, and one that starts beside them may get less than the day had left.

### Answers to replies

An answer asks the day for room as a review does, with a ceiling of 60 000 tokens (input and output
of all its calls) in place of Tokens per review. It keeps to that as far as Qualor can tell ahead,
but each call may also use up to 16 000 tokens for thinking ([Room to think](#room-to-think)), so an
answer from a model that thinks can end somewhat over. A day with less room than the answer's first
call needs skips it. Qualor offers it again only when it next looks at the comments on a later UTC
day ([At once, or at the next analysis](#at-once-or-at-the-next-analysis)), and only while the note
is at most 30 days old.

### Room to think

A model that thinks counts its thinking in the output limit. So each review or reply call asks for
up to 16 000 output tokens beyond the answer's own limit, fewer when the window has less left beside
the input and the answer. They cost nothing unless used. Qualor plans a review with the answer's own
limit, so a call that thinks can spend that room beyond the plan, and the review can end further
over its limit. A model or server that refuses so large a limit is asked again without the room,
as [The current models](./ai-assistant.md#the-current-models) describes.

### Big merge requests

The reviewers' first message holds the list of changed files and the changed code. They read the
rest with their tools. At the default of 300 000 tokens per review:

- From about 80 changed files, the list leaves little room for code in that message: under 5 000
  characters, and under 1 000 from about 100 files.
- From about 105 changed files, the reviewers get shorter lists, with fewer files, fewer line ranges
  per file and fewer analyzer findings. That frees room for about 11 000 characters of code. The
  summary says "This merge request is large, so the reviewers were shown a shorter list of its
  changes and read the rest with their tools." The files left off are counted, and the reviewers
  read them with their tools.

Long paths, many line ranges per file and many analyzer findings lower these thresholds. At 600 000
tokens per review, a merge request with ordinary paths keeps the full lists at any number of files.

A merge request is skipped as too large only when **Tokens per review** cannot hold even the
shortest lists, below about 110 000 tokens. For big merge requests, raise **Tokens per review** (to
600 000, say) and check that the day's budget can pay for it.

Each call sends at most the model's context window less the room for its answer. Set **Context
window** in **Settings → AI provider** when the model takes less than 1 000 000 tokens. A reviewer
that fills the window answers with what it has. A merge request whose first message does not fit,
even with the shortest lists, is not reviewed.

The rules files keep up to 16 000 characters each, as long as the window has room for them. On a
window without that room, they share half of the room the window leaves for the first message, and
the code gets the other half. A short file stays whole, and the long ones are cut evenly. The model
is told how much of each was cut. Under 1 000 characters of a long file is no use, so a long file
is left out, and a short one stays whole. In both cases the summary says "The repository’s
instructions files were shortened to fit the model’s context window, so the review may not follow
all of them."
Raising **Tokens per review** does not change this. A window of 1 000 000 tokens is not affected. A
change that fits the window is reviewed whatever the size of its rules files.

### How tokens are counted

Tokens are what the provider reports. When a call reports no input count, Qualor counts a quarter of
the bytes sent, both in the review's ceiling and in today's figure. A missing output count is left
out of today's figure, so a provider that reports none shows too little. A call that was refused,
not taken or could not reach the provider is not counted. Cached input counts in full in every token
budget, and at the **Cached input** price in a cost budget: caching lowers the cost, never what a
token budget allows.

## Troubleshooting

### What the summary says

| The summary says | What it means, and what to do |
|---|---|
| AI review in progress… | The review waits for the snapshot (up to 15 minutes) or is running. |
| AI review did not run: no repository snapshot came for this commit. See the CI job’s log and the guide’s `fetch-depth` note. | No snapshot arrived within 15 minutes. Read the `AI review:` lines of the CI job's log ([The scan log](#the-scan-log)). The usual causes are a shallow clone, a pipeline that is not a merge request pipeline, and a secret scan that did not finish ([What your CI needs](#what-your-ci-needs)). No `AI review:` line at all means a scanner from before AI review, or a CI other than GitLab CI and GitHub Actions. A snapshot that arrives later starts the review. |
| AI review did not run: the server refused the repository snapshot of this commit. (`Reason: SNAPSHOT_INVALID`) | The server could not use the upload, or it was of another merge request. The server log says why. Run the job again, and report it if it repeats. |
| AI review is skipped while this merge request is a draft; the next pipeline after it is ready reviews it, and a `qualor review` note reviews it now. | Mark it ready and run the pipeline again, or write `qualor review` to review the draft now. The next push skips the draft again ([Commands](#commands)). |
| AI review did not run because this merge request is merged or closed. | Nothing to do. |
| AI review is switched off for this project. (`Reason: …`) | See [Why AI review is off for a project](#why-ai-review-is-off-for-a-project). |
| AI review found nothing to review in the changed files. | Not an error: only files the review leaves out changed ([What it reviews](#what-it-reviews)). |
| AI review did not repeat: the changes it reviews are the same as in its last review, whose findings stay open. | Not an error: the push changed nothing the review reads. |
| AI review did not run because its token budget for today is spent. | Wait for UTC midnight, or raise the budgets ([Budgets and today's usage](#budgets-and-todays-usage)). It also appears when the day has too little left for a merge request of this size. |
| AI review did not run because this merge request is too large for the Tokens per review budget; raise it in Settings → AI. | **Tokens per review** is below about 110 000, too little for even the shortest lists of changes. Raise it in **Budgets** ([Big merge requests](#big-merge-requests)). |
| AI review did not run because this merge request is too large for the model’s context window; raise Context window in the AI provider settings if the model takes more. | A reviewer's first message does not fit one call of the model. With the judge's 16 384 tokens of room for its answer, no window under about 26 600 tokens fits even a one-line change. A rules file such as `AGENTS.md` does not skip the review: it is shortened to fit, and the summary says so. Raise **Context window** in **Settings → AI provider** if the model takes more, or use a model with a larger window. Raising **Tokens per review** does not help. |
| AI review failed: the model provider returned an error or could not be reached. The next push reviews again. | A call was refused, timed out, was rate limited or got no answer. Qualor retries a rate-limited, timed-out or unavailable call twice, waiting the time the provider asks for, or else 5 s and then 30 s, never more than 60 s and never past the review's time. The server log's `AI review call finished` lines give each call's error code and HTTP status ([When the model provider fails](#when-the-model-provider-fails)). **Test again** in **Settings → AI provider** checks the provider. If the log has no such line for the review, no call was made: the stored API key no longer decrypts because `QUALOR_SECRET_KEY` changed (set the key again), or calls are paused after repeated failures (`PROVIDER_UNAVAILABLE`). |
| AI review failed: the model provider does not support the tool calls the review needs. The next push reviews again. | Use a model and server that can call tools. The Test says `cannot call tools, so AI review would fail` for this one ([Models that work](#models-that-work)). For OpenAI's newest models, choose **Responses** under **API** in **Connection options** and press **Save and test**: the line then says `can call tools`. |
| AI review failed because the model’s context window is too small for this merge request; raise Context window in the AI provider settings, or use a model with a larger window. | A call of the judge did not fit the context window. Either its first message, with the reviewers' and the earlier findings, did not fit even with their texts cut, or the judge had read code and a turn with the wrap-up beside it did not fit. The server log's `AI review run ended` line says `detail: window_full`. A push with as many findings fails again; one with fewer may pass. Raise **Context window** if the model takes more, or use a model with a larger window. |
| AI review failed because it ran out of time. The next push reviews again. | The judge had no answer when the review's time was up. A slow model, a provider that keeps asking Qualor to wait, or a very large merge request can cause it. The server log's `AI review run ended` line says `detail: time_limit`. For a slower model, the operator raises `QUALOR_AI_REVIEW_MAX_MINUTES`, up to 240 ([Snapshot limits and workers](#snapshot-limits-and-workers)). |
| AI review failed: the model’s answers could not be read. The next push reviews again. | The judge did not answer in the required form, even when asked again. Small models do this more often: try a stronger one. |
| AI review failed because of an error in Qualor. The next push reviews again. | An unexpected error, or a server stop during the review. If it repeats while the server runs, report it with the server log's `AI review run failed` line. |
| The review reached its token limit, so it may have missed problems. | A reviewer, the judge or the second check used its share ([How a review spends its tokens](#how-a-review-spends-its-tokens)). Raise **Tokens per review**, mainly for big merge requests. |
| A reviewer reached its limit of 16 turns, so it may have missed problems. | A reviewer, the judge or the second check read code for 16 turns, the fixed maximum, and answered with what it had. More tokens do not help. It is likelier in a big merge request. |
| The repository’s instructions files were shortened to fit the model’s context window, so the review may not follow all of them. | The model’s context window is small, and the rules files (`AGENTS.md`, `CLAUDE.md`, `REVIEW.md`) share half of the room it leaves for the first message. A long file is cut to fit, or left out when under 1 000 characters of it would remain. Raise **Context window** in **Settings → AI provider** if the model takes more, or use a model with a larger window. |
| The review reached its time limit, so it may have missed problems. | A reviewer, the judge or the second check ran out of the review's time. It answered with what it had, or did not run. The reviewers stop at 60 % of the time, so the judge can answer. More tokens do not help. For a slower model, the operator raises `QUALOR_AI_REVIEW_MAX_MINUTES` ([Snapshot limits and workers](#snapshot-limits-and-workers)). |
| A reviewer reached the model’s context window, so it may have missed problems. | A reviewer, the judge or the second check read as much code as one call holds, and answered with what it had. More tokens do not help. Raise **Context window** if the model takes more; a model with a larger window reads more. |
| A reviewer’s answer could not be read, so part of the review is missing. | One reviewer did not answer in the required form; the rest of the review is intact. Try a stronger model. |
| There were more serious security findings than the review verifies, so the rest were not checked a second time. | Not an error: the second check covers five findings. |
| The scanner left some files out of the repository snapshot to stay within its limits, so the review did not see all of them. | Raise the [snapshot limits](#snapshot-limits-and-workers). |

A failed or skipped review is not retried by itself. The next push, or a rerun of the CI job,
reviews again.

### Why a reply or a command was not answered

Nothing shows in the merge request when Qualor skips a note or fails on it, so start with the
server log. Each handled reply or command gets one `AI reply ended` line, with `replyId` (its
record), `status` (`done`, `skipped` or `failed`), `outcome` and `reason`. A record whose job was
lost for good (both tries failed, or died with their server) has no such line. Qualor ends it
`failed` with the reason `internal`, and the warning `ended AI replies whose job was lost` lists it
under `ended` by `replyId`, with its `outcome`. A note with neither line was never taken up:

| Symptom | What to check |
|---|---|
| A reply gets no answer, and the log has no `AI reply ended` line for it | The note must meet the conditions of [Replies](#replies): an open thread Qualor started on a finding, a person as author, written after the warning was confirmed and at most 30 days ago, in an open merge request. AI review must be on for the project ([Why AI review is off for a project](#why-ai-review-is-off-for-a-project)). Without a webhook the answer comes at the next analysis. |
| A command gets no answer | The first line of a top-level note must start with `qualor review`, `qualor fix` or `qualor stop`; on GitHub, in a comment on the pull request's page ([Commands](#commands)). AI review must be on for the project: without it, Qualor says nothing. The merge request needs an analysis by Qualor. Without a webhook the answer comes at the next analysis. |
| On GitHub, `qualor review` is answered only at the next analysis | GitHub does not send the `issue_comment` event: the App lacks the Issues permission or the event, or the installation's owner has not accepted the new permission ([GitHub](./github.md#update-an-app-you-created-before)). |
| On GitLab, replies and commands are answered only at the next analysis | The project has no webhook, its secret token differs (GitLab shows 401 under **Recent events**), **Comments** is not ticked, or GitLab cannot reach Qualor ([GitLab](./gitlab.md#answers-to-replies-and-commands-webhook)). |
| A reply in a busy thread is answered only the next day | The thread had its 5 rounds for the UTC day. The next round waits for a later UTC day, when Qualor next looks at the comments (a webhook delivery or an analysis), and reads every note written meanwhile. |
| A reply is answered, but the finding stays open | The author may not change a status ([Who may change a status](#who-may-change-a-status)). Or the thread is an analyzer's, or its finding is no longer open. Or the reply states no decision of priority and no claim the code bears out. Or the merge request had no snapshot, which a false positive needs. |
| A finding changed its status after a reply | A member wrote a decision of priority, or a claim the code bore out. The issue's **History** names the person, and anyone can set the status back. |

What `outcome` says, for a handled note (`status` `done`):

| `outcome` | What happened |
|---|---|
| `answered` | Qualor answered in the thread of an AI finding, and changed nothing |
| `acknowledged` | The model saw nothing to answer, such as a thank-you, so nothing was posted |
| `explained` | Qualor explained an analyzer's finding in its thread |
| `wont_fix` | The reply decided the finding's priority: it is marked won't fix, its thread is resolved, and the answer says so |
| `false_positive` | The code bore out the claim: the finding is marked false positive, and its thread is resolved |
| `review_requested` | `qualor review` started a review, and Qualor answered "Reviewing this commit" |
| `in_progress` | `qualor review` found a review of the commit waiting or running |
| `already_reviewed` | `qualor review` found the commit's review done, or the same as the last review |
| `not_available` | `qualor fix` or `qualor stop`, which do nothing yet, or a `qualor review` from someone who may not ask |
| `review_off` | `qualor review`, after AI review was switched off for the project |

A note that changed a status, or a command that started a review, keeps that outcome if it then
ends skipped or failed, for example because its thread was deleted before Qualor could answer. The
change happened, and the issue's **History** says so.

What `reason` says, for a note that was skipped or failed. Nothing is posted:

| `reason` | What it means, and what to do |
|---|---|
| `budget_spent` (skipped) | The day had no room for the answer. Qualor offers it again when it next looks at the comments on a later UTC day, while the note is at most 30 days old ([Answers to replies](#answers-to-replies)). To answer sooner, raise the budgets. |
| `inactive` (skipped) | AI review stopped covering the project while the note waited or the model decided: it was switched off, the project left the list or was unmapped, or the provider or one of its models changed and the confirmation is outdated ([Why AI review is off for a project](#why-ai-review-is-off-for-a-project)). |
| `closed` (skipped) | The merge request was merged or closed. Nothing to do. |
| `thread_gone` (skipped) | The thread or the command's note was deleted, someone resolved the thread before Qualor answered, or the project is no longer mapped to that provider. Nothing to do. |
| `superseded` (skipped) | A newer round in the same thread covers this one, and its answer reads these notes too. |
| `expired` (skipped) | The note waited over 30 days while its GitLab or GitHub connection or the model provider kept failing. Nothing to do: a new reply starts a new round. |
| `provider_error` (failed) | The model could not be asked or gave no answer ([When the model provider fails](#when-the-model-provider-fails)). The log has an `AI review reply call finished` line for each call, with its error code. While Qualor pauses calls to a failing provider, a reply does not fail: it waits for the pause to end (the log says `AI reply waits for the circuit of its model provider`). |
| `provider_no_tools` (failed) | The model's server refuses tool calls ([Models that work](#models-that-work)). For OpenAI's newest models, choose **Responses** under **API** in the **Connection options** of **Settings → AI provider**. |
| `bad_answer` (failed) | The model's answer could not be read, or named a status the thread does not allow, even after a second try. Nothing is posted, on purpose. A stronger model fails less often. |
| `internal` (failed) | An unexpected error in Qualor, or something that cannot be answered: the SCM connection can no longer be used (its token no longer decrypts after `QUALOR_SECRET_KEY` changed, or its address is no longer allowed), the issue is no longer the project's, or the merge request has no analysis to review. The log's `AI reply not answered:` or `AI reply failed on its last try` line says which. A record whose job was lost is in the `ended` list of the warning `ended AI replies whose job was lost` instead. |

A skipped or failed note is not tried again, except for `budget_spent`. A later reply in the same
thread starts a new round that reads the earlier notes too.

### When the model provider fails

Each call of a review that failed with a provider error has an `AI review call finished` line in the
server log, with its status and, if it failed, its error code:

| Error code in the log | What to do |
|---|---|
| `PROVIDER_TIMEOUT` | The model sent nothing for as long as a call waits, or the call went past 15 minutes (**Allow time** in [Models that work](#models-that-work)). A slow local model may need more: raise the **Timeout** in the **Connection options** of **Settings → AI provider**, up to 600 seconds. |
| `PROVIDER_RATE_LIMITED` | The provider's own limit. Qualor waited as the provider asked and tried twice. Review again later, or lower the budgets. |
| `PROVIDER_REFUSED_KEY` | Set a valid API key, and check the key header (`api-key` for Azure). |
| `PROVIDER_REJECTED_REQUEST` | The provider refused the request: check the base URL, the model's name and the output limit parameter ([AI assistant: Troubleshooting](./ai-assistant.md#troubleshooting)). |
| `PROVIDER_BAD_ANSWER` | The answer was not in a form Qualor could read: the address is not a Chat Completions, Responses or Anthropic Messages API, or the answer was over 1 MiB. Check the base URL and the **API** setting ([AI assistant: Troubleshooting](./ai-assistant.md#troubleshooting)). |
| `PROVIDER_WORKSPACE_REQUIRED` | An organisation-wide Anthropic key is not scoped to a workspace. Enter its workspace ID (`wrkspc_…`) in **Settings → AI provider**. The call is not retried. |
| `URL_NOT_ALLOWED` | The provider's address is no longer allowed. The operator lists its host and port in `QUALOR_LLM_INTERNAL_HOSTS`, or the instance admin uses an `https` address that resolves to public addresses ([AI assistant: Troubleshooting](./ai-assistant.md#troubleshooting)). |
| `PROVIDER_UNAVAILABLE` | The provider could not be reached, answered with a server error, or closed the connection mid-answer (a stream that ended early). Check the base URL and the network. After five AI review calls in a row fail, Qualor pauses AI review calls to that address for 10 minutes. A review that starts then fails at once, with no call in the log, and an answer to a reply waits for the pause to end. Explain, Suggest triage and Suggest a fix keep their own count. |

### The scan log

Every scan log line about the snapshot starts with `AI review: `, left out below. The table lists
the messages that call for action. Other lines say what the snapshot holds and masks;
`QUALOR_LOG_LEVEL=debug` shows more.

| Message in the scan log | What it means, and what to do |
|---|---|
| `AI review is off for this project (<reason>), so no repository snapshot is sent` | Not an error. See [Why AI review is off for a project](#why-ai-review-is-off-for-a-project). |
| `no snapshot sent, the secret scan (<engines>) did not complete` | An engine that is on and had something to run did not finish, or rule files you named in `analyzers.semgrep.configs` never ran. Fix the path or the tool, or switch the engine off with `enabled: false` ([When the secret scan stops the snapshot](#when-the-secret-scan-stops-the-snapshot)). An engine with nothing to run, such as Semgrep on its defaults, does not cause it. |
| `no snapshot sent, the secret scan's output could not be read` | Run the scan again. If it repeats, read the debug log. |
| `no snapshot sent, the merge request's head commit <sha> is not in the clone and could not be fetched` | Give the job the full history, or check out the pull request's head ([What your CI needs](#what-your-ci-needs)). |
| `… is not in the clone (scm.autoFetch is false)` | Allow the fetch (`scm.autoFetch: true`), or give the clone the commit. |
| `no snapshot sent, the merge request's head commit is unknown (…)` | The CI did not name the commit: run in merge request pipelines on GitLab, on the `pull_request` event on GitHub. |
| `no snapshot sent, the merge request's head and origin/<target> have no common commit in this clone` | The clone lacks the history: `GIT_DEPTH: 0` or `fetch-depth: 0`. |
| `no snapshot sent, the merge request's changes alone are over the server's snapshot limits` | The merge request is very large. The operator can raise the [limits](#snapshot-limits-and-workers). |
| `no snapshot sent, the head files that differ from the scanned checkout could not be scanned` | Gitleaks failed on them. Run the scan again, or rebase the merge request if the target branch changed a file your Gitleaks configuration extends, or read the debug log. |
| `no snapshot sent, --mr and --mr-target name another merge request …` | Pass `--mr` and `--mr-target` only for the merge request CI runs for. |
| `no snapshot sent, the server refused it (409 AI_REVIEW_OFF …)` | AI review was switched off, or the provider changed, while the job ran. |
| `… (413 SNAPSHOT_TOO_LARGE …)` | Over the limits. Raise them, and the proxy's body limit. |
| `… (409 SNAPSHOT_EXISTS …)` | The analysis already has a snapshot. |
| `the merge base's files could not be scanned for secrets (…), so the snapshot sends none of the lines the merge request removes` | Gitleaks could not run over the target branch's versions. The snapshot is sent without removed lines. |
| `the secret scan is off in qualor.yml; only built-in patterns mask secrets in the snapshot` | You switched Gitleaks off ([When the secret scan stops the snapshot](#when-the-secret-scan-stops-the-snapshot)). |
| `N paths left out of the repository snapshot, which cannot hold them safely` | A warning: the snapshot is sent without those paths, whose names are very long, hold characters a snapshot path may not have, or hold a secret. |
| `N files are not in the clone's objects and were left out of the snapshot` | A partial clone lacks those files. Fetch the objects, or use a full clone. |
| `the server could not be asked whether it reviews (…), so no repository snapshot is sent` | The scanner could not reach the server's review route (network, proxy or certificate). The report is uploaded; there is no snapshot this time. |
| `the server did not say whether it reviews (…), so no repository snapshot is sent` | The server answered with an error, such as 403 for a token that cannot upload. The text names it. |
| `the merge request's diff could not be read, so the snapshot has no patches: …` | git failed to produce the diff. The snapshot is sent without diffs. |
| `no snapshot sent: <error>` | A git, disk or network failure while the snapshot was built or sent. The text says which, with any secret masked. |
| `building the repository snapshot took longer than 10 minutes, so none is sent` | Usually a stalled fetch, or a very large repository on a slow runner. Give the job the full history so nothing is fetched, or more CPU. This push is not reviewed; the next one sends a snapshot again. |
| `the server is busy with other uploads; retrying the snapshot` | The upload slots are taken, and the scanner retries. The operator can raise `QUALOR_MAX_CONCURRENT_UPLOADS`. |

### Why AI review is off for a project

| Reason | Fix |
|---|---|
| `no_provider` | An instance admin connects a provider in **Settings → AI provider**. |
| `organization_disabled` | An instance admin allows the organisation to use AI there, under **Organizations**. |
| `review_disabled` | An organisation admin presses **Switch on AI review…** in **Settings → AI**. |
| `consent_outdated` | The provider, or one of its models (a strong or a fast model counts), changed. An organisation admin presses **Review and confirm…** in **Settings → AI**. |
| `project_not_selected` | Add the project to **Projects to review** in **Settings → AI**. A project the instance admin excluded from AI is never reviewed. |
| `not_mapped` | Map the project to its GitLab or GitHub repository ([GitLab](./gitlab.md), [GitHub](./github.md)). |
| `provider_changed` | The instance admin changed the provider, or one of its models, while a review was running, and the confirmation covers the new setup. The review stopped, and the next push is reviewed with the new provider. |

## API

The settings page uses these endpoints, so you can script the same steps:

| Endpoint | Who | What it does |
|---|---|---|
| `GET /api/v0/organizations/{id}/ai/review` | organisation admins | Returns the settings, the warning (`notice`), `consentCurrent` and the instance ceiling (`instanceCeiling.tokensPerDay`). `provider` has `host`, `model` and `models` (every model it uses, once each, sorted). `usage` is today's use: `tokensToday`, `reviewsToday` and `costTodayUsd`, `null` while no prices are set. `providerTest` comes from the instance admin's last Test: `toolCalling` (`supported`, `not_supported` or `unknown`), `modelsWithoutTools` (the models that did not call the tool) and `at` (when it ran). |
| `PUT /api/v0/organizations/{id}/ai/review` | organisation admins | Sets `enabled`, `scope` (`all` or `selected`), `projectIds` and `budgets`, and answers like the `GET`. To switch AI review on, or confirm again, add `acknowledgeDataSharing: { host, model, models }`, copied from the `provider` of the `GET` answer. |
| `GET /api/v0/issues?branchId=…&engine=ai` | | Lists AI findings, the issues of the engine `ai`. |
| `GET /api/v0/issues/{id}` | | Gives a finding's `aiReview`: `category`, `body`, `assumption`, `verification`, `suggestion` and `reviewedCommit`. It is `null` for other issues. |
| `POST /api/v0/system/llm/test` | instance admins | Tests every model of the provider at once. For the standard model it answers `toolCalling` (`supported`, `not_supported` or `not_checked`) and `hint` (`null`, or an object with the `code` `USE_RESPONSES_API` and a `message`). `models` has one entry per model: `tier`, `model`, `ok`, `reportedModel`, `latencyMs`, `toolCalling`, `problem` and `hint`. |
| `GET /api/v0/system/llm` | instance admins | `lastTest` is the last Test's outcome, kept until the provider's settings or key change: `at`, `userId`, and per model `tier`, `model`, `ok`, `toolCalling` and `problemCode`. It is `null` without a Test of the provider as it is now. `reviewStatus` says, per organisation, whether its admins switched AI review on (`enabled`) and whether their confirmation covers the provider as it is now (`consentCurrent`). Both are read-only: a `PUT` that sends them back is accepted and ignores them, so the confirmation stays the organisation admins'. |
| `GET /api/v0/projects`, `GET /api/v0/projects/{id}` | | A project's `aiReview.reason` says why AI review does not run for it: the first that applies of `no_provider`, `organization_disabled`, `review_disabled`, `consent_outdated`, `project_not_selected` and `not_mapped`, or `null` while it runs ([Why AI review is off for a project](#why-ai-review-is-off-for-a-project)). `enabled` and `organizationEnabled` keep their meaning: `enabled` is true for a chosen project whatever its repository mapping. |
| `GET /api/v0/projects/review-context`, `POST /api/v0/analyses/{id}/review-snapshot` | the scanner, with the project's analysis token | Asks whether to send a snapshot, and its limits, then uploads it. Errors: `AI_REVIEW_OFF`, `SNAPSHOT_EXISTS`, `SNAPSHOT_TOO_LARGE`, `SNAPSHOT_INVALID` and `ANALYSIS_NOT_FOUND`. |

Errors of the settings endpoints:

| Error | Status | When |
|---|---|---|
| `AI_DISABLED` | 409 | no provider, or the organisation may not use AI |
| `AI_REVIEW_CONSENT_REQUIRED` | 409 | switching on without the acknowledgement |
| `AI_REVIEW_PROVIDER_CHANGED` | 409 | the provider's host, model or set of models changed since you read the warning. Nothing is stored: read the `GET` answer again |
| `PROJECT_NOT_IN_ORGANIZATION` | 422 | a project of another organisation |
