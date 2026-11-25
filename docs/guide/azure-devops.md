# Azure DevOps

Qualor connects to Azure DevOps Services (`dev.azure.com`) and Azure DevOps Server 2022 or later.
An organisation administrator adds a connection, tests it and maps each Qualor project to a
repository. A project admin can also map the project to [Azure Boards](#azure-boards), so that
findings become work items.

## Before you start

- An organisation administrator account in Qualor.
- To use a service principal: Owner or administrator rights in the Azure DevOps organisation, to add
  it under **Organization settings → Users** with the **Basic** access level. Any user may create a
  personal access token.
- For Azure DevOps Server on your network: its host and port in `QUALOR_SCM_INTERNAL_HOSTS`
  ([Server settings](./install-server.md#server-settings)).

## Connect

Open **Settings → Azure DevOps** and press **New connection**.

| Field | Value |
|---|---|
| Address | Services: `https://dev.azure.com/<organization>` or `https://<organization>.visualstudio.com`. Server: the collection URL, such as `https://ado.example.com/DefaultCollection` |
| Authentication | A service principal with a client secret, a service principal with a certificate, or a personal access token |
| Directory (tenant) id | A service principal only: the tenant of the Microsoft Entra app |
| Application (client) id | A service principal only: the app's client id |
| Client secret, or certificate and private key (PEM), or personal access token | The credential |

| Deployment | Authentication |
|---|---|
| Azure DevOps Services | Service principal or personal access token |
| Azure DevOps Server | Personal access token |

Qualor stores the credential encrypted and never shows it again. Changing the address, the
authentication or an id needs the credential again.

### A service principal

A service principal does not depend on a person's account. Set it up in three steps:

1. In Microsoft Entra, register an app. Note its **Directory (tenant) id** and **Application
   (client) id**.
2. Under **Certificates & secrets**, create a client secret, or upload a certificate.
3. In Azure DevOps, open **Organization settings → Users** and add the app's service principal with
   the **Basic** access level. Add it to each project whose repositories Qualor should see.

The organisation must be connected to the same Microsoft Entra tenant.

A certificate is one PEM text with the certificate and its private key. The key must be unencrypted
and RSA, at least 2048 bits, and must belong to the certificate. The text is at most 16 KiB. You can
paste it or choose the file. Qualor shows the certificate's expiry date and warns before it
expires. An expired certificate fails the test.

Qualor gets a token for the service principal from Microsoft Entra (`login.microsoftonline.com`),
from the server only.

### A personal access token

Create the token in Azure DevOps under **User settings → Personal access tokens**. The scope
**Code: Read** is enough for the test. For
[comments and status on pull requests](#comments-and-status-on-pull-requests) the token needs
**Code: Read & write**. Replies and commands need more: see
[the identity's permissions](#the-identitys-permissions). It sees what its owner sees, and it stops
working when it expires or its owner loses access.

If Azure DevOps Server's certificate comes from a private CA, give the server that CA with
`NODE_EXTRA_CA_CERTS`.

## Test the connection

Press **Test** on the connection. A passing test shows who connected and how much that identity
sees:

> Connected as Qualor; 12 repositories in 3 projects visible.

With a mapped repository, a passing test can add that the identity cannot read who may change
findings. Fix it as [the identity's permissions](#the-identitys-permissions) say.

With an [Azure Boards](#azure-boards) mapping, a passing test can add that the identity may not
create work items. Fix it as [What Boards needs](#what-boards-needs) says.

A failing test shows one of these:

| Message | Meaning and fix |
|---|---|
| The stored credential can no longer be read | The server key changed. Set the credential again |
| The server no longer allows this Azure DevOps address, or this Azure DevOps Server is on an internal address | The operator lists the host and port in `QUALOR_SCM_INTERNAL_HOSTS` |
| The Azure DevOps host name could not be found, did not answer in time, or could not be reached | Check the address and the network from the server |
| Azure DevOps refused the credential | The credential is wrong, expired, or may not read the organisation |
| The identity is not a member of this Azure DevOps organization or has no access level | Add the service principal under **Organization settings → Users** with the **Basic** access level |
| Azure DevOps answered with a web page instead of data | Check the credential and the address |
| Microsoft Entra refused the service principal | Check the tenant id, the client id and the secret or certificate |
| The certificate expired on a date | Upload a new certificate |
| Microsoft Entra could not be reached | Check that the server can reach `login.microsoftonline.com` |
| Microsoft Entra did not answer in time | Check that the server can reach `login.microsoftonline.com` |
| Microsoft Entra answered with an error | Try again later; if it persists, check that the server can reach `login.microsoftonline.com` |
| The credential lacks a permission in Azure DevOps | Give it read access to Code |

A service principal sees only the projects it was added to. A test that connects but finds no
repositories means it has no project yet.

## Map a repository

Open **Settings → Repositories**. For each project, pick the Azure DevOps connection, then choose
the repository from the list. Its entries read `Project / Repository`. Type in the search field to
narrow a long list, and press **Save**.

A repository is stored by its id, so a rename in Azure DevOps keeps the mapping.

## Add repositories and set up CI

**Add repositories** (in **Projects**, [Quick start](./quick-start.md#fastest-path-add-repositories))
creates a project for each repository you tick and can set up CI for it. Qualor opens a pull
request. Your pipelines on the main branch don't change until you merge it. The pipeline and its
secret variable are created right away. The first analysis runs on the main branch once the pull
request is merged. Pull requests are analysed after that, through the Build validation policy.

Each repository shows as `Project / Repository`. The project key is `<project>/<repository>`, with
every character outside `A-Z a-z 0-9 . _ / : -` replaced by `-`. The project's name keeps the
original characters.

### Turn it on

Press the switch **Allow Qualor to set up CI (opens pull requests, creates pipelines and
policies)** on the connection, in **Settings → Azure DevOps**. It is off until you press it. The
server also needs `QUALOR_PUBLIC_URL` ([Server settings](./install-server.md#server-settings)).
Without either, **Add repositories** still creates the projects and shows the snippet and the token.

### What Qualor does

| Step | What Qualor does |
|---|---|
| 1 | Pushes the branch `qualor/setup` with one new file, `.azure-pipelines/qualor.yml`. It is the [docker pipeline](#pick-a-pipeline) without an extension, with the project key in its `variables:` and the scanner image pinned to the server's version |
| 2 | Creates the pipeline `Qualor` in the folder `\` (`Qualor (<repository>)` when the project already has a pipeline of that name), pointing at that file. It has the variable `QUALOR_URL` and the secret variable `QUALOR_TOKEN`, a project analysis token named **CI setup**. The token is never in the pull request |
| 3 | Lets the pipeline use its agent pool |
| 4 | Opens the pull request **Add Qualor code analysis**. Its description lists everything Qualor did outside the pull request |
| 5 | After the pull request is merged and the first analysis of the main branch has arrived, adds a Build validation policy `Qualor` on the default branch |

The policy does not block anyone: pull requests are analysed, and a failed analysis does not stop
the merge. To block on the gate, see [Block the merge on the gate](#block-the-merge-on-the-gate).

### The agent pool

Name the pool in the field **Agent pool** of **Add repositories**. On Azure DevOps Services you may
leave it empty: the pipeline then runs on the Microsoft-hosted pool **Azure Pipelines**, with the
image `ubuntu-latest`. On Azure DevOps Server the field is required, because it has no
Microsoft-hosted agents. The pool's agents need Linux and Docker.

A Microsoft-hosted pool is open to all pipelines, so step 3 needs nothing there. For a self-hosted
pool Qualor authorises the pipeline. When its identity may not, the result names the approval you
make by hand: Azure DevOps asks for it before the first run.

### The pull request check

The result of the setup shows the state of the policy.

| State | Meaning |
|---|---|
| Waiting | The check starts after the first analysis of the main branch |
| On | The policy `Qualor` exists |
| Manual step | Qualor did not add the policy. Add or enable the Build validation policy on the main branch yourself. The identity lacks **Edit policies**, or a disabled policy for the pipeline exists |
| Failed | Qualor could not add the policy. Add it yourself |

### What the identity needs

When Azure DevOps refuses a step, the result names the rights that step needs. A Project
Administrator can do every step. The minimal role set for a service principal is the **Basic**
access level and **Contributors**, plus **Edit policies**. Whether Contributors alone are enough is
not checked yet.

| Step | Right |
|---|---|
| Push the branch | **Contribute** and **Create branch** on the repository |
| Open the pull request | **Contribute to pull requests** on the repository |
| Create the pipeline and its secret | **Edit build pipeline** in the project |
| Find the agent pool | Read access to the project's agent pools |
| Authorise the pipeline on a self-hosted pool | The **Administrator** role on the pool: **Project settings → Agent pools**, the pool, **Security**. Otherwise a manual step |
| Add the policy | **Edit policies** on the repository. Otherwise a manual step |

A personal access token also needs the matching scopes. The PAT scopes are not verified yet. The
fix rights are in [the fix table](./fix-merge-requests.md#turning-it-on).

### When Qualor writes nothing

Qualor shows the snippet and the manual steps instead of opening a pull request when the repository
is empty, or when a pipeline that Qualor did not create already uses
`.azure-pipelines/qualor.yml`. It never overwrites a pipeline or a variable. In that case it makes
no token. Rename that pipeline's file or delete the pipeline, or copy the job into a file of your
own.

### Undo CI setup

1. Close the pull request and delete the branch `qualor/setup`. Only the identity that pushed it
   may delete it without **Force push** on the repository. Contributors lack **Force push** by
   default.
2. Delete the pipeline `Qualor` (or `Qualor (<repository>)`).
3. Delete the Build validation policy `Qualor` on the default branch, if it exists.
4. In Qualor, revoke the project's **CI setup** token in the project's token settings.

## Run the scanner in Azure Pipelines

A pipeline runs the scanner on Linux agents with Docker and uploads the report to your Qualor
server. Pipelines on Azure Repos are detected: Qualor reads the branch, the tag, the pull request
and its target, and the commit from the agent's variables.

### Variables

Set both under **Pipelines → Edit → Variables**.

| Variable | Value |
|---|---|
| `QUALOR_URL` | The address of your Qualor server |
| `QUALOR_TOKEN` | The project's analysis token, marked as a secret |

### Pick a pipeline

Copy one file to `azure-pipelines.yml`.

| File | Use it for |
|---|---|
| [`integrations/azure-devops/qualor.yml`](../../integrations/azure-devops/qualor.yml) | Any language but C#, with the `Qualor@0` task |
| [`integrations/azure-devops/qualor-docker.yml`](../../integrations/azure-devops/qualor-docker.yml) | The same, with `docker run` and no extension |
| [`integrations/azure-devops/qualor-dotnet.yml`](../../integrations/azure-devops/qualor-dotnet.yml) | C#, with the `Qualor@0` task |
| [`integrations/azure-devops/qualor-dotnet-docker.yml`](../../integrations/azure-devops/qualor-dotnet-docker.yml) | C#, with `docker run` and no extension |

The `Qualor@0` task needs the Qualor extension.

| Deployment | How to get the extension |
|---|---|
| Azure DevOps Server | Upload the extension's VSIX file, from the release page, under **Collection settings → Extensions** (the local gallery) |
| Azure DevOps Services | Only the Marketplace installs an extension: use the `docker run` examples until the extension's Marketplace listing is public |

| Task input | Meaning |
|---|---|
| `dotnet` | `true` analyses C# with the MSBuild integration |
| `dotnetBuild` | The build command for C#. Default: `dotnet build --no-incremental` |
| `imageTag` | The tag of `qualor/scanner` and `qualor/scanner-dotnet`. Default: the extension's version |
| `arguments` | Extra arguments for `qualor scan`, and for `qualor dotnet end` with `dotnet: true`. Never put a token or password here: the task logs its command line |

The extension updates itself on Azure DevOps Services. Set `imageTag` to your Qualor server's release line.

The checkout step needs `fetchDepth: 0`. In a pull request build the task fails with that hint on a shallow clone. Branch builds deepen the clone themselves.

### Cache the vulnerability database

On Azure DevOps Services, a cache step before the scan keeps the vulnerability database between
builds. Add it after the checkout. The key holds the build id, so every build saves a new entry, and
`restoreKeys` restores the latest one:

```yaml
  - script: mkdir -p "$(Build.SourcesDirectory)/.qualor/trivy"
    displayName: Create the cache directory
  - task: Cache@2
    inputs:
      key: 'qualor-trivy | "$(Build.BuildId)"'
      restoreKeys: qualor-trivy
      path: $(Build.SourcesDirectory)/.qualor/trivy
```

Azure DevOps Server has no pipeline caching: leave the step out there.

### Pull requests

Azure Repos ignores `pr:` in the YAML. Add the pipeline as a Build validation policy under
**Repos → Branches → Branch policies** of the target branch.

The task checks out the pull request's head, not Azure's merge commit. A pipeline that skips this
checkout still uploads, but Qualor then posts no inline threads
([details](#comments-and-status-on-pull-requests)).

### The default branch

Qualor does not detect the default branch on Azure Pipelines. When it is not `main`, set it in
`qualor.yml`:

```yaml
scm:
  mainBranch: develop
```

### C#

With `dotnet: true` the build runs inside the `qualor/scanner-dotnet` container. Two things follow.

- The build sees `.git` read-only. A tool that writes into `.git`, such as GitVersion, must run in
  an earlier step.
- The container has no Azure Artifacts credential provider and no `VSS_NUGET_*` variables, so the
  build restores only from feeds it can reach without them. For a private feed, use the docker
  example and give the build step the feed's credentials yourself, for example in an `-e` variable
  that your `nuget.config` reads.

## Comments and status on pull requests

Qualor reports each analysis of a pull request in Azure DevOps. The connection and the repository
mapping are enough.

| What | Where |
|---|---|
| A status `qualor/<project key>` | On the pull request, on the iteration that was analysed. `succeeded` when the gate passes or the project has no gate, `failed` otherwise |
| A summary | One closed thread, edited in place on each analysis |
| A thread on each new issue | On a line the pull request added, at most 50 |
| A commit status of the same name | On each analysed branch. It is informational: a commit status does not satisfy a branch policy |

### Block the merge on the gate

Under **Repos → Branches → Branch policies** of the target branch, add a **Status check**:

| Field | Value |
|---|---|
| Status to check | `qualor/<project key>` |
| Authorized identity | Qualor's identity: the connection's service principal, or the owner of its personal access token |
| Reset conditions | **Reset status whenever there are new changes** |

Set the authorized identity. Without it, anyone who may contribute to the pull request can post a
passing status of that name, the pull request's own pipeline included.

### The identity's permissions

Give Qualor's identity **Contribute to pull requests** on the repository. A personal access token
also needs the right [scope](#a-personal-access-token). Without the permission, Azure DevOps refuses
the status, the threads and the summary, so none of them appears. **Settings → Azure DevOps** then
shows the problem.

[Replies and commands](#ai-review-replies-and-commands) need two more reads. Qualor looks up each
commenter on the identities host, and reads the repository's permissions. Members of **Project
Administrators** may read both. Whether a Contributor alone may, and which personal access token
scopes are enough, is not verified yet.

If `qualor review` is refused for everyone, the identity cannot read permissions. **Test** then
says that it cannot read who may change findings. Add the identity to **Project Administrators** in
that project.

The service hooks need **Edit subscriptions**
([Let Qualor subscribe](#let-qualor-subscribe)).

### Fix pull requests

Qualor can open [fix pull requests](./fix-merge-requests.md) that bump a vulnerable dependency.
Press the switch **Allow fix pull requests** on the connection in **Settings → Azure DevOps**. It is
off, also for connections that existed before. The pull requests show as **PR !12**.

Grant the identity the rights [the token table](./fix-merge-requests.md#turning-it-on) lists in the
repository's **Security** settings.

The [fix job](./fix-merge-requests.md#azure-pipelines) runs in a pipeline of the main branch.

### Threads

- Inline threads need the pipeline to check out the pull request's head. The Qualor task and the
  head checkout of the examples do. Otherwise the summary says why there are none.
- Qualor resolves its thread with a comment when the issue is no longer open, and reopens it if the
  issue returns.
- Qualor never reopens a thread a person resolved.
- When someone replied in a thread, Qualor leaves it open and adds a note that the issue is fixed.

### When Azure DevOps refuses Qualor

When a problem of the connection stops the status or the comments, **Settings → Azure DevOps**
shows it and since when. Such a problem is a refused credential, a missing permission, a stored
credential that can no longer be read, or an address the server no longer allows.

The messages and fixes are those of a [failing test](#test-the-connection), with one exception. A
missing permission there means **Contribute to pull requests** on the repository, and for a personal
access token also **Code: Read & write**.

A passing **Test**, or the next decoration that succeeds, clears such a problem. A hook problem
clears differently: see [the states](#the-states).

## AI review, replies and commands

[AI review](./ai-review.md) works on Azure DevOps pull requests. It needs the connection, the
repository mapping and a pipeline that uploads the scan.

- AI threads are posted whatever the pipeline checked out.
- A thread carries an **Apply** suggestion when the fix replaces up to 15 added lines, or deletes them.
- Qualor reads replies in its open threads: **Active** or **Pending**.
- A command is the first comment of a new thread, and Qualor answers in that thread.
- An [AI fix suggestion](./ai-assistant.md#posting-a-fix) is posted as a thread with **Apply**, for
  whole lines: one line, several lines, or a deletion.

[AI review](./ai-review.md#replies-and-commands) has the rest, including
[who may change a status](./ai-review.md#who-may-change-a-status).

To look up who wrote a comment, Qualor asks the Azure DevOps identities host, from the server only.
Allow it in a firewall: `vssps.dev.azure.com` for `https://dev.azure.com/<organization>`, and
`<organization>.vssps.visualstudio.com` for `https://<organization>.visualstudio.com`. Azure DevOps
Server needs no extra host.

## Service hooks

With service hooks, Azure DevOps tells Qualor at once that someone commented. Without them, Qualor
reads replies and commands every 15 minutes, in the 50 most recently analysed AI-reviewed pull
requests. Open **Settings → Azure DevOps** and find **Service hooks** under the connection.

Qualor needs `QUALOR_PUBLIC_URL` set to an `https` address. Azure DevOps sends the hooks' password
only there. Without one, **Create or update Qualor's subscriptions** is disabled and says why.

### Let Qualor subscribe

Press **Create or update Qualor's subscriptions**. Qualor makes two subscriptions in each Azure
DevOps project that holds a mapped repository. The identity needs **Edit subscriptions** in that
project, which Project Administrators have by default.

A personal access token may not be allowed to create subscriptions. If the button is refused, use a
[service principal](#a-service-principal) or subscribe by hand.

### Subscribe by hand

1. Press **Show a new password**. Qualor shows the URL, the user `qualor` and the password once.
2. In Azure DevOps, open **Project settings → Service hooks** and add a **Web Hooks** subscription
   for **Pull request commented on** (`ms.vss-code.git-pullrequest-comment-event`).
3. Add a second one for **Pull request updated** (`git.pullrequest.updated`).
4. In both, enter the URL, choose basic authentication, and enter the user and the password.

A new password replaces the old one. Azure DevOps keeps the old one until you subscribe again, and
Qualor refuses its deliveries until then. While the hooks work, Qualor asks before it makes a new
password.

### The states

**Test** shows each project's state.

| State | Meaning |
|---|---|
| Active | Both subscriptions work |
| On probation | Azure DevOps is retrying failed deliveries and may skip events |
| Switched off in Azure DevOps | A person or Azure DevOps disabled one |
| Not subscribed | A subscription of Qualor's is missing |
| Older password | Azure DevOps may hold another password than Qualor. It clears with the first delivery that brings Qualor's password, or when you press **Create or update Qualor's subscriptions** |

Probation and switched-off hooks also show as a problem on **Settings → Azure DevOps**. Replies are
still read every 15 minutes. Press **Create or update Qualor's subscriptions** to fix them.

Qualor checks the subscriptions every 15 minutes. The problem clears when that check finds them
active, or finds none to check. Changing the connection's address clears it too.

### Change or delete a connection

Changing the connection's address clears the password. Subscribe again afterwards.

Deleting a connection leaves its subscriptions in Azure DevOps. Remove them under **Project
settings → Service hooks**.

## Azure Boards

Qualor turns a code issue or a dependency vulnerability into an Azure Boards work item with one
click, or by itself for new vulnerabilities. It shows the work item's id and state next to the
finding. When Qualor stops finding the problem, it adds a note to the work item's discussion.

Azure Boards is in every edition. It uses the organisation's Azure DevOps connection: there is
nothing more to connect. A project admin maps each project to an Azure DevOps project. Everyone who
may triage issues creates work items.

### What Boards needs

- An [Azure DevOps connection](#connect) in the organisation.
- For a personal access token, the scope **Work Items: Read & write** (`vso.work_write`).
- For the identity, the **Basic** access level and **Edit work items in this node** on the area
  path the project maps. Azure DevOps does not let Stakeholder access create new tags, such as
  `qualor`.
- `QUALOR_PUBLIC_URL` on the server. Without it work items carry no link back to Qualor
  ([Server settings](./install-server.md#server-settings)).

**Save** in the project's panel and **Test** on the connection both check the right to create work
items.

### Map a project to Azure Boards

A **project admin** opens **Project → Settings → Azure Boards**. The panel shows when the
organisation has an Azure DevOps connection. Without one, an org admin sees a link to **Settings →
Azure DevOps**.

| Field | Meaning |
|---|---|
| **Connection** | shown with more than one Azure DevOps connection. The default is the project's repository connection, else the first |
| **Azure DevOps project** | the projects the connection sees. It may differ from the repository's project |
| **Work item type** | the type Qualor creates, such as Issue or Bug ([Which work item types work](#which-work-item-types-work)) |
| **Area path**, **Iteration path** | **Project root** by default, or a path the project lists |
| **Tags** | up to 10 extra tags, each 1 to 100 characters, without `;` or `,`. Qualor always adds `qualor` |
| **Create work items for new vulnerabilities** | [the automatic rule](#the-automatic-rule), off by default |

**Save** asks Azure DevOps to check a test work item with these settings, without making it. A
missing right, a required field or a rule then stops the save. For a refused field or rule, the
panel shows Azure DevOps's own words.

**Remove mapping** stops new work items for the project. Existing work items stay in Azure Boards,
and Qualor keeps reading their state and adding notes. Mapping the project to another Azure DevOps
project later changes only the new work items.

### Which work item types work

Qualor offers a type when it can fill every field the type requires. It fills the title, the
description, the tags, the area path and the iteration path. A required field with a default, such
as State or Value Area, is no problem. A type with another required field is listed disabled, with
the reference names of the fields it needs: "Defect — Needs: Custom.Team". Choose another type, or
ask the process administrator to make those fields optional or give them a default.

The description also goes into **Repro Steps** whenever the type has that field:

| Process | Type | The description goes into |
|---|---|---|
| Basic | Issue | **Description** |
| Agile, Scrum | Bug | **Description** and **Repro Steps**. The Bug form shows only Repro Steps |

Hidden types, such as Test Plan or Shared Steps, are not offered.

Qualor stores the type by its reference name, so a renamed type keeps working. **Save** checks the
type again. A type that is removed or gains a required field later makes new work items fail: map
the project again.

### Create work items

Qualor makes one work item per finding. The findings that qualify are those of
[Jira](./jira.md#create-jira-issues): a code issue on the main branch, and a vulnerability once per
project, package and vulnerability. A closed finding shows no button.

| Where | How |
|---|---|
| The issue page | the **Azure Boards** card, **Create work item** |
| The **Issues** tab | select rows and **Create Azure Boards work items**: at most 500 issues. A row with a work item shows a pill with its id and state |
| The **Vulnerabilities** tab | **Create work item** on a row, or tick rows and **Create Azure Boards work items**: at most 100 vulnerabilities |

A bulk request ends with a line such as "12 work items queued, 3 already linked, 1 not linkable".
Creation runs in the background. Each new work item counts against the same per-user limit as
status changes: 120 a minute, with a burst of 500.

The issue page's **Azure Boards** card and a Vulnerabilities row offer the same actions:

| State | What you see | What you can do |
|---|---|---|
| Waiting | **Creating…** | wait |
| Created | `#<id>` as a link to the work item, its state, "checked 5 min ago" | **Unlink** |
| Failed | the reason | **Retry**, **Unlink** |
| Missing | "Not found in Azure Boards" | **Create again**, **Unlink** |
| Unlinked | no link | **Create work item** |

**Unlink** asks for confirmation. The work item stays in Azure Boards, Qualor stops updating it,
and the [automatic rule](#the-automatic-rule) never creates another one for that finding.

A person needs the permission to triage issues. A request needs a mapped project and a connection
without a credential problem: otherwise the screen says what is missing.

### What the work item holds

| Part | Content |
|---|---|
| Title | the issue's message, or `<vulnerability id> in <package> (<severity>)`. At most 255 characters, on one line |
| Description | the lines of a [Jira issue's description](./jira.md#what-the-jira-issue-holds), with a link to the finding in Qualor. Its last paragraph is `Qualor reference: qualor-<id>-<number>` |
| Repro Steps | the description again, when the type has the field |
| Tags | `qualor` and the mapping's tags |
| Links | a **Hyperlink** to the finding in Qualor |
| Area path, iteration path | the mapping's |

Do not edit or remove the line `Qualor reference: …`, and keep the tag `qualor`. When Azure
DevOps's answer to a create is lost, Qualor finds the work item by both, so the finding gets one
work item, not two.

There is no code snippet: code stays in Qualor. Qualor escapes everything that came from a report,
a rule, an advisory or a model, so it cannot become a link, a mention, an image or markup in Azure
DevOps. The links to Qualor appear only when the server has `QUALOR_PUBLIC_URL`.

### States and notes

Every 15 minutes Qualor reads the state of its work items, and at once after a changed mapping is
saved. The state shows next to the finding, coloured by its category: grey for Proposed and
Removed, blue for In Progress, green for Resolved and Completed. A work item that moved to another
project keeps its link. A work item that Qualor cannot find in two passes in a row becomes
**Missing**.

Qualor adds notes to the work item's discussion, and never changes its state:

| When | Note |
|---|---|
| Qualor no longer finds the issue or the vulnerability | "Qualor no longer finds …" |
| It finds it again | "Qualor finds this again: …" |

What counts as gone is the same as for [Jira](./jira.md#status-and-comments). A closed work item
gets notes too.

### The automatic rule

**Create work items for new vulnerabilities** creates work items without a click. It takes one of
**Off**, **Critical**, **High and above**, **Medium and above**, **Low and above**, and is off by
default. **Exploited vulnerabilities (CISA KEV)** adds the exploited ones; it needs Business or
Enterprise.

It follows [Jira's automatic rule](./jira.md#the-automatic-rule):

- Only vulnerabilities first found after you save count, never the backlog.
- At most 50 new work items per organisation in one pass. The rest follow in the next passes.
- A finding you unlinked is never created again.
- It needs vulnerability monitoring on for the project.

No audit entry records an automatic work item, because Qualor acts, not a person.

### One tracker per project

A project uses Jira or Azure Boards, never both. While one is mapped, the other's panel shows one
line: "This project uses Jira." or "This project uses Azure Boards.". To switch, remove the other
mapping first.

A finding has one tracker too. A finding with a Jira issue gets no work item, and a finding with a
work item gets no Jira issue, also after the project switched. The automatic rule skips such
findings. Existing links of the old tracker keep syncing.

### Permissions

| To do this | Permission | Role |
|---|---|---|
| Map a project, set the rule | `project.settings` | Project admin and above |
| Create, retry and unlink work items | `issue.triage` | Maintainer and above |
| See the work items | `project.read` | everyone who reads the project |

Every change is in the [audit log](./roles-and-audit.md#what-is-recorded).

### Troubleshooting

A credential problem of the connection stops new work items and state reads: a refused credential,
a sign-in page instead of data, a stored credential that can no longer be read, or an address the
server no longer allows. **Settings → Azure DevOps** shows it, and the fixes are those of
[a failing test](#test-the-connection). Each pass makes one call to check it and resumes when the
call succeeds.

| Problem | Cause | Fix |
|---|---|---|
| "The credential may not create work items in the mapped area path of Azure DevOps." | Azure DevOps refused the create (HTTP 403) | give the identity the rights in [What Boards needs](#what-boards-needs), then **Retry** |
| A failed work item shows Azure DevOps's own words | Azure DevOps refused a field, such as a required one or a rule | fix it in Azure DevOps or in the mapping, then **Retry** |
| "The mapped work item type no longer exists or needs fields Qualor does not set. Map the project again." | the type was removed, or gained a required field | [map the project](#map-a-project-to-azure-boards) with a type that works, then **Retry** |
| "Azure DevOps did not find the project, or the credential cannot see it." | the Azure DevOps project is gone, or the identity cannot see it | map the project again, or add the identity to the Azure DevOps project |
| "Azure DevOps refused the work item as too large." | Azure DevOps refused the request as too large | ask the Azure DevOps administrator about the limit |
| "Qualor could not tell whether Azure DevOps created the work item." | the answer to a create was lost, and Azure DevOps refused the search for it | look in Azure Boards for a work item with the tag `qualor`. **Retry** creates it again |
| "Not found in Azure Boards" | Qualor did not find the work item in two passes in a row: it was deleted, or the identity cannot see it any more | **Create again** makes a new one |
| "The project had no Azure Boards mapping when the work item was to be created." | the mapping was removed before creation | map the project, then **Retry** |
| "The finding is closed or can no longer have a work item." | the finding was deleted, or was closed, before the work item was made | nothing to do |
| "This finding already has a Jira issue." | [one tracker per finding](#one-tracker-per-project) | nothing to do |
| **Save**: "Azure DevOps refused a test work item with this mapping. It said: …" | a required field Qualor does not fill, or a rule | fix what Azure DevOps names, then **Save** again |
| **Save**: "Qualor cannot fill these required fields of the work item type: …" | the type requires fields Qualor cannot fill | [Which work item types work](#which-work-item-types-work) |
| **Save**: "The Azure DevOps project no longer lists the chosen area path or iteration path. Choose them again." | the path was renamed or deleted | choose the paths again |
| **Save**: "The credential may not read or create work items in Azure DevOps. …" | Azure DevOps refused the identity (HTTP 403) | [What Boards needs](#what-boards-needs) |
| **Test**: "The identity lacks a right: Create work items in the mapped Azure Boards project (Work items: Read & write)." | Azure DevOps refused a test work item of a mapped project | [What Boards needs](#what-boards-needs) |
| "This project uses Jira. Remove its Jira mapping first." | the project has a Jira mapping | remove the Jira mapping in **Project → Settings → Jira**, or keep Jira |
| Work items have no link back to Qualor | `QUALOR_PUBLIC_URL` is not set on the server | set it |
| Nothing is created and no problem shows | the project is not mapped, or vulnerability monitoring is off for an automatic rule | check the panel |

## Roles and audit

Only organisation administrators see and change Azure DevOps connections. Creating, changing and
deleting one, and subscribing its hooks, is recorded in the [audit log](./roles-and-audit.md).

## Delete a connection

Press **Delete** on the connection. Projects mapped to it lose their mapping. Their analyses stay.
Its Azure Boards mappings and work item links go too. The work items stay in Azure Boards.
