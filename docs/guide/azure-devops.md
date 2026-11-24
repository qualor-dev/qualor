# Azure DevOps

Qualor connects to Azure DevOps Services (`dev.azure.com`) and Azure DevOps Server 2022 or later.
An organisation administrator adds a connection, tests it and maps each Qualor project to a
repository.

Not yet available in this release: fix pull requests, CI setup, and Azure Boards. A connection and a
mapping prepare them.

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
the repository from the list. Its entries read `project/repository`. Type in the search field to
narrow a long list, and press **Save**.

A repository is stored by its id, so a rename in Azure DevOps keeps the mapping.

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

## Roles and audit

Only organisation administrators see and change Azure DevOps connections. Creating, changing and
deleting one, and subscribing its hooks, is recorded in the [audit log](./roles-and-audit.md).

## Delete a connection

Press **Delete** on the connection. Projects mapped to it lose their mapping. Their analyses stay.
