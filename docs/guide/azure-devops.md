# Azure DevOps

Qualor connects to Azure DevOps Services (`dev.azure.com`) and Azure DevOps Server 2022 or later.
An organisation administrator adds a connection, tests it and maps each Qualor project to a
repository.

Not yet available in this release: comments and statuses on pull requests, AI review, fix pull
requests, CI setup, Azure Boards. A connection and a mapping prepare them.

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

Create the token in Azure DevOps under **User settings → Personal access tokens**, with the scope
**Code: Read**. It sees what its owner sees, and it stops working when it expires or its owner
loses access.

If Azure DevOps Server's certificate comes from a private CA, give the server that CA with
`NODE_EXTRA_CA_CERTS`.

## Test the connection

Press **Test** on the connection. A passing test shows who connected and how much that identity
sees:

> Connected as Qualor; 12 repositories in 3 projects visible.

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

The `Qualor@0` task needs the Qualor extension in your organisation. Until its Marketplace listing
is public, install it from the VSIX file attached to the release.

| Task input | Meaning |
|---|---|
| `dotnet` | `true` analyses C# with the MSBuild integration |
| `dotnetBuild` | The build command for C#. Default: `dotnet build --no-incremental` |
| `imageTag` | The tag of `qualor/scanner`. Default: the extension's version |
| `arguments` | Extra arguments for `qualor scan` |

The checkout step needs `fetchDepth: 0`. The task fails with that hint on a shallow clone.

### Pull requests

Azure Repos ignores `pr:` in the YAML. Add the pipeline as a Build validation policy under
**Repos → Branches → Branch policies** of the target branch.

The task checks out the pull request's head, not Azure's merge commit. A pipeline that skips this
checkout still uploads, but later inline comments cannot be placed in it.

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

## Roles and audit

Only organisation administrators see and change Azure DevOps connections. Creating, changing and
deleting one is recorded in the [audit log](./roles-and-audit.md).

## Delete a connection

Press **Delete** on the connection. Projects mapped to it lose their mapping. Their analyses stay.
