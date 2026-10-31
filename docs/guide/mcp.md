# MCP server for AI agents

Qualor has a built-in MCP server (Model Context Protocol), so an AI agent such as Claude Code,
Cursor or claude.ai can work with Qualor. The agent reads the quality gate and the issues of a
branch or merge request, asks the [AI assistant](./ai-assistant.md) to explain a finding or suggest
a fix and, if you allow it, marks a finding false positive or won't fix. It acts **as the person
who signed in, with that person's rights**, and never sees more than they do. There is nothing to
install: each person connects their own agent.

## Requirements

- `QUALOR_PUBLIC_URL` is set to the address people open Qualor at, such as
  `https://qualor.example.com` ([Install the server](./install-server.md#server-settings)). Without
  it the MCP server is off, and **Settings → MCP** says so.
- Qualor is served over **HTTPS**, usually by a reverse proxy. AI clients refuse to sign in over
  plain `http://`, except on `localhost`.
- If Qualor is served under a path, such as `https://example.com/qualor`, the proxy also passes the
  addresses that start with `/.well-known/oauth-` at the root of the host to Qualor, unchanged
  ([Reverse proxy and TLS](./install-server.md#reverse-proxy-and-tls)).
- The person has a Qualor account. Single sign-on works as usual.

The MCP address is the server's address followed by `/mcp`, such as
`https://qualor.example.com/mcp`. **Settings → MCP** shows it with a Copy button.

## Connect Claude Code

```bash
claude mcp add --transport http qualor https://qualor.example.com/mcp
```

Then type `/mcp` in Claude Code, pick `qualor` and choose **Authenticate**. Your browser opens
Qualor: sign in if needed, and click **Allow**.

## Connect Cursor

Add the server to `~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project:

```json
{
  "mcpServers": {
    "qualor": {
      "url": "https://qualor.example.com/mcp"
    }
  }
}
```

Cursor then asks you to sign in, on the same Qualor page.

## Connect claude.ai or Claude Desktop

Open **Settings → Connectors → Add custom connector**, name it `Qualor` and enter
`https://qualor.example.com/mcp`. Click **Connect** and allow the app in Qualor.

Claude then reaches your server from the internet, so the server must be reachable from there. A
server on a private network works with Claude Code and Cursor on a laptop inside that network, but
not with claude.ai.

## Other clients

Any client that supports MCP over HTTP with OAuth sign-in works. Give it the MCP address: Qualor
tells it where to register and sign in, and the client opens your browser.

## What the agent can do

The page where you allow the app lists what it may do. Reading is always included. **Change issue
statuses** is a separate box that appears only if the app asks for it: untick it to let the app
only read. The choice is made the first time you allow an app. Allowing it again keeps a right it
already has: to take it away, [disconnect the app](#disconnect-an-app) and connect it again with
the box unticked.

| Tool | What it does | Needs |
|---|---|---|
| `qualor_projects` | Lists the projects you can see, so the agent can match the `projectKey` of `qualor.yml` | read |
| `qualor_gate_status` | Whether the quality gate of a branch or merge request passes, and which conditions fail. With a commit SHA, also whether CI has analysed that commit yet | read |
| `qualor_issues` | The issues of a branch or merge request, most severe first. By default the open issues in new code, which is what the gate counts. Security hotspots, which the gate does not count, are listed with `kind: hotspot`. Findings of the [AI review](./ai-review.md) are marked `AI`: they may be wrong, and the gate never counts them | read |
| `qualor_issue` | One issue in full: the code, secondary locations, the rule and its history. For a finding of the AI review, also the review's text, what it assumes, the second check, the suggested change and the commit it read | read |
| `qualor_rule` | What a rule checks and how to fix what it reports | read |
| `qualor_measures` | Coverage, duplication and ratings; for a file, its covered and uncovered lines | read |
| `qualor_explain` | Asks the AI assistant to explain an issue | read, and the AI assistant on |
| `qualor_suggest_fix` | Asks the AI assistant for a fix. Nothing is posted anywhere | read, and the AI assistant on |
| `qualor_transition_issue` | Marks an issue false positive or won't fix, or reopens it, with a mandatory comment. The optional `reason` (a VEX justification) is required for a false positive on a Trivy issue of the main branch or a tracked branch ([Dependency vulnerabilities](./dependency-vulnerabilities.md#statuses-and-reasons)) | change issue statuses |

The server also offers one ready-made prompt, **Fix the quality gate** (`fix_quality_gate`), which
clients show as a command or a menu entry. It tells the agent to read the failed conditions, fix
the issues in new code, push, and check the gate again after CI.

A branch is named by its name, a merge or pull request by its number. With neither, the agent looks
at the project's main branch.

## Permissions

- **Your role decides.** The agent has your role in each project. A Viewer can read. Asking the AI
  assistant and changing an issue's status need Maintainer or above, as in the web UI
  ([Roles](./roles-and-audit.md#roles)). Anything you could not do yourself answers "forbidden".
- **An agent allowed only to read cannot change an issue**, whatever it tries.
- **A status change by the agent says so.** Its comment ends with a line naming the app, so
  reviewers can tell it from your own.
- **The token works only on the MCP address.** It cannot call the REST API, the CLI or the web UI,
  and it does not replace a [personal token](./users-projects-tokens.md#tokens).
- **The AI assistant keeps its own rules.** `qualor_explain` and `qualor_suggest_fix` send the same
  redacted data as the buttons in the issue view, and only when an administrator switched the
  assistant on for the organisation ([What is sent](./ai-assistant.md#what-is-sent-and-where)).
- The agent cannot create or delete projects, change settings or manage users.

Access tokens last an hour, and the app renews them by itself. An app unused for 90 days is
disconnected.

## The agent's loop

The server computes the quality gate after CI has analysed a commit, not on the agent's machine. So
the agent works in a loop:

1. It fixes the code and **pushes**.
2. **CI runs `qualor scan`** ([GitLab](./gitlab.md), [GitHub](./github.md),
   [other CI](./other-ci.md)).
3. It calls `qualor_gate_status` with the pushed commit SHA. While the state is `not_yet` or
   `in_progress`, CI has not delivered yet: it waits a minute or two and asks again.
4. At `analyzed` it reads the gate and the failed conditions, and goes back to step 1 if the gate
   still fails.

| State of a commit | Meaning |
|---|---|
| `analyzed` | the analysis is done |
| `in_progress` | the analysis is running |
| `failed` | the analysis ended with an error |
| `not_yet` | Qualor has not seen the commit |

If a commit was analysed more than once, the newest analysis counts. Without a commit SHA, the tool
reports the branch's latest analysis, which may be of an older commit.

## Disconnect an app

**Settings → Connected apps** lists the apps you allowed, with their rights and when they were last
used. **Disconnect** ends an app at once: its tokens stop working. A disconnected app, like one idle
for 90 days, shows the **Allow** page again the next time it connects.

An administrator can see and disconnect any user's apps in **Settings → Users → Connected apps**,
for example when someone leaves or a laptop is lost.

## For administrators

**Settings → MCP** (instance admins) shows the MCP address, or asks you to set
`QUALOR_PUBLIC_URL`. It controls which apps may connect:

- **Let apps register themselves** (dynamic registration). Most agents register this way, so leave
  it on unless you want an allow-list only. Anyone can register under any name, so their consent
  page says "Not verified: this app registered itself". The page always shows the address the
  browser returns to: users should allow only an app they started themselves.
- **Accept apps identified by a metadata URL (CIMD).** Some clients, such as claude.ai, identify
  themselves by an `https` address that describes them. Qualor fetches that address when someone
  signs in, and the consent page shows its host. Turn this off if the server must make no such
  request.
- **Allowed apps.** One client id per line, or a URL prefix ending in `/`. When the list has
  entries, only those apps can connect. An app not on it can no longer sign in or renew its login,
  but an app already connected keeps working until its current login runs out, up to an hour. To
  stop it at once, disconnect it in **Settings → Users → Connected apps**.

With an audit log ([Roles and the audit log](./roles-and-audit.md)), Qualor records
`oauth.client_registered`, `oauth.grant_created`, `oauth.grant_revoked` (with who ended it, or that
a refresh token or authorization code was reused) and `oauth.settings_changed`, in the log and in
its export.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| **Settings → MCP** says "Set `QUALOR_PUBLIC_URL`", and `/mcp` answers 404 | The server has no public address. Set `QUALOR_PUBLIC_URL` and restart |
| The client signs in, then asks again and again (a 401 loop) | `QUALOR_PUBLIC_URL` differs from the address the client uses: another host, `http` instead of `https`, or a path the proxy changes. The token is issued for one exact address. Fix the variable or the proxy |
| The client cannot connect or refuses the address | The server is on plain `http://` away from `localhost`, or claude.ai cannot reach it from the internet |
| "The administrator of this server does not allow this app." on the consent page | The allow-list in **Settings → MCP** does not include the app |
| This request has expired or was already answered | A sign-in request lives for 10 minutes. Start the connection again from the app |
| A tool says the AI assistant is off (`AI_DISABLED`) | An instance admin has not allowed the organisation to use the [AI assistant](./ai-assistant.md), or the feature, in **Settings → AI provider**, or the issue's project or path is excluded. The other tools work |
| "Project … has no analysed branch" | CI has not run `qualor scan` on that branch or merge request yet |
| "Matches several commits" (`AMBIGUOUS_COMMIT`) | The short SHA fits more than one commit. The agent should send more characters |
| "Searched the first … branches" (`SEARCH_INCOMPLETE`) | The project has very many branches or analyses, and the one asked for was not among the newest. Name it exactly |
| Forbidden when changing an issue | Your role in the project cannot triage, or the app may only read. Connect the app again and tick **Change issue statuses** (shown only if the app asks for it) |
| An agent that runs several processes with one login is signed out from time to time | Qualor ends a login when the same refresh token is used twice, which is what a stolen token looks like. Processes that share a login and renew at the same moment trigger it. Connect again; if it happens often, run the agent's MCP connection in one process |

More errors are in [Troubleshooting](./troubleshooting.md).
