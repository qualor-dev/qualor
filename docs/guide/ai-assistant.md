# AI assistant

The AI assistant asks a language model about one issue: explain it, suggest triage or suggest a
fix. It is **off by default**, and it uses a model you choose with your own key, hosted or on your
own network. This page also sets up the AI provider that [AI review](./ai-review.md) uses. AI
review has its own switch, warning and budgets.

## What it does

The **AI assistant** panel of the issue view has three actions. Each runs only when a person clicks
it, for that one issue.

- **Explain**: what the rule checks, why this code triggers it, the risk, and how to fix it.
- **Suggest triage**: a verdict ("Likely a false positive", "Likely a true positive" or
  "Uncertain"), a confidence and up to five reasons. The model never changes the issue. To agree,
  click **Mark as false positive…**: the usual status change opens with an empty comment for your
  own reason. The changelog records that the AI suggestion was shown and that the decision was
  yours.
- **Suggest a fix**: a replacement for the flagged lines, shown as before and after. On a merge
  request or pull request mapped to GitLab or GitHub, **Post to merge request** posts it as a GitLab
  suggestion or a GitHub suggested change, which a person reviews and applies there.

Triage and fix need an **open** issue. A fix also needs the issue's file, line and surrounding
code. Qualor never commits, pushes, or opens a branch or merge request of its own.

Every answer is labelled "AI-generated, may be wrong", with the model's name and the time. Answers
are shown as plain text: links, Markdown and HTML in them are never rendered.

With an Enterprise licence, fixes can also be suggested without a click: see
[Automatic fix suggestions](#automatic-fix-suggestions-enterprise).

### Posting a fix

A fix is shown only when it passes the safety rules: it stays inside the shown lines and holds no
secret, no control characters and no GitLab quick action. It is posted only when all of these hold,
and otherwise the panel says why:

- The merge request's head is still the commit Qualor analysed. After a newer push, analyse it and
  ask again.
- The lines to replace are lines the merge request added, and they are unchanged.
- The issue is still open, and the assistant and its fix feature are still on.

Posting the same suggestion twice posts it once. No extra GitLab scope or GitHub App permission is
needed: the token or App that comments on merge requests posts the suggestion.

## What is sent, and where

Nothing is sent until an instance admin has connected a provider, allowed the organisation to use
AI and switched the feature on, and a person clicks. No scan, merge request comment or background
job calls a model by itself. Only the server contacts the model, never the scanner.

Two features call the model without a click, and an organisation admin must switch each on first:

- [Automatic fix suggestions](#automatic-fix-suggestions-enterprise) (Enterprise) send the same
  data as a person's fix.
- [AI review](./ai-review.md) (every edition) sends **repository code**: the merge request's diff,
  any file the model chooses to read from the copy the scanner uploaded to your server, and the
  threads it answers in. See [What the model is sent](./ai-review.md#what-the-model-is-sent).

For the one issue a person asks about, the server sends:

- the rule: its key, name, description and CWE numbers;
- the issue's severity, quality, kind and message;
- the file path, the lines and the language;
- the code the scan stored: the flagged lines with up to 3 lines of context on each side.

**Secrets are redacted first.** The scanner replaces the secrets its analyzers find with
`«redacted»`. The server redacts again before anything leaves: private keys, cloud and SCM tokens,
API keys, JSON Web Tokens, passwords in URLs, `Authorization` headers, and values assigned to names
such as `password`, `secret`, `token` or `api_key`. It finds these in code, `.env` and YAML files,
properties, Dockerfiles, connection strings and XML.

**Never sent:**

- issues of secret-detection rules: Gitleaks, and rules about credentials in code;
- issues in files that look like credentials: `.env` files, keys and certificates (`*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.ppk`), `id_rsa` and similar, `credentials*`, `.npmrc`,
  `.pypirc`, `.netrc`, `.git-credentials`, `.pgpass`, `.htpasswd`, Docker and Kubernetes configs,
  Terraform variables and state, and `secrets.yml`. A source extension changes nothing:
  `credentials.js` is not sent either;
- issues of an excluded project or on an excluded path;
- the names of the project, organisation and branch, commit SHAs, users and changelog comments.

**Data and privacy**, in **Settings → AI provider**, lists what each feature sends and to which
host. The panel in the issue view names the same fields, with the provider's host and model.

## Configuration

### The provider (instance admins)

An instance admin connects one provider for the whole instance in **Settings → AI provider**. A
**Status** card sums up the provider and its last Test, the organisations that may use AI, where
AI review is on or paused, the limits and the prices. Four sections follow, each with its own Save:
**Provider**, **Organizations**, **Limits** and **Data and privacy**. Only **Provider** shows until
a provider is saved.

In **Provider**, first choose the kind of API the model speaks. The other settings then appear:

| Setting | What to enter |
|---|---|
| Provider | **OpenAI-compatible**: OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio, LiteLLM and other servers of the Chat Completions or Responses API. **Anthropic**: Claude models at `api.anthropic.com` |
| Base URL | With the version path for OpenAI-compatible servers: `https://api.openai.com/v1`, `https://<resource>.openai.azure.com/openai/v1`, `http://ollama:11434/v1`. For Anthropic, `https://api.anthropic.com`, filled into an empty field when you choose **Anthropic** |
| API key | Write-only: stored encrypted, never shown again. Leave it empty for a local model without a key. A stored key shows as **Set**, with **Replace the key** and **Remove the key**. **Remove the key** deletes it when you save; **Undo** keeps it |
| Workspace ID | Anthropic only, optional: `wrkspc_…`, for a key of the whole organisation that is not scoped to a workspace ([The current models](#the-current-models)). Not a secret |
| Model | The **standard model**, as the provider spells it. Explain, Suggest triage, Suggest a fix, the review's reviewers and the answers to replies use it |
| Strong model | Under the switch **Use a stronger and a faster model for parts of AI review**, off by default. Runs the review's judge and its second check of security findings. Empty: the standard model ([Model tiers](#model-tiers)) |
| Fast model | Under the same switch. Runs the quality reviewer of a review of 10 changed lines or fewer. Empty: the standard model |
| Prices | Under the switch **Count costs with these models' prices**, off by default. **Input**, **Output** and optional **Cached input** prices per model, in US dollars per million tokens ([Budgets and limits](#budgets-and-limits)) |

**Connection options** is a fold that lists its values while closed. Most providers need no change
there:

| Setting | What to enter |
|---|---|
| API | OpenAI-compatible only. **Chat Completions**, which vLLM, Ollama, LM Studio, LiteLLM and Azure serve, or **Responses**, which OpenAI's newest models need for tool calling ([The current models](#the-current-models)). Until you choose, the page sets **Responses** for a new provider at `api.openai.com` and **Chat Completions** for any other |
| Key header | OpenAI-compatible only: `Authorization: Bearer` (the default) or `api-key (Azure)` |
| Output limit parameter | Chat Completions only. `max_completion_tokens` for OpenAI and Azure OpenAI, whose current models refuse `max_tokens`; `max_tokens` for vLLM, Ollama and most other servers. Until you choose, the page sets it from the base URL's host. Hidden for **Responses**, which always uses `max_output_tokens` |
| Ask for a JSON object | OpenAI-compatible only: JSON mode, on by default. Turn it off for a server that refuses `response_format` |
| Timeout | 5–600 seconds, default 60, for a whole request of Explain, Suggest triage, Suggest a fix and the Test. Review and reply calls stream: they wait at least 300 seconds for the first piece and between pieces, and 15 minutes in all ([Models that work](./ai-review.md#models-that-work)) |
| Context window | 8,000–10,000,000 tokens; empty means 1,000,000. The most the model reads in one call: a review or reply call never exceeds it, less the room for the answer. Set it when the model takes less; with several models, give the smallest window. It changes no consent and pauses no AI review ([Models that work](./ai-review.md#models-that-work)) |
| Set a temperature | OpenAI-compatible only, off by default: no temperature is sent, and the model uses its own. On: a **Temperature** from 0 to 2 |

Press **Save and test**. It saves the provider, then tests each model at once: the standard model,
and the strong and fast models when they name another model. Each test is a fixed prompt with no
repository data, through the API you chose. When it passes, a second fixed call checks tool
calling, which [AI review](./ai-review.md#models-that-work) needs.

**Last test** shows one line per model, such as
`gpt-6.1-sol: connected in 812 ms · can call tools` or
`gpt-4o-mini: connected in 640 ms · cannot call tools, so AI review would fail`. A failed model's
line says what went wrong, and failures do not affect the other models. When the tool check could
not tell, the line shows the connection only. When any model failed, the page adds
`The test failed for 1 of 3 models.` When a model needs **Responses** or a **Workspace ID**, the
Test says so ([Troubleshooting](#troubleshooting)).

**Test again** retests the saved provider while the section has no unsaved changes. Qualor keeps
the last Test, with when it ran and who ran it, until the provider's settings or key change. An
organisation admin who switches AI review on is warned about a model that cannot call tools
([In Qualor](./ai-review.md#in-qualor)).

- For Azure OpenAI, use the v1 API's base URL. Per-deployment URLs
  (`/openai/deployments/<name>/…?api-version=`) are not supported.
- **Changing the base URL needs the key again.** Qualor sends a stored key only to the address it
  was entered for.
- **Changing the address or the models pauses AI review** in the organisations whose admins
  confirmed them ([The warning](./ai-review.md#the-warning)). While AI review is on somewhere,
  **Save and test** asks first, such as "Pause AI review in Acme?". **Save and pause AI review**
  saves; **Cancel** sends nothing. The assistant's actions carry on. The key, the API, the timeout,
  the temperature, the workspace and the prices pause nothing.
- **Remove the provider…** asks "Remove the AI provider?", then stops every AI feature in every
  organisation and deletes the API key. Organisations keep their settings.
- The API key is encrypted with `QUALOR_SECRET_KEY`. After that key changes, set the API key again.
- The address must be `https` and resolve to public addresses, unless the operator lists the host
  in `QUALOR_LLM_INTERNAL_HOSTS` ([A local model with Ollama](#a-local-model-with-ollama)).
  Redirects are not followed, and no proxy is used.
- After 5 failures in a row (timeouts, no answer, rate limits), Qualor pauses calls to the address
  for 10 minutes. AI review has a pause of its own: failing reviews never pause the assistant, and
  the reverse.

### A local model with Ollama

To keep code on your own network, run [Ollama](https://ollama.com) next to the server. Qualor uses
Ollama's OpenAI-compatible API at `/v1`.

1. Add an `ollama` service to the server's [`compose.yml`](./install-server.md#the-compose-file),
   with a volume for its models and no published port:

   ```yaml
   services:
     server:
       # ... as in "Install the server"
     ollama:
       image: ollama/ollama:<version> # pin a version
       restart: unless-stopped
       volumes:
         - ollama:/root/.ollama
       security_opt: ['no-new-privileges:true']

   volumes:
     data:
     ollama:
   ```

2. Allow the server to call it over plain `http` on the internal network. In `.env`:

   ```sh
   QUALOR_LLM_INTERNAL_HOSTS=ollama:11434
   ```

   The guide's `compose.yml` passes this variable to the server. It is separate from
   `QUALOR_SCM_INTERNAL_HOSTS`: a GitLab listed there cannot be the model's address, nor the
   reverse.

3. Start it and download a model into the volume:

   ```sh
   docker compose up -d
   docker compose exec ollama ollama pull <model>
   ```

4. In **Settings → AI provider**, choose **OpenAI-compatible**, the base URL
   `http://ollama:11434/v1`, the model's name as `ollama list` shows it, and no API key. Press
   **Save and test**. Then allow the organisations you want under **Organizations**, with their
   features.

A local model on a CPU can be slow. If requests end with "The model did not answer in time", raise
**Timeout** in **Connection options** (up to 600 seconds), and give Ollama the memory its model
needs. vLLM and LM Studio are set up the same way, with their own host and port in
`QUALOR_LLM_INTERNAL_HOSTS`.

To keep the server and its database on a network with no route out, as the repository's
`deploy/docker-compose.yml` does, see
[A local model with Ollama](../../deploy/README.md#a-local-model-with-ollama) in
`deploy/README.md`.

### The current models

- **OpenAI: Chat Completions or Responses.** OpenAI's newest models (`gpt-6.1-sol`,
  `gpt-6.1-terra` and `gpt-6-luna` were checked) take function tools with reasoning only through
  **Responses**. [AI review](./ai-review.md#models-that-work) needs tools, so choose **Responses**
  under **API** for them. The Test tells you when you did not.
- **Through Responses**, the output limit is always `max_output_tokens`, and the API clamps one that
  is too large. Requests are stateless: Qualor sends `store: false`, so OpenAI keeps nothing beyond
  its own abuse monitoring. The model's reasoning comes back encrypted and goes back with the next
  turn of a conversation. With JSON mode on, Qualor adds `Reply in JSON.` to the first message when
  no message says JSON, as the API requires.
- **Anthropic.** The current models (Claude 4.7 and later) take no temperature. Qualor never sends
  one, and saving one through the API is refused. They think by default, and Qualor sends their
  thinking back unchanged with each turn of a conversation, as they require. A key of the whole
  organisation that is not scoped to a workspace needs its **Workspace ID**, which Qualor sends as
  `anthropic-workspace-id` on every request. Without it the provider refuses the call, and the
  Test says so (`PROVIDER_WORKSPACE_REQUIRED`).
- **Room to think.** Thinking counts in the output limit, so review and reply calls ask for up to
  16 000 output tokens more than the answer needs (less when the window has less left), and the assistant's actions and the Test 4 000 more.
  The room costs nothing unless the model uses it. When a model or server refuses that much (a 400,
  or a 422 from Hugging Face TGI), Qualor asks once more without the room, whatever the refusal
  says, unless it is about the workspace, tools, the Responses API or streaming. This holds for
  Responses API servers too. If the second ask works, it leaves the room out for that server and
  model until the server restarts. It does not remember a refusal that names the context window the
  prompt shares with the answer, as vLLM and Anthropic word it. Then it asks for the room again on
  every call, and without it when the prompt leaves none, so a vLLM with a small window pays one
  quick refusal per call. How the room counts in a review's budget:
  [Budgets and today's usage](./ai-review.md#budgets-and-todays-usage).
- **A refusal fails the step.** Qualor reads a model's refusal as an answer it could not read, so
  the step fails ([Models that work](./ai-review.md#models-that-work)). Qualor never falls back to a
  model you did not choose.

### Model tiers

AI review's work falls into three tiers, and each can have its own model. Only the standard model
is required:

| Tier | Setting | What runs on it |
|---|---|---|
| Strong | **Strong model** | the judge of a review, and the second check of its security findings |
| Standard | **Model** | the reviewers (quality, tests, security and performance), the answers to replies, and Explain, Suggest triage and Suggest a fix |
| Fast | **Fast model** | the quality reviewer of a review of 10 changed lines or fewer |

A tier uses the standard model when **Use a stronger and a faster model for parts of AI review** is
off, when the tier is empty, or when it names the standard model. You choose each tier's model, not
the work a tier does. The security reviewer that a sensitive path adds to a small review stays on
the standard model, as do the reviewers of every larger review.

What an organisation admin confirms to switch AI review on names every model, sorted, such as
`api.openai.com (gpt-6-luna, gpt-6.1-sol, gpt-6.1-terra)`. Changing, adding or dropping one stops
AI review until an organisation admin confirms again ([The warning](./ai-review.md#the-warning)).
With prices entered, each tier with its own model needs its own prices
([Budgets and limits](#budgets-and-limits)).

### Organisations and projects

The **Organizations** section of **Settings → AI provider** lists every organisation, 25 at a time
(**Show 25 more**), with a filter. A row shows whether the organisation may use AI (**Allowed** or
**Not allowed**), its **Assistant features**, how many of its projects are **Never sent**, and what
its own admins switched on: **AI review**, **AI review (paused)**, **Fix suggestions** or **Fix
suggestions (not running)**.

**Open** chooses the organisation in the header and goes to its AI page. **Edit** opens the
organisation's editor under its row. For an organisation named Acme it holds these settings, saved
with **Save Acme**:

- **Allow AI in Acme**: organisations start with it off, and while it is off nothing of the
  organisation is sent. While it is on, the organisation's people can use the features below, and
  its admins can switch on AI review, which sends repository code, and automatic fix suggestions.
  Switching it off where AI review is on says "AI review is on in Acme: it stops, and its
  repository copies are deleted, when you save."
- **Assistant features**: **Explain**, **Suggest triage** and **Suggest a fix**, each off until
  switched on. Switching **Suggest a fix** off where automatic fix suggestions are on says "Acme's
  automatic fix suggestions stop without it."
- **Never sent to the provider**: projects whose issues are never explained, triaged or fixed, and
  that AI review never reviews. Their repository copies are deleted. **Add a project** searches the
  organisation's projects, and **Remove** takes one off.

**Never send these paths**, in **Data and privacy**, takes up to 100 globs, such as `legacy/**` or
`**/*.generated.ts`, added one at a time with **Add**. They match the issue's path in every
organisation.

An organisation admin sees their organisation's choices, read-only, in the **Assistant** section of
**Settings → AI**.

The panel appears in the issue view only for an organisation that may use AI, and each action only
when its feature is on and the issue can be sent. For an excluded project the panel says "An
instance admin excluded this project from AI." Asking and posting need the role that changes an
issue's status, Maintainer or above ([Roles](./roles-and-audit.md#roles)), signed in or with a
token that has the `write` scope ([Users, projects and tokens](./users-projects-tokens.md)).

## Budgets and limits

The instance admin sets the assistant's limits in the **Limits** section of **Settings → AI
provider**, under **Explain, Suggest triage and Suggest a fix**. They apply to each allowed
organisation, per UTC day. Automatic fix suggestions count as fix suggestions.

| Limit | Default |
|---|---|
| Explanations per day | 200 |
| Triage suggestions per day | 100 |
| Fix suggestions per day | 25 |
| Tokens per day (sent and received) | 1 000 000 |
| Limit the cost | off. On, **Cost per day** in US dollars. It needs the models' prices: without them the switch is disabled under "No prices are set, so a cost limit would count nothing. Enter them under Provider → Prices." |
| Asks per person and hour | 30, the three features together |

No edition caps these budgets: the explanation, triage and fix budgets each go up to 100 000 a day.
An organisation over a budget gets "The organization's AI budget for today is used up" until the
next UTC midnight. A person over the hourly bound gets "You asked too often; try again in a few
minutes".

An organisation's use today is on the **Today** line of the Status card in **Settings → AI**: an
**Assistant** meter of tokens against **Tokens per day**, the counts so far ("Explanations 12 ·
Triage 3 · Fixes 1"), and "Budget reached for today" once it is. The page's **Assistant** section
lists the limits.

**What counts.** A request counts against the daily budgets from the moment it is queued. It stops
counting if it fails without using any tokens: the provider refused the API key or asked for a
workspace ID, or nothing was sent. Nothing is sent when the assistant was turned off, the settings
or the issue changed, the issue is gone, or the key or the address can no longer be used. Every
other failure, such as a timeout or a refused request, still counts. The hourly bound counts every
request. Posting a suggestion to a merge request does not count again.

**Cache.** An answer is kept for the issue for 30 days. Asking again with the same code, rule and
model shows the stored answer at once, sends nothing and costs no budget. **Ask again** sends a new
request, which counts.

Each server process runs at most two requests at once, and at most one per organisation, so one
busy organisation cannot hold up the others. A slow or unavailable provider never delays analyses,
gates or merge request comments.

**Prices.** The estimated cost needs prices, in US dollars per million tokens. Switch on **Count
costs with these models' prices** in **Provider**. It shows **Input**, **Output** and **Cached
input** prices for the standard model and for each tier with a model of its own
([Model tiers](#model-tiers)), each row named by its model. An empty **Cached input** counts cached
input at the input price.

- With prices entered, a tier with its own model needs its prices too. Saving without them is
  refused ("Give the strong model's prices too", "Give the fast model's prices too").
- Through the API, prices for a tier with no model of its own are refused ("Set the strong model
  first").
- A call is costed at the prices of the model it went to.
- With a cost limit, Qualor turns what is left of it into tokens at the dearest price among your
  models.

**Prompt caching.** AI review and its replies use the provider's prompt cache. On Anthropic,
Qualor marks each call's system prompt and the end of its conversation for caching, five minutes at
a time. OpenAI caches by itself. Anthropic charges 1.25 times the input price for what it writes to
the cache. A server that refuses the markers is asked again without them.

The **AI review** group of **Limits** is not the assistant's budget. Its switch **Cap the tokens an
organization may give AI review**, with **Tokens per day, per organization**, caps what an
organisation admin may give [AI review](./ai-review.md#budgets-and-todays-usage). Off, there is no
cap: "Off: no cap, and organization admins may allow up to 1,000,000,000 tokens a day."

## Automatic fix suggestions (Enterprise)

With an Enterprise licence (feature `llm.auto-fix`, see [Enterprise](./enterprise.md)), Qualor
suggests fixes for the new findings of a merge request or pull request by itself. It posts them as
GitLab suggestions or GitHub suggested changes. It is **off by default** in every organisation.
Nothing is committed or pushed: a person applies each suggestion on GitLab or GitHub, or ignores
it.

### What runs, and when

After each analysis of a merge request or pull request whose project is mapped to GitLab or GitHub
([GitLab](./gitlab.md), [GitHub](./github.md)), Qualor picks the findings that get a suggestion:

- only **new-code** findings of that merge request: never the old issues of its target branch, and
  never an analysis of the main branch or another branch;
- only **open** issues at or above the **minimum severity** (default **High**: blocker and high);
- at most **the maximum per analysis** (default 10, from 1 to 25), the most severe first;
- never an issue Qualor already asked a model about by itself, whatever the answer. A later
  analysis, or a new commit that still has the finding, does not suggest it again;
- never an issue the assistant would not send for a person
  ([What is sent, and where](#what-is-sent-and-where)).

If a person already got a fix for the issue and it still applies (same code, rule and model,
within the 30-day cache), Qualor neither asks again nor posts it. Otherwise it asks by itself.

Qualor asks in the background, so the analysis, the quality gate and the merge request comment are
never delayed. It sends the same redacted data as for a person's fix. An answer is posted as an
inline suggestion only if, at that moment, it passes the checks of [a person's fix](#posting-a-fix)
and automatic fix suggestions are still on for the organisation and the project. After a newer
push, the next analysis starts again, and findings that got no suggestion yet can get one.

The suggestion carries the "AI-generated, may be wrong" label and the line "Posted automatically
for new findings of this merge request. A person can switch this off in Qualor's AI settings." The
issue view marks it **Suggested automatically**. A fix a person asked for is never posted
automatically.

### Switch it on and off

1. An instance admin has connected a provider and allowed the organisation to use AI with
   **Suggest a fix** on ([Configuration](#configuration)). Without that, automatic fix suggestions
   cannot be switched on.
2. An **organisation admin** opens **Settings → AI**, with the organisation chosen in the header.
   In **Automatic fix suggestions** they switch on **Post fix suggestions automatically**, choose
   **Minimum severity** and **At most per analysis**, and press **Save fix suggestions**. This
   needs the permission `org.ai.manage` of the Organization admin role
   ([Roles and the audit log](./roles-and-audit.md)). The section also lists the projects that
   opted out.
3. A **project admin** can opt one project out in **Project → Settings → AI**, under **Fixes**, with
   **Post fix suggestions to this project's merge requests automatically**. It saves at once.

When it cannot run, the pages say why:

| Where | Message | Meaning |
|---|---|---|
| **Settings → AI**, switch disabled | "Needs Suggest a fix for Acme, which an instance admin turns on in Settings → AI provider." | the organisation lacks **Suggest a fix** |
| **Settings → AI** | "On, but not running: Suggest a fix is off for Acme. An instance admin turns it on in Settings → AI provider." | **Suggest a fix** went off after the switch was turned on |
| **Project → Settings → AI** | "Acme has automatic fix suggestions off. An organization admin switches them on in Settings → AI." | a project cannot switch it on while its organisation has it off |
| **Project → Settings → AI** | "Not for a project excluded from AI." | the project is excluded from AI |

Switching it off, or losing the licence, stops new suggestions at once, including requests already
waiting. Suggestions already posted stay on the merge request.

### Budget and audit

An automatic suggestion counts as a fix request of the organisation: against **Fix suggestions per
day**, the tokens and the estimated cost ([Budgets and limits](#budgets-and-limits)). It counts
against no person's hourly bound. The fix budget is the only limit. When it is used up, Qualor
stops asking for that analysis and logs one line (`outcome: budget_exhausted`). A later analysis of
the same merge request picks up the remaining findings after the next UTC midnight. If suggestions
use the budget up too fast, lower **At most per analysis** or raise the budget.

The audit log records `organization.auto_fix_changed` for the organisation's settings and
`project.auto_fix_changed` for a project's opt-out. Each automatic request and each post are
recorded as `ai.requested` and `ai.fix_posted`, by the system
([Roles and the audit log](./roles-and-audit.md#what-is-recorded)).

## Retention and audit

The server records every request sent to the provider: who asked, for which issue, the feature, the
provider's host and model, the size and a hash of what was sent, the names of the fields sent, the
number of redactions, the status, the token counts, the estimated cost when prices are set, and the
duration. It never records the API key, and it records the content sent only if you ask it to:

- **Keep a copy of what is sent**, in **Data and privacy** (off by default), keeps the exact data
  sent, after masking, for 1–90 days (**Keep for**, default 7).
- The answer is kept, since the issue view shows it and a fix is posted from it. A fix keeps the
  lines it replaces, to check them against the merge request before posting.
- Request records are deleted after **90 days**, or with their organisation or project. The record
  of an automatic fix suggestion stays while its issue exists: it keeps Qualor from suggesting that
  fix again.
- Each finished request writes one log line with the same details, never the content or the key.
  When the provider answered with an error, the line has its HTTP status (`providerStatus`).
- [AI review](./ai-review.md#how-long-copies-live) calls are recorded the same way, with the
  feature `review` (a review's calls) or `review-reply` (the answers to replies), the model of each
  call, and no issue or person. With **Keep a copy of what is sent** on, their prompts are kept for
  the days set there, and the model's answers stay with the record. The prompts hold the code the
  model was shown and, for a reply, what people wrote in the thread.

An organisation's use today and its budgets are at `GET /api/v0/organizations/{id}/ai`.

## Troubleshooting

| Message | What to do |
|---|---|
| "The model did not answer in time" | Raise **Timeout** in **Connection options** of **Settings → AI provider**. A local model on a CPU needs more |
| "The model provider could not be reached" | Check the base URL, and that the server can reach the host. After 5 failures in a row, Qualor pauses calls to the address for 10 minutes |
| "The model provider is rate limiting Qualor; try later" | The provider's own limit. Qualor retries after the time the provider asks for. Try again later, or lower the budgets |
| "The provider refused the API key (HTTP 401)" | Set a valid key. Check the key header (`api-key` for Azure) |
| "The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit" | The key is valid but may not use this model. Check the model's name, the key's project or workspace permissions, and the account's billing or credit |
| "The model does not accept max_tokens; set the output limit parameter to max_completion_tokens in the AI provider settings" (or the other way round) | The model refused the output limit parameter, also when asked again without the room to think. Choose the other **Output limit parameter** in **Connection options** |
| "The provider refused the request; check the base URL and the model" | An OpenAI-compatible base URL usually needs `/v1`. Check the model's name. OpenAI's newer models need the `max_completion_tokens` output limit parameter, and some servers need **Ask for a JSON object** off |
| "The provider's answer was not understood" | The address is not a Chat Completions, Responses or Anthropic Messages API (check **API** too), or the answer was over 1 MiB |
| "This key is not scoped to a workspace: give its workspace ID above" (elsewhere "… in the AI provider settings"; code `PROVIDER_WORKSPACE_REQUIRED`) | An Anthropic key of the whole organisation needs its **Workspace ID** (`wrkspc_…`) in **Settings → AI provider**. The request is not retried |
| "This model takes tools only through the Responses API: choose Responses in Connection options." (under the Test's lines) | Choose **Responses** under **API** in **Connection options**, then press **Save and test** ([The current models](#the-current-models)) |
| "Anthropic's current models take no temperature: leave it empty" | An Anthropic provider cannot be saved with a temperature. The page sends none; through the API, leave `provider.temperature` empty |
| "Give the strong model's prices too" or "Give the fast model's prices too" | Prices are entered and a tier has a model of its own. Enter that model's input and output prices, or clear all prices ([Budgets and limits](#budgets-and-limits)) |
| "The provider's address is not allowed" | The operator lists the host with its port in `QUALOR_LLM_INTERNAL_HOSTS`, or use an `https` address that resolves to public addresses |
| "The stored API key can no longer be read; set it again" | `QUALOR_SECRET_KEY` changed. Enter the API key again |
| "The model's answer could not be used" | The model did not answer with the expected JSON, or its answer was cut off. Ask again, or try another model |
| "The model declined to answer" | The provider's content filter or the model refused |
| "The suggested fix was not safe to show" | The fix broke a [safety rule](#posting-a-fix). Ask again, or fix it by hand |
| "This organization may not use AI." | An instance admin allows the organisation, with the feature on, under **Organizations** in **Settings → AI provider** |
| "Findings of secret rules are never sent" / "Issues in credential files are never sent" | By design: Explain, Triage and Fix never send them. Handle these issues without the assistant |
| "An administrator excluded this issue's path or project" | By design. An instance admin can change the exclusions |
| "Something changed since you asked; ask again" | The settings or the issue changed (a new analysis) while the request waited |
| "The request was interrupted; ask again" | The server crashed or was killed while the request ran, a stop took longer than its grace period (60 seconds in the guide's Compose file and Helm chart), or the request failed unexpectedly. A request waiting or running when the server stops in time goes back to the queue and is answered after the restart |
| "Not posted: the merge request has a newer commit" | Analyse the latest commit, then ask for a new fix |
| "Not posted: the lines are not added lines of the merge request" / "the code on the merge request differs" | A suggestion can only replace lines the merge request added, unchanged. Fix it by hand |
| No automatic suggestions on a merge request | Go through [the checklist below](#no-automatic-fix-suggestions) |
| No **Automatic fix suggestions** section in **Settings → AI**, whose Status ends with "Automatic fix suggestions are part of Qualor Enterprise." | The licence does not list `llm.auto-fix`, or it lapsed. Apply a key that lists it ([Enterprise](./enterprise.md)) |
| "Automatic fix suggestions need the Enterprise plan." in the **Automatic fix suggestions** section, or the API's 403 `FEATURE_NOT_LICENSED` | The licence does not list `llm.auto-fix`. On the page, it lapsed while the page was open. Apply a key that lists it, then open the page again |
| "Switching them on needs AI set up on this server and allowed for this organization, with Suggest a fix. …" when saving automatic fix suggestions (the API's 409 `AI_DISABLED`) | An instance admin first connects a provider, allows the organisation and turns on **Suggest a fix**, in **Settings → AI provider** |
| 409 `AUTO_FIX_OPT_OUT_LIMIT_REACHED` | An organisation lists at most 1 000 projects that opted out. Let a project back in first |
| "The project is not mapped to GitLab or GitHub" | Map it in **Settings → Repositories** ([GitLab](./gitlab.md), [GitHub](./github.md)) |

### No automatic fix suggestions

Check, in order:

1. The licence lists `llm.auto-fix`.
2. **Post fix suggestions automatically** is on in **Settings → AI** for the organisation.
3. The organisation may use AI, with **Suggest a fix** on, in **Settings → AI provider**.
4. The project did not opt out and is not excluded from AI.
5. The project is mapped to GitLab or GitHub.
6. The findings are new in this merge request, open and at the minimum severity.
7. No suggestion was made for them before.
8. The daily fix budget is not used up.

### Error codes in the API

`AI_DISABLED` (409), `AI_NOT_ELIGIBLE` (409, with the reason in `detail`), `AI_POST_NOT_POSSIBLE`
(409, with the reason in `detail`), `AI_QUOTA_EXCEEDED` (429 with `Retry-After`) and
`RATE_LIMITED` (429).

A failed request's `error.code` is one of `PROVIDER_TIMEOUT`, `PROVIDER_UNAVAILABLE`,
`PROVIDER_RATE_LIMITED`, `PROVIDER_REFUSED_KEY`, `PROVIDER_WORKSPACE_REQUIRED`,
`PROVIDER_REJECTED_REQUEST`, `PROVIDER_BAD_ANSWER`, `URL_NOT_ALLOWED`, `KEY_UNDECRYPTABLE`,
`MALFORMED_OUTPUT`, `OUTPUT_TRUNCATED`, `MODEL_REFUSED`, `OUTPUT_REFUSED`, `AI_DISABLED`,
`SETTINGS_CHANGED`, `ISSUE_CHANGED`, `ISSUE_GONE` or `REQUEST_ABANDONED`.
