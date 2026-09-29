# AI assistant

Qualor can ask a language model about one issue at a time. It is optional, **off by default**, and
uses a model you choose, with your own key: a hosted provider or a local model on your own network.

## What it does

In the issue view, the **AI assistant** panel offers three actions. Each one runs only when a person
clicks it, for that one issue.

- **Explain**: what the rule checks, why this code triggers it, the risk, and how to fix it.
- **Suggest triage**: whether the finding looks like a false positive, with a verdict ("Likely a
  false positive", "Likely a true positive" or "Uncertain"), a confidence and up to five reasons.
  It is only a suggestion: the model never changes an issue. A person who agrees clicks **Mark as
  false positive…**, which opens the usual status change with an empty comment. They write their
  own reason, as always, and the issue's changelog records that the AI suggestion was shown and
  that the decision was theirs.
- **Suggest a fix**: a replacement for the flagged lines, shown as before and after. On a merge
  request or pull request mapped to GitLab or GitHub, a person can click **Post to merge request**.
  Qualor then posts it as a GitLab suggestion or a GitHub suggested change, which a person reviews
  and applies there. Qualor never commits, pushes or opens a branch or merge request of its own.

Every answer is labelled "AI-generated, may be wrong", with the model's name and the time. Answers
are shown as plain text: links, Markdown and HTML in them are never rendered.

A fix is posted only when all of these hold. Otherwise the panel says why nothing was posted:

- the merge request's head is still the commit Qualor analysed (after a newer push, analyse it and
  ask again);
- the lines to replace are lines the merge request added, and they are unchanged;
- the issue is still open, and the assistant and its fix feature are still enabled.

Posting the same suggestion twice posts it once. Qualor needs no extra GitLab scope or GitHub App
permission for this: the token or App that comments on merge requests posts the suggestion.

Triage and fix need an **open** issue. A fix also needs the issue's file, line and the code around
it.

## What is sent, and where

Nothing is sent to any model until an instance admin has configured a provider **and** enabled
the organisation **and** the feature, **and** a person clicks. No scan, merge request comment or
background job ever calls a model by itself, and the scanner (the CLI) never contacts a model: only
the server does.

For the one issue a person asks about, the server sends:

- the rule: its key, name, description and CWE numbers;
- the issue's severity, quality and kind, and its message;
- the file path, the lines and the language;
- the code around the issue that the scan already stored: the flagged lines with up to 3 lines of
  context on each side.

**Secrets are redacted first.** The scanner already replaces the secrets its analyzers find with
`«redacted»`. The server then redacts again, before anything leaves: private keys, cloud and SCM
tokens, API keys, JSON Web Tokens, passwords in URLs, `Authorization` headers, and values assigned
to names such as `password`, `secret`, `token` or `api_key` (in code, `.env` and YAML files,
properties, Dockerfiles, connection strings and XML).

**Never sent at all:**

- issues of secret-detection rules (Gitleaks, and rules about credentials in code);
- issues in files that look like credentials: `.env` files, keys and certificates (`*.pem`, `*.key`,
  `*.p12`, `*.pfx`, `*.jks`, `*.ppk`), `id_rsa` and similar, `credentials*`, `.npmrc`, `.pypirc`,
  `.netrc`, `.git-credentials`, `.pgpass`, `.htpasswd`, Docker and Kubernetes configs, Terraform
  variables and state, `secrets.yml`. A source extension is no exception: `credentials.js` is not
  sent either;
- issues of an excluded project or on an excluded path;
- the names of the project, organisation and branch, commit SHAs, users and changelog comments.

The **What is sent** panel in the settings, and a notice in the issue view's panel, name these
fields together with the provider's host and model.

## Configuration

### The provider (instance admins)

An instance admin opens **Settings → AI assistant** and configures one provider for the whole
instance:

| Setting | What to enter |
|---|---|
| Kind | **OpenAI-compatible** (OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio and other servers with the chat completions API) or **Anthropic** |
| Base URL | with the version path for OpenAI-compatible servers: `https://api.openai.com/v1`, `https://<resource>.openai.azure.com/openai/v1`, `http://ollama:11434/v1`. Anthropic: `https://api.anthropic.com` |
| Model | the model's name as the provider spells it |
| API key | write-only. It is stored encrypted and never shown again. Leave it empty for a local model without a key |
| Key header | `Authorization: Bearer` (the default), or `api-key` for Azure |
| JSON mode | on by default. Turn it off for a server that refuses `response_format` |
| Output limit field | `max_tokens` (the default), or `max_completion_tokens` for OpenAI's newer models, which refuse `max_tokens` |
| Temperature | optional; not sent when empty |
| Timeout (seconds) | 5–600, default 60, for the whole request |

Press **Test**. It sends a fixed prompt that holds no repository data to the saved provider, and
shows the model's name and the latency, or what went wrong.

- For Azure OpenAI, use the v1 API's base URL. The older per-deployment URLs
  (`/openai/deployments/<name>/…?api-version=`) are not supported.
- **Changing the base URL needs the key again**, so a stored key is only ever sent to the address
  it was entered for. **Remove the key** deletes it.
- The key is encrypted with `QUALOR_SECRET_KEY`. After that key changes, set the API key again.
- The address must be `https` and resolve to public addresses, unless the operator lists the host
  in `QUALOR_LLM_INTERNAL_HOSTS` (see [a local model](#a-local-model-with-ollama)). Redirects are
  not followed, and no proxy is used.

### Organisations and projects

On the same page, per organisation, the instance admin chooses:

- **Enabled**: nothing of an organisation is ever sent while it is off. Organisations start off.
- the features: **Explain**, **Suggest triage** and **Suggest a fix**, each off until checked;
- excluded projects, whose issues are never sent.

**Never send these paths** takes up to 100 globs (such as `legacy/**` or `**/*.generated.ts`),
matched against the issue's path in every organisation.

The AI assistant panel appears in the issue view only for an enabled organisation, and each action
only when its feature is on and the issue can be sent. Any member of the organisation can ask and
post, as for changing an issue's status: signed in, or with a token that has the `write` scope (see
[Users, projects and tokens](./users-projects-tokens.md)).

## A local model with Ollama

To keep code on your own network, run [Ollama](https://ollama.com) next to the server. Qualor talks
to Ollama's OpenAI-compatible API at `/v1`.

1. Add an `ollama` service to the [`compose.yml`](./install-server.md#the-compose-file) of the
   server, with a volume for its models and no published port:

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

   The guide's `compose.yml` passes this variable to the server. It is a list separate from
   `QUALOR_SCM_INTERNAL_HOSTS`: listing a GitLab does not let the model point at it, nor the reverse.

3. Start it and download a model into the volume:

   ```sh
   docker compose up -d
   docker compose exec ollama ollama pull <model>
   ```

4. In **Settings → AI assistant**, choose **OpenAI-compatible**, base URL `http://ollama:11434/v1`,
   the model's name as `ollama list` shows it, and no API key. Press **Test**, then enable the
   organisations and features you want.

A local model on a CPU can be slow. If requests end with "The model did not answer in time", raise
the timeout (up to 600 s). Give Ollama the memory its model needs. vLLM and LM Studio are set up the
same way, with their own host and port in `QUALOR_LLM_INTERNAL_HOSTS`.

To run the server with its database on a separate network with no route out, as the repository's
own `deploy/docker-compose.yml` does, see "A local model with Ollama" in
[`deploy/README.md`](../../deploy/README.md#a-local-model-with-ollama).

## Budgets and limits

The instance admin sets daily budgets per organisation (UTC days) under **Budgets per organisation
and day (UTC)**:

| Budget | Default |
|---|---|
| Explanations | 200 a day |
| Triage suggestions | 100 a day |
| Fix suggestions | 25 a day |
| Tokens (sent and received) | 1 000 000 a day |
| Estimated cost in US dollars | off. It needs the model's prices per million tokens, which you enter |
| Requests per person | 30 an hour, all features together |

**The community edition allows at most 25 fix suggestions per organisation per day**, whatever the
fix budget says. Posting a suggestion to a merge request does not count again. Explanations and
triage have no community ceiling: your budgets apply, since it is your key. With an
[enterprise licence](./enterprise.md) your fix budget is the only limit. The hint under the field
says the ceiling of the edition the server runs as.

If a licence lapses, a fix budget above 25 that you saved stays saved: the ceiling of 25 applies
when suggestions are made, and the saved budget applies again with a renewed key. Until then you
can save the rest of the page with that budget unchanged, or lower it, but not raise it.

An organisation over a budget gets "The organisation's AI budget for today is used up" until the
next UTC midnight. A person over the hourly bound gets "You asked too often; try again in a few
minutes".

**Cache.** An answer is kept for the issue for 30 days. Asking again for the same issue, with the
same code, rule and model, shows the stored answer at once, sends nothing and costs no budget.
**Ask again** sends a new request and counts against the budget.

Each server process runs at most two requests at once, and at most one per organisation, so one busy
organisation cannot hold up the others. A slow or unavailable provider never delays analyses, gates or merge
request comments.

## Retention and audit

The server records every request sent to the provider: who asked, for which issue, the feature,
the provider's host and model, the size and a hash of what was sent, the names of the fields sent,
the number of redactions, the status, the token counts, the estimated cost when prices are set, and
the duration. It never records the API key, and it does not record the content sent unless you ask
it to:

- **Store the prompts sent** (off by default) keeps the exact redacted data sent, for 1–90 days
  (**Days to keep them**, default 7).
- The answer is kept, since the issue view shows it and a fix is posted from it. For a fix, the
  lines it replaces are kept with it, to check them against the merge request before posting.
- Request records are deleted after **90 days**, or with their organisation or project.
- Each finished request also writes one log line with the same details, never the content or the
  key. When the provider answered with an error, the line has its HTTP status (`providerStatus`).

Today's use and budgets for an organisation are at `GET /api/v0/organizations/{id}/ai`.

## Troubleshooting

| Message | What to do |
|---|---|
| "The model did not answer in time" | raise the timeout in the settings; a local model on a CPU needs more |
| "The model provider could not be reached" | check the base URL and that the server can reach the host. After 5 failures in a row Qualor pauses calls to that address for 10 minutes |
| "The model provider is rate limiting Qualor; try later" | the provider's own limit. Qualor retries after the time the provider asks for; try again later, or lower the budgets |
| "The provider refused the API key (HTTP 401)" | set a valid key; check the key header (`api-key` for Azure) |
| "The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit" | the key is valid but may not use this model: check the model's name, the key's project or workspace permissions, and the account's billing or credit |
| "The provider refused the request; check the base URL and the model" | an OpenAI-compatible base URL usually needs `/v1`; check the model's name. OpenAI's newer models need the `max_completion_tokens` output limit field; some servers need JSON mode off |
| "The provider's answer was not understood" | the address is not a chat completions or Anthropic Messages API, or the answer was over 1 MiB |
| "The provider's address is not allowed" | the operator lists the host with its port in `QUALOR_LLM_INTERNAL_HOSTS`, or use an `https` address that resolves to public addresses |
| "The stored API key can no longer be read; set it again" | `QUALOR_SECRET_KEY` changed. Enter the API key again |
| "The model's answer could not be used" | the model did not answer with the expected JSON, or its answer was cut off. Ask again, or try another model |
| "The model declined to answer" | the provider's content filter or the model refused |
| "The suggested fix was not safe to show" | the fix broke a safety rule (outside the shown lines, a secret, control characters, or a GitLab quick action). Ask again or fix it by hand |
| "The AI assistant is not enabled for this organisation" | an instance admin enables the organisation and the feature |
| "Findings of secret rules are never sent" / "Issues in credential files are never sent" | by design. Handle these issues without the assistant |
| "An administrator excluded this issue's path or project" | by design; an instance admin can change the exclusions |
| "Something changed since you asked; ask again" | the settings or the issue changed (a new analysis) while the request waited |
| "The request was interrupted; ask again" | the server restarted, or the request failed unexpectedly, while it ran |
| "Not posted: the merge request has a newer commit" | analyse the latest commit, then ask for a new fix |
| "Not posted: the lines are not added lines of the merge request" / "the code on the merge request differs" | suggestions can only replace lines the merge request added, unchanged. Fix it by hand |
| "The project is not mapped to GitLab or GitHub" | map it in **Settings → GitLab** or **GitHub** ([GitLab](./gitlab.md), [GitHub](./github.md)) |

Error codes in the API: `AI_DISABLED` (409), `AI_NOT_ELIGIBLE` (409, with the reason in `detail`),
`AI_POST_NOT_POSSIBLE` (409, with the reason in `detail`), `AI_QUOTA_EXCEEDED` (429 with
`Retry-After`) and `RATE_LIMITED` (429). A failed request's `error.code` is one of `PROVIDER_TIMEOUT`,
`PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_REFUSED_KEY`,
`PROVIDER_REJECTED_REQUEST`, `PROVIDER_BAD_ANSWER`, `URL_NOT_ALLOWED`, `KEY_UNDECRYPTABLE`,
`MALFORMED_OUTPUT`, `OUTPUT_TRUNCATED`, `MODEL_REFUSED`, `OUTPUT_REFUSED`, `AI_DISABLED`,
`SETTINGS_CHANGED`, `ISSUE_CHANGED`, `ISSUE_GONE` or `REQUEST_ABANDONED`.
