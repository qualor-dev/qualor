# Slack and Microsoft Teams notifications

Qualor posts to a Slack or Microsoft Teams channel when the quality gate of a project's main branch
fails, when it passes again, when a vulnerability in a tracked version is exploited, and once a week
with a security digest. Messages link back to Qualor.
For a receiver of your own, use a generic webhook ([Webhooks and REST API](./webhooks-and-api.md)).

Organisation administrators set it up, for every project of the organisation or for one project. A
Slack or Teams webhook counts toward the organisation's 50 webhooks.

## What arrives

| Message | When |
|---|---|
| **Quality gate failed** | the main branch's gate becomes failed, after a new analysis or a changed issue status. It lists up to five failing conditions, the new issues on new code by security, reliability and maintainability, the commit, and an **Open in Qualor** button |
| **Quality gate passes again** | the main branch's gate passed after it had failed |
| **Exploited vulnerability** | at once, when a vulnerability in a tracked version or tracked branch is in the CISA KEV catalog. Each one posts once. Business and Enterprise. It lists the project, the vulnerability, the package and installed versions, the fix, the targets and the KEV date, for up to 10 vulnerabilities, then a count. A run makes one post per webhook. A webhook added later gets none of the earlier posts |
| **Weekly security digest** | every Monday from 09:00 in the webhook's time zone (below): new security issues of the last 7 days by severity, open security issues, the gate of every project that needs attention (up to 20, then a count), and the three most severe new issues. With Business or Enterprise it also has the section **Vulnerabilities in tracked versions**: the new High and Critical vulnerabilities of the week, counted per project (up to 10 projects), with the KEV count |

The webhook's time zone defaults to the browser's when you create the webhook, and can be any IANA
zone such as `Europe/Berlin` or `UTC`. The digest covers the 7 days that end that Monday at 09:00.
A week with no new security issue, no new High or Critical vulnerability and no failing gate sends
nothing. A Monday the server was down all day is skipped.

The first exploited post can list the KEV vulnerabilities already present, once, as the
[exploited email](./email.md#vulnerability-emails) does.

Webhooks with the weekly digest got the event `vulnerabilities.exploited` when the server was
upgraded. To stop the posts, send `PATCH /api/v0/webhooks/{id}` with the events you keep. `PATCH`
replaces the whole list, so name every event that stays:

```json
{"events":["gate.failed","gate.recovered","digest.weekly"]}
```

You can also create the webhook again ([Webhooks and REST API](./webhooks-and-api.md#webhooks)).
The UI cannot edit a webhook's events.

Merge requests and other branches never post to the channel. Each person can still watch a project
by email ([Email](./email.md)).

Messages link to Qualor only when the server knows its address, `QUALOR_PUBLIC_URL`
([Install the server](./install-server.md)). Without it messages have no buttons or links, and the
**New webhook** dialog says so.

## Slack

1. Open <https://api.slack.com/apps> and create an app: **Create New App**, then **From scratch**.
   Name it `Qualor` and pick your workspace.
2. In the app's settings, open **Incoming Webhooks** and switch **Activate Incoming Webhooks** on.
   Press **Add New Webhook to Workspace**, choose the channel and press **Allow** (or
   **Authorize**). For a private channel you must be a member.
3. Copy the **Webhook URL** (`https://hooks.slack.com/services/…`).
4. In Qualor, open **Settings → Webhooks → New webhook**, or **Project → Settings → Webhooks** for
   one project. Choose **Slack**, paste the URL, keep the events, choose the time zone of the
   digest, and press **Add webhook**.
5. Press **Send test** on the new webhook. The channel shows "Qualor is connected".

A Slack Workflow Builder webhook (`https://hooks.slack.com/triggers/…`) also works. Give its trigger
one text variable named `text`, and use it in the workflow's message step. Workflow messages show
the summary line only.

## Microsoft Teams

Teams receives messages through a **Workflows** webhook. Qualor does not accept Office 365 connector
URLs (`….webhook.office.com`): Microsoft retired those connectors in May 2026.

1. In Teams, select **More options (…)** next to the channel, then **Workflows**.
2. Choose the template **Send webhook alerts to a channel**: a workflow that starts with "When a
   Teams webhook request is received" and posts to a channel. Check the team and channel, and press
   **Save**.
3. Copy the webhook link it shows (`https://….environment.api.powerplatform.com/…`).
4. In Qualor, press **New webhook**, choose **Microsoft Teams**, paste the link, choose the time
   zone, and press **Add webhook**.
5. Press **Send test**. The channel shows a card "Qualor is connected".

An Azure Logic Apps workflow with an HTTP trigger that posts cards to Teams also works: Qualor
accepts its `….logic.azure.com` URL.

A workflow belongs to the person who created it. If they leave, the webhook stops, so add a co-owner
in the Workflows app.

## Security

- The webhook URL is a secret: anyone who has it can post to your channel. Qualor stores it
  encrypted and shows only its end (`https://hooks.slack.com/services/T…/…/abcd`). To change it,
  create a new URL in Slack or Teams, add a new webhook in Qualor and delete the old one.
- Qualor accepts only the Slack and Teams webhook hosts here. The rules of every webhook apply too:
  public addresses only, and no credentials in the URL.
- Messages carry project names, branch names, rule names, issue messages and file paths, never code.

## Troubleshooting

| What you see | What to do |
|---|---|
| "Use a Slack incoming webhook URL" | Paste the URL from **Incoming Webhooks**, not a channel link or an app's OAuth token |
| "Office 365 connectors are retired" | Create a Workflows webhook as above |
| "Use a Teams Workflows webhook URL" | Paste the link the workflow shows (`….environment.api.powerplatform.com`) |
| A delivery says "The Slack webhook no longer exists; create a new one" (or Teams) | The app, the webhook or the workflow was removed, or the channel archived. Create a new URL and a new webhook in Qualor |
| Deliveries fail with HTTP 403 or `action_prohibited` | A Slack admin restricts posting to that channel |
| Teams deliveries fail with HTTP 429 | Teams accepts at most 4 requests a second per webhook; Qualor retries |
| No digest on Monday | A week with nothing new and every gate passing sends nothing. Otherwise check that the webhook is switched on and subscribes to **Weekly security digest** |
| "The webhook URL cannot be decrypted" | `QUALOR_SECRET_KEY` changed. Delete the webhook and add it again with its URL |

Failed deliveries are retried, listed under **Recent deliveries**, and alert the administrators by
email after the last attempt, as for every webhook ([Webhooks](./webhooks-and-api.md#webhooks)).
