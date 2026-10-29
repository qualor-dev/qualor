# Email

Qualor sends email through an SMTP server you choose: alerts for administrators, [account
emails](#account-emails) such as password reset links, and [project
notifications](#project-notifications) for the projects people watch. Nothing is sent until an
instance administrator or the operator sets up a server. Qualor never tracks whether a message was
opened or a link clicked.

## Set up in Qualor

An instance administrator opens **Settings → Email**:

1. Under **SMTP server**, enter the **Host**, the **Security** and the **Port**, the **Username**
   and **Password** if the server needs them, the **From name** and **From address**, and optionally
   a **Reply-to** address. Press **Save**.
2. Under **Send a test message**, check the address (yours by default) and press **Send test**. The
   page shows the server's answer, or why it refused.

The password is stored encrypted with `QUALOR_SECRET_KEY` and never shown again. **Replace** enters
a new one, and **Remove** deletes it. Saving with an empty **Host** turns email off.

| Security | Port | Use |
|---|---|---|
| STARTTLS | 587 | the usual one: the connection switches to TLS, and Qualor does not send if the server does not offer it |
| TLS | 465 | TLS from the first byte (also called SMTPS) |
| None | 25 | no encryption: only for a relay on your own network |

## Set up with environment variables

The operator can set the server instead. **Settings → Email** then shows it read-only, marked **Set
by the environment**. The alert switches can still be changed there.

| Variable | Meaning |
|---|---|
| `QUALOR_SMTP_URL` | `smtp://user:password@host:587` (STARTTLS), `smtps://user:password@host:465` (TLS), or `smtp://host:25?security=none` (no TLS). Without a port: 587 for `smtp://`, 465 for `smtps://` |
| `QUALOR_SMTP_FROM` | the sender, `Qualor <qualor@example.com>` or just the address. Required with `QUALOR_SMTP_URL` |
| `QUALOR_SMTP_REPLY_TO` | optional: where replies go |

URL-encode special characters in the user name and the password: `@` as `%40`, `:` as `%3A`, `/` as
`%2F`, `%` as `%25`. A mistake in these variables stops the server at start. The message names the
variable, never the password.

| Provider | `QUALOR_SMTP_URL` | Notes |
|---|---|---|
| Microsoft 365 | `smtp://qualor%40example.com:<password>@smtp.office365.com:587` | The mailbox needs SMTP AUTH turned on: Microsoft 365 admin center → the user → Mail → Manage email apps → Authenticated SMTP |
| Gmail or Google Workspace | `smtp://qualor%40example.com:<app password>@smtp.gmail.com:587` | Use an app password of that account, not its normal password. App passwords need 2-step verification |
| Amazon SES | `smtps://<SMTP user name>:<SMTP password>@email-smtp.eu-west-1.amazonaws.com:465` | Use SES's SMTP credentials, not an access key. The From address must be a verified identity |
| A relay on your network | `smtp://postfix.internal:25?security=none` | |

With Docker Compose, add to `.env`:

```sh
QUALOR_SMTP_URL=smtp://qualor%40example.com:<password>@smtp.office365.com:587
QUALOR_SMTP_FROM=Qualor <qualor@example.com>
```

Then uncomment the two `QUALOR_SMTP_…` lines of `compose.yml` ([Install the
server](./install-server.md#the-compose-file)). With Helm, see
[Settings](./install-server.md#settings).

## TLS and private certificate authorities

Qualor always checks the SMTP server's certificate, and speaks TLS 1.2 or later. No setting accepts
a certificate that does not verify. If your mail server's certificate comes from a private
certificate authority, give the server that CA in `NODE_EXTRA_CA_CERTS` ([Server
settings](./install-server.md#server-settings)).

## What Qualor sends

| Message | To | When |
|---|---|---|
| Test message | the address you type | **Send test** in **Settings → Email** |
| Licence expiry | every instance administrator with an email address | 30, 7 and 1 day before the licence expires, when its 14-day grace period starts, and when it ends ([When a licence expires](./enterprise.md#when-a-licence-expires)). A trial key gets three: 7 days and 1 day before the end, and on the end day (no 30-day or grace email). Each once per licence key. A step missed while email was off is not sent late |
| Failing webhook | every instance administrator with an email address, and the organisation's administrators ([below](#failing-webhooks-for-organisation-administrators)) | a delivery of any webhook, Slack and Teams ones too, gives up after its 7 attempts. At most one a day for each webhook, and only for a webhook that is switched on ([Webhooks](./webhooks-and-api.md#webhooks)) |
| Password reset link, invitation, password changed | the account's email address | see [Account emails](#account-emails) |
| Project notifications | everyone who watches the project | its quality gate fails or passes again, or an analysis fails ([Project notifications](#project-notifications)) |

The two alerts for administrators each have a switch in **Settings → Email → Alerts for
administrators**. Both are on by default. An administrator without an email address gets nothing:
add one in **Settings → Users**. The panel says how many administrators have none.

Every message has an HTML part and a plain-text part. Its links lead to the address in
`QUALOR_PUBLIC_URL`. Without it, a message says where to go in Qualor instead, and **Settings →
Email** warns.

## Account emails

Account emails go to the email address on the person's account. The reset and invitation emails
carry a link, so they also need `QUALOR_PUBLIC_URL`. The password-changed notice needs only the SMTP
server. Without `QUALOR_PUBLIC_URL`, it has no link to reset the password.

| Email | Sent when | Details |
|---|---|---|
| **Reset your Qualor password** | someone uses **Forgot password?** on the sign-in page | The link works once, for 60 minutes. It does not sign anyone in: the person signs in with the new password afterwards |
| The inviter's name, then **invited you to Qualor** | an instance administrator invites a new user in **Settings → Users** | The link works once, for 7 days. The admin can resend or revoke it |
| **Your Qualor password was changed** | after a reset through a link, a change of one's own password, or a reset by an administrator | It names the account, the time (UTC) and, for a change the person made, the address it came from |

The secret part of each link comes after `#` in the address, so it never reaches the server's logs,
a proxy or another site. Qualor stores only a hash of it, and deletes a message's body from the
database once the message is delivered.

Without an SMTP server or without `QUALOR_PUBLIC_URL`:

- the sign-in page shows no **Forgot password?**;
- **Settings → Users** creates users with an initial password only;
- an instance admin resets forgotten passwords.

See [Users, projects and tokens](./users-projects-tokens.md#forgotten-passwords-and-invitations).

## Project notifications

Anyone who can see a project can **watch** it, and get an email when something needs them:

| Email | Sent when |
|---|---|
| **Quality gate failed** | the gate of a watched branch becomes Failed, from any other status, also on a branch's first analysis. It lists the failing conditions and counts the new issues by severity |
| **Quality gate passes again** | the gate goes from Failed to Passed, after an analysis or after issues were marked false positive or won't fix (or reopened) |
| **Analysis failed** | Qualor could not process an analysis, for example an invalid report. At most one email per branch every 6 hours. When Qualor cannot tell which branch failed, every watcher of the project gets it |

### Watching a project

On a project's page, press **Watch** (the bell). Watching starts with the main branch and all three
emails. Press **Watching** to change:

- **Main branch**, or **All branches and merge requests**;
- each email on or off: **The quality gate fails**, **The quality gate passes again** and **An
  analysis fails**;
- **Stop watching**.

**Settings → Notifications** lists every project you watch, with the same choices. It also has the
switch for all notification email: **Email me at** your address.

Nobody watches anything until they press **Watch**. Creating a project watches nothing.

### Who gets the email

An email goes to you only while all of these hold:

- You can still see the project: through a role in its organisation, a role on the project, or as
  instance administrator. If you lose access, the emails stop. They start again if you get access
  back.
- Your account is active and has an email address. An instance administrator sets it in **Settings →
  Users**.
- **Email me at …** is on in **Settings → Notifications**.
- Email is set up on the server.

The [read-only demo](./users-projects-tokens.md#a-public-read-only-demo) account never gets email.

### Stopping the emails

Every email ends with **Stop watching this project** and **Notification settings**. Stop watching
works without signing in. In a browser, the link opens a page that asks once, then stops, so a mail
scanner that opens links stops nothing. Mail apps with a one-click unsubscribe button (Gmail, Apple
Mail, Outlook) stop watching in one click, without the question. Without `QUALOR_PUBLIC_URL` the
emails have no links: use **Settings → Notifications** instead.

### Failing webhooks for organisation administrators

Organisation administrators get the failing-webhook email for their organisation's webhooks. Turn it
off in **Settings → Notifications** with **Failing webhooks in organisations I administer**. Turning
off **Email me at …** stops it too. An instance administrator who is also an organisation
administrator gets it once, not twice.

## Delivery, retries and the log

A message is stored in the same database transaction as what it is about, so it is never sent for
something that did not happen. Qualor then sends it in the background, so a slow mail server never
delays analyses.

- A temporary failure is retried 1, 2, 4, 8, 16 and 32 minutes later: 7 attempts over about an hour.
  A temporary failure is a server that cannot be reached or does not answer in time, or a `4xx`
  answer such as greylisting. When the last attempt fails too, the message is **Failed** and stays
  in the log. It is not sent later.
- A permanent failure fails the message at once: a `5xx` answer, a refused password, a certificate
  that does not verify, or STARTTLS not offered.
- A message still waiting after 2 days is given up and failed.

**Recent messages** in **Settings → Email** lists every message with when it was queued, the
recipient, the subject, its status (**Delivered**, **Retrying n/7**, **Failed** or **Pending**) and
the server's answer or the error. A message's body is kept encrypted only while it waits, and
deleted once it was sent or failed. The log keeps the subject, the recipient, the status and the
server's answer for 30 days ([Retention](./install-server.md#retention)).

The API, for instance administrators only ([REST API](./webhooks-and-api.md#rest-api)):

| Route | What it does |
|---|---|
| `GET /api/v0/system/mail`, `PUT /api/v0/system/mail` | the settings. The password is write-only |
| `POST /api/v0/system/mail/test` | sends a test message: `{ "to": "you@example.com" }` |
| `GET /api/v0/system/mail/messages` | the recent messages |

Changing the settings and sending a test are recorded in the [audit
log](./roles-and-audit.md#the-audit-log-enterprise-audit-log).

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| "The SMTP server could not be reached, or the TLS connection to it failed." | a wrong host or port, a firewall (allow the server's outgoing connections to that port; with the Helm NetworkPolicy, add an egress rule), or a certificate that does not verify | check **Host**, **Port** and **Security**; for a private CA, set `NODE_EXTRA_CA_CERTS` |
| "The SMTP server refused the user name or password." | wrong credentials | Microsoft 365: turn on Authenticated SMTP for the mailbox; Gmail: use an app password |
| STARTTLS refused, or "the server does not offer it" | the server speaks implicit TLS, or no TLS | choose **TLS** (port 465), or **None** for a relay on your own network |
| a `5xx` answer such as "relay not permitted" or "sender not allowed" | the server does not let this account send as the **From address** | use an address the account may send from |
| "The stored password can't be decrypted (QUALOR_SECRET_KEY changed): enter it again." under **Password**, or "The stored SMTP password can no longer be read. Enter it again." after **Send test** | `QUALOR_SECRET_KEY` changed | **Replace** the password |
| "The SMTP server did not answer in time." | the server is slow or a firewall drops the connection | check **Host** and **Port**, that the server is up, and the firewall between Qualor and it |
| "The SMTP server refused the message." | the server refused the sender or the recipient without a reply that says why | check the **From address** and the recipient; look at the mail server's own log |
| messages have no links, and the page warns about `QUALOR_PUBLIC_URL` | `QUALOR_PUBLIC_URL` is not set | set it and restart ([Server settings](./install-server.md#server-settings)) |
| an administrator gets no alerts | no email address, the alert is off, or it was sent already (once per licence step, once a day per webhook) | add the address in **Settings → Users**; check the switches; look at **Recent messages** |
| Notifications arrive late, or many watchers get one at once | the email provider limits how fast Qualor may send, and many watchers can reach that limit | nothing: Qualor retries throttled messages for about an hour. **Recent messages** shows them as Retrying |
