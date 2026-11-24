# The support bundle

The support bundle is one zip file with what we need to help you: the versions, the configuration
without secrets, the health of the database and the recent failures. You download it, can read
every file in it, and decide whether to send it. Qualor never sends it anywhere.

It needs a Business or Enterprise licence key that lists the feature `support-bundle` (see
[Enterprise](./enterprise.md)).

## What is in it

The file is named `qualor-support-<yyyymmdd-hhmmss>.zip` and is at most 20 MiB. Every file in it is
UTF-8 JSON, except `logs.jsonl`, which holds one JSON log line per line.

| File | What it holds |
| --- | --- |
| `manifest.json` | when the bundle was made, whether by the web UI or the command, which server replica made it, the files in it, and notes on what was cut or could not be collected |
| `versions.json` | the server, Node.js and PostgreSQL versions, whether the database is embedded or external, the platform, whether it runs in a container, the uptime, the memory and the number of CPUs |
| `license.json` | the edition, the state (`active`, `grace`, `expired` or `none`), the licence id, the customer, the dates, and the features listed and active. **Never the key** |
| `plugins.json` | the enterprise plugins that loaded, or why one did not |
| `migrations.json` | the applied database migrations, and how many are pending |
| `config.json` | the effective configuration. Only settings that are safe to share are shown (port, log level, worker settings, retention, switches, the kind of database); every other one shows `[set]` or `[unset]`. A URL keeps only its scheme, host and port |
| `settings.json` | the settings saved in the database, shown the same way: for example the AI provider's kind, model and host, and which organisations may use AI, but never a key |
| `health.json` | the readiness checks, the database pool, the database size, and the estimated row counts of the 15 largest tables |
| `jobs.json` | the number of jobs by queue and status, and the last 50 failed jobs with their error text (cut to 500 characters, no job data) |
| `analyses.json` | the last 50 failed analyses: the project key, the branch, the time and the error |
| `scm.json` | the GitLab, GitHub and Azure DevOps connections: host, status, the state of the circuit breaker and the last error. No token, private key or webhook secret. The command's bundle has no live connection state, and its manifest says so |
| `logs.jsonl` | the last server log lines of the replica that made the bundle, oldest first: at most 5 000 lines and 5 MiB. Only in a bundle downloaded from the web UI |

**Never in it:** passwords, tokens and their hashes, `QUALOR_SECRET_KEY`, the database password,
API keys (the AI provider's, SCM tokens), webhook and stream secrets, single sign-on client secrets
and keys, the licence key, source code, issue messages, comments, AI prompts and answers.

Error texts and log lines are also checked against the secret values this server is configured
with, and a match is replaced by `[redacted]`. A bundle over 20 MiB loses its oldest log lines
first, then its oldest failed jobs, then its oldest failed analyses. `manifest.json` says what was
cut.

## Download it from the web UI

An instance admin opens **Settings → Support** and selects **Download support bundle**. The page
appears only for instance admins, on a server whose licence lists `support-bundle`. Through the
API, `GET /api/v0/ee/support/bundle` returns the zip to an instance admin, as an attachment.

- One bundle is prepared at a time on a server. The download is a plain link, so the browser shows
  a refusal as a failed download or a small error page (see [Troubleshooting](#troubleshooting)).
- With several replicas, the logs come from the replica that served your request. To see another
  replica's, download again, or run the command below on it.
- **Each download is recorded in the audit log** as `support.bundle_downloaded`, with who
  downloaded it and the size ([Roles and the audit log](./roles-and-audit.md#what-is-recorded)).
  The feature `audit-log` is in both plans.

## When the web UI is down

For a server that will not start, or that you cannot sign in to, a command in the server image
makes the same bundle. Run it in the folder of your Docker Compose file
([Install the server](./install-server.md#the-compose-file)), with `-T`. The zip goes to the
standard output, and the command refuses to write it to a terminal.

```sh
# while the server is running
docker compose exec -T server /usr/local/bin/node dist/main.js support-bundle > qualor-support.zip

# while the server is stopped
docker compose run --rm -T server support-bundle > qualor-support.zip
```

The command uses the server's own configuration and licence key, so it works only where the server
would. `--out <file>` writes the zip to a file inside the container instead of the standard output.
That is mostly useful with `docker compose run` and a mounted folder.

The command's bundle has **no logs**. Add them yourself from the server container, and read them
before you send them. They carry the redaction the server writes them with.

```sh
docker compose logs --no-color --tail 5000 server > qualor-server.log
```

`docker logs --tail 5000 <container>` does the same.

How the command behaves:

- It **never changes the database** and records **no audit event**, because nobody is signed in.
  It starts no web server, no workers and no update check, and runs no migrations.
- With the embedded database, it uses the database of the running server. While the server is
  stopped, it starts the database for a moment and stops it again. It never creates a database.
- If migrations have not run yet, the command still writes what it can. `migrations.json` shows how
  many are pending, and a section it cannot read holds the error instead of its data. A database
  that was never set up gives no bundle.

| Exit code | Meaning |
| --- | --- |
| 0 | the zip was written |
| 1 | any other failure |
| 2 | the licence does not include `support-bundle`, or there is no licence |

The message is on the standard error.

## Send it to us

Email the zip, and the log file, to <support@qualor.dev>, with what went wrong and when. Support is
part of the Business and Enterprise plans ([Enterprise](./enterprise.md#plans-and-prices)).

## When the licence lapses

Without `support-bundle`, the **Support** page leaves **Settings**, the route answers 403
`FEATURE_NOT_LICENSED`, and the command exits with 2. Nothing is deleted. A renewed key brings it
back at the next start.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| the command says `the bundle is a zip archive: redirect standard output to a file` | it ran without `-T`, or without `>` or `--out`. Redirect the output to a file |
| the command exits with 2 | the licence does not list `support-bundle`, or it lapsed. Check **Settings → Licence** or the server log |
| the command exits with 1 and names `QUALOR_LICENSE_FILE` | the licence file cannot be read. Check the path and the file's permissions |
| the command says a Qualor server `holds` the data folder, `but its database did not answer` | the server is starting or has just stopped. Wait for it, or 30 seconds, and run it again |
| the command says `no Qualor server is running` on the folder `and it holds no database` | the volume is empty or wrong. Check the `data` volume of your `compose.yml` |
| the download answers 429 `RATE_LIMITED` | another bundle is being prepared. Try again in a moment |
| the download answers 403 | you are not an instance admin, or the licence has no `support-bundle` |
| `manifest.json` has a note `could not be collected` | one section failed and holds its error. The rest is complete |
