# Quick start

This page takes you from nothing to a first analysis in about 15 minutes. You need Linux, macOS or
WSL, with Docker, Compose v2 and `openssl`. Everything runs from the `qualor/server` and
`qualor/scanner` images on Docker Hub.

The fastest path is [Add repositories](#fastest-path-add-repositories): connect GitHub or GitLab,
tick your repositories, and merge one merge request in each. The manual path follows it, for any
other CI system or when you want to see each step.

## 1. Start the server

Create a directory:

```sh
mkdir -p ~/qualor && cd ~/qualor
```

Save the compose file from [Install the server](./install-server.md#the-compose-file) there as
`compose.yml`. Then create the settings with generated secrets, and start:

```sh
umask 077
cat > .env <<EOF
QUALOR_VERSION=0.13
QUALOR_SECRET_KEY=$(openssl rand -hex 32)
QUALOR_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 16)
EOF
docker compose up -d
docker compose ps          # wait until "server" is healthy (15–30 s)
grep BOOTSTRAP .env        # the admin password for the first sign-in
```

Open <http://127.0.0.1:8080> and sign in as `admin` with that password. Then change it: open the
menu under your name at the top right and choose **Change password**. **Forgot password?** works
only once Qualor can send email
([Forgotten passwords](./users-projects-tokens.md#forgotten-passwords-and-invitations)).

The server listens on `127.0.0.1` only. To reach it from other machines, put TLS in front of it
([Reverse proxy and TLS](./install-server.md#reverse-proxy-and-tls)).

## Fastest path: Add repositories

An organization admin does this in the UI. Qualor creates the projects and sets up CI for them.

1. Connect GitHub ([GitHub](./github.md#3-the-github-app)) or GitLab
   ([GitLab](./gitlab.md#3-merge-request-comments-and-commit-status)). For CI setup, also set
   `QUALOR_PUBLIC_URL` on the server, turn on **Allow Qualor to set up CI** on a GitLab connection,
   or give a GitHub App **Contents**, **Workflows** and **Secrets** (each Read and write).
2. Open **Projects → Add repositories**, pick the connection and tick up to 50 repositories.
   Repositories that already have a project are marked. An archived repository cannot be picked.
3. Leave **Set up CI with a merge request** on, and start. Qualor creates a project for each
   repository, with the repository path as its key and the organization's default gate and profiles.
   A project that already has that key and no repository is mapped to the repository and keeps its
   history.
4. Merge the merge request in each repository. The first analysis runs when the pipeline of the
   merged commit finishes.

Qualor opens a merge request only when it can edit the CI files safely. Otherwise, and when you turn
CI setup off, it shows the snippet to add and the project token, once. Copy the token then: it is
not shown again. What the merge requests contain, and how to undo them, is in
[GitHub](./github.md#set-up-ci-with-a-pull-request) and
[GitLab](./gitlab.md#set-up-ci-with-a-merge-request).

### The setup checklist

Organization admins see **Set up Qualor** in a corner of the screen. Its steps are Connect GitHub or
GitLab, Add repositories, Get the first analysis, Turn on AI review and Invite your team. Each step
ticks by itself from the server's state and links to the page where you do it. Collapse the list, or
choose **Don't show again** to hide it for good. When only a server admin can set up an AI provider,
the AI step says so and does not count.

## Or by hand

The steps below do the same without Add repositories. Use them for CI systems other than GitHub and
GitLab, or to see each part.

### 2. Pull the scanner

```sh
docker pull qualor/scanner:0.13
```

It is about 4.1 GB, 1.4 GB of which is Trivy's vulnerability database. CI runners pull it the same
way.

### 3. Create a project and a token

1. **Projects → New project.** The **Key** identifies the project in every scan. By default the
   scanner uses the CI project path as the key: `CI_PROJECT_PATH` on GitLab (`group/app`),
   `GITHUB_REPOSITORY` on GitHub (`owner/repo`). Use the same value here and you need no config
   file.
2. The main branch is `main`, and analyses of every other branch are compared with it. If your
   default branch has another name, such as `master`, change it before the first scan in
   **Project → Settings → Main branch** ([Projects](./users-projects-tokens.md#projects)).
3. **Settings → Access tokens → New token**, with the scope **Upload analyses**. Copy the token: it
   is shown only once.

For CI, a [project analysis token](./users-projects-tokens.md#project-analysis-tokens) is safer: it
can only upload to its own project.

### 4. Run a first scan locally

From the root of any git repository you want to analyse:

```sh
cd /path/to/your/repo
docker run --rm --network host \
  -v "$PWD":/src -w /src \
  -e QUALOR_URL=http://127.0.0.1:8080 \
  -e QUALOR_TOKEN=<token> \
  -e QUALOR_PROJECT_KEY=<project key> \
  qualor/scanner:0.13 scan
```

`--network host` lets the container reach the server on `127.0.0.1`, on Linux. With Docker
Desktop, use `QUALOR_URL=http://host.docker.internal:8080` instead.

The scanner runs the analyzers that fit your code, uploads the report and prints the gate verdict.
A first analysis of the main branch has no new code, so it passes the default gate. Open the
project in the UI to see its issues, coverage, duplication and size.

Some analyzers need the project prepared first. For JavaScript or TypeScript, install the
dependencies (`npm ci`): ESLint runs from the project's own `node_modules`, with its own config.
For Java, build first (`mvn -DskipTests package`): SpotBugs reads compiled classes. See
[Languages and analyzers](./languages-and-analyzers.md).

### 5. Put it in CI

- GitLab: [GitLab](./gitlab.md)
- GitHub: [GitHub](./github.md)
- Anything else: [Other CI systems and local scans](./other-ci.md)

From then on, every merge request or pull request gets a verdict on the code it changes, and the
pipeline fails when the gate fails. Once the GitLab or GitHub connection is set up, reviewers also
see a summary comment and comments on the changed lines.

## What next

- Tune what "good" means: [Quality gates, profiles and issues](./quality-gates.md).
- Coming from SonarQube: [Migrating from SonarQube](./migrate-from-sonarqube.md).
- Let a model review your merge requests: [AI review](./ai-review.md).
- Let an AI agent do the rollout: [AI prompts](./ai-prompts.md).
