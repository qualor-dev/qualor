# Quick start

This page takes you from nothing to a first analysis in about 15 minutes. You need Linux, macOS or
WSL, with Docker, Compose v2 and `openssl`. Everything runs from the `qualor/server` and
`qualor/scanner` images on Docker Hub.

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

## 2. Pull the scanner

```sh
docker pull qualor/scanner:0.13
```

It is about 4.1 GB, 1.4 GB of which is Trivy's vulnerability database. CI runners pull it the same
way.

## 3. Create a project and a token

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

## 4. Run a first scan locally

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

## 5. Put it in CI

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
