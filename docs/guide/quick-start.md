# Quick start

This page takes you from nothing to a first analysis in about 15 minutes. You need a Linux or macOS
machine (or WSL) with Docker and Compose v2, and `openssl`. Everything runs from the images on Docker
Hub: `qualor/server` and `qualor/scanner`.

## 1. Start the server

```sh
mkdir -p ~/qualor && cd ~/qualor
```

Save the compose file from [Install the server](./install-server.md#the-compose-file) there as
`compose.yml`. Then create the settings with generated secrets, and start:

```sh
umask 077
cat > .env <<EOF
QUALOR_VERSION=0.6
QUALOR_SECRET_KEY=$(openssl rand -hex 32)
QUALOR_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 16)
EOF
docker compose up -d
docker compose ps          # wait until "server" is healthy (15–30 s)
grep BOOTSTRAP .env        # the admin password for the first sign-in
```

Open <http://127.0.0.1:8080> and sign in as `admin` with that password. Then change it: open the
menu under your name at the top right and choose **Change password**. The server listens on `127.0.0.1` only. To reach it from other
machines, put TLS in front of it ([Install the server](./install-server.md#reverse-proxy-and-tls)).

## 2. Pull the scanner

```sh
docker pull qualor/scanner:0.6
```

It is about 4.1 GB, and 1.4 GB of that is Trivy's vulnerability database. CI runners pull it the same
way.

## 3. Create a project and a token

1. **Projects → New project.** The **key** identifies the project in every scan. By default the
   scanner uses the CI project path as the key: `CI_PROJECT_PATH` on GitLab (`group/app`) or
   `GITHUB_REPOSITORY` on GitHub (`owner/repo`). Use the same value here, and you need no config file.
   The project's main branch is `main`. Analyses of any other branch are compared with it. If your
   default branch has another name, such as `master`, rename it through the API:
   `PATCH /api/v0/projects/<id>` with `{"mainBranchName":"master"}`. See
   [Users, projects and tokens](./users-projects-tokens.md#projects).
2. **Settings → Access tokens → New token**, with the scope **Upload analyses**. Copy the token now,
   because it is shown only once.

For CI, a project analysis token is safer: it can only upload to its own project. See
[Users, projects and tokens](./users-projects-tokens.md#project-analysis-tokens).

## 4. Run a first scan locally

From the root of any git repository you want to analyse:

```sh
cd /path/to/your/repo
docker run --rm --network host \
  -v "$PWD":/src -w /src \
  -e QUALOR_URL=http://127.0.0.1:8080 \
  -e QUALOR_TOKEN=<token> \
  -e QUALOR_PROJECT_KEY=<project key> \
  qualor/scanner:0.6 scan
```

`--network host` lets the container reach the server on `127.0.0.1`. That works on Linux. With Docker
Desktop, use `QUALOR_URL=http://host.docker.internal:8080`.

The scanner runs the analyzers that fit your code, uploads the report and prints the gate verdict. A
first analysis of the main branch has no new code, so it passes the default gate. Open the project in
the UI to see the issues, coverage, duplication and size.

A JavaScript or TypeScript project needs its dependencies installed first (`npm ci`), because ESLint
runs from the project's own `node_modules` and with its own config. A Java project needs to be built
first (`mvn -DskipTests package`), because SpotBugs reads compiled classes. See
[Languages and analyzers](./languages-and-analyzers.md).

## 5. Put it in CI

- GitLab: [GitLab](./gitlab.md)
- GitHub: [GitHub](./github.md)
- Anything else: [Other CI systems and local scans](./other-ci.md)

From then on, every merge request or pull request gets a verdict on the code it changes. The pipeline
fails when the gate fails. With the SCM connection set up, reviewers also see a summary comment and
comments on the changed lines.

## What next

- Tune what "good" means: [Quality gates, profiles and issues](./quality-gates.md).
- Coming from SonarQube: [Migrating from SonarQube](./migrate-from-sonarqube.md).
- Let an AI agent do the rollout: [AI prompts](./ai-prompts.md).
