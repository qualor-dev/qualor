# Security policy

## Reporting a vulnerability

Email **security@qualor.dev**, or report it privately on GitHub: open the Qualor repository
(<https://github.com/qualor-dev/qualor>) and choose **Security → Report a vulnerability**.
Please do not open a public issue, merge request or pull request for a vulnerability.

Include what you found, the affected version or commit, how to reproduce it, and what an attacker
gains. There is no PGP key; send the report as plain email.

What to expect:

- an acknowledgement within **3 working days**;
- an assessment (whether it is a vulnerability, its severity, and a plan) within **10 working
  days**;
- a fix and a coordinated disclosure within **90 days** of the report, sooner when the fix is
  ready, with credit to you unless you prefer otherwise.

## Scope

Everything in the Qualor repository (the server, the web UI, the `qualor` CLI,
`packages/shared`, the CI templates and integrations, the Helm chart, and `enterprise/`), and the
published images `qualor/server`, `qualor/scanner` and `qualor/scanner-dotnet`. Vulnerabilities in
the analyzers Qualor runs (ESLint, PMD, SpotBugs, OpenGrep, Gitleaks, Trivy, Roslyn) belong to their
projects; tell us too if Qualor's use of them makes things worse.

## Supported versions

The first release is 0.1.0. While Qualor is in 0.x, security fixes go into the latest minor
release only (for example `0.17.z`); the minor tag (`qualor/server:0.17`) follows it. There is no
floating `0` tag, because a 0.x minor release may change behaviour. From 1.0 on, fixes go into the
latest minor release of the latest major version, and the major tag (`qualor/server:1`) follows
it.

## Verifying a release

Every release since 0.1.0 is signed with cosign: the images, the Helm chart, and the release
files through their `SHA256SUMS`. The public key is `cosign.pub` in the Qualor repository and at
<https://qualor.dev/cosign.pub>. Verify with that key, not with the copy a release carries.

Every command below carries `--insecure-ignore-tlog=true`. The signatures are checked against our
public key only and are not recorded in the public Rekor transparency log, so without the flag
cosign looks for a log entry and fails.

```sh
cosign verify --key https://qualor.dev/cosign.pub --insecure-ignore-tlog=true qualor/server:0.17.0
cosign verify-attestation --key https://qualor.dev/cosign.pub --insecure-ignore-tlog=true --type spdxjson qualor/server:0.17.0
curl -fsSLO https://qualor.dev/cosign.pub
cosign verify-blob --key cosign.pub --insecure-ignore-tlog=true --bundle SHA256SUMS.bundle SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```
