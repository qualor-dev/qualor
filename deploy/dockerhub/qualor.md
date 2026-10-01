# qualor/qualor

Short description: Helm chart for Qualor, the self-hosted code quality platform and open-source SonarQube alternative

Categories: Developer tools, Integration & delivery, Security

## Overview

The Helm chart of [Qualor](https://qualor.dev), the open-source, self-hosted SonarQube alternative
with no lines-of-code licence. It runs the [`qualor/server`](https://hub.docker.com/r/qualor/server)
image, and its version is the server's version. It needs Kubernetes 1.29 or later and a default
StorageClass.

Website: <https://qualor.dev> · Install guide:
<https://qualor.dev/docs/install-server#kubernetes-helm> · Source and issues:
<https://github.com/qualor-dev/qualor>

### Install

Create the namespace and the secrets:

```sh
kubectl create namespace qualor
kubectl -n qualor create secret generic qualor-secrets \
  --from-literal=QUALOR_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=QUALOR_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)"
```

Write `values.yaml`:

```yaml
secrets:
  existingSecret: qualor-secrets
config:
  publicUrl: https://qualor.example.com
  trustProxy: '1'
ingress:
  enabled: true
  className: nginx
  host: qualor.example.com
  tls:
    secretName: qualor-tls # a certificate Secret, for example from cert-manager
```

Install, wait, and read the first admin password:

```sh
helm install qualor oci://registry-1.docker.io/qualor/qualor --version 0.3.2 -n qualor -f values.yaml
kubectl -n qualor rollout status statefulset/qualor
kubectl -n qualor get secret qualor-secrets -o jsonpath='{.data.QUALOR_BOOTSTRAP_ADMIN_PASSWORD}' | base64 -d
```

By default the server runs its own PostgreSQL on a 10 GiB volume, with one replica
(`database.mode: embedded`). `external` uses your managed database and `bundled` adds a PostgreSQL
StatefulSet to the release; both run several replicas. The install guide covers the settings,
backups and upgrades.

### Licence

The chart is MIT-licensed, like Qualor: <https://github.com/qualor-dev/qualor>.

### Trademarks

SonarQube and SonarCloud are trademarks of SonarSource SA. Qualor is an independent project and is
not affiliated with, sponsored or endorsed by SonarSource. Their names are used only to describe
compatibility and to compare features.
