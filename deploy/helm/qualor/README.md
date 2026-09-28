# Qualor Helm chart

Installs the Qualor server: the API, the web UI and the analysis worker in one container, with
its own PostgreSQL 18 on a volume (`database.mode: embedded`, the default), your PostgreSQL 16+
(`external`), or a PostgreSQL 18 StatefulSet in the release (`bundled`).

The user documentation is at <https://qualor.dev/docs/install-server#kubernetes-helm>.
`values.schema.json` specifies and checks the values.

## Notes on values

- `ingress.annotations`: Helm merges yours with the defaults (the ingress-nginx body size, request
  buffering and read timeout). Set a key to `null` to remove a default.
- `database.external.caSecret`: a Secret with the certificate of a private CA (key
  `database.external.caKey`, default `ca.crt`). It is mounted read-only and set as
  `NODE_EXTRA_CA_CERTS`; do not set that variable in `extraEnv` too.
- `networkPolicy.enabled` (off by default): the server accepts only its port, from
  `networkPolicy.ingressFrom` or from anywhere, and the bundled PostgreSQL only the server. The
  server's egress is restricted only when `networkPolicy.egress` has rules (DNS and the bundled
  PostgreSQL are then added). It needs a CNI that enforces NetworkPolicy.

## Upgrades

- **Embedded mode has one pod.** An upgrade stops it before the new one starts, so the server is
  down for the restart (up to a minute or two, longer when migrations run). Plan for it.
- **Volume claims do not change on upgrade.** `persistence.*` and
  `database.bundled.persistence.*` are read only when the claim is created. To grow a volume,
  resize the claim itself (`kubectl edit pvc`), if its StorageClass allows expansion.
- **`database.mode` does not move data.** Changing it on an existing release starts an empty
  database. Move the data with a dump and a restore (see Backups in https://qualor.dev/docs/install-server).
- **The bundled password is read once**, when PostgreSQL creates its database. To rotate it, run
  `ALTER USER qualor PASSWORD '…'` in `<release>-postgres-0` first, then change the Secret or
  `database.bundled.password` and restart the servers.
- **Secrets you own are not watched.** A changed `secrets.existingSecret`,
  `database.external.existingSecret` or `database.bundled.existingSecret` takes effect after
  `kubectl rollout restart` of the server workload. The chart's own Secrets restart the pods
  through the `checksum/secret` annotation.
- **A new PostgreSQL major version** (in a later image) needs a dump with the old image and a
  restore with the new one; the release notes say when.
