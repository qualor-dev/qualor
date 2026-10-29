# Qualor Enterprise

The enterprise features of Qualor, loaded by the server through its plugin interface
(`server/src/plugins/`) and only while a licence key is valid, including its 14-day grace
period after it expires. Without a key this code is never read.

**Licence:** source-available under the Qualor Enterprise Licence, [`LICENSE`](./LICENSE). You
may read, copy and modify it for development and testing. Carrying it unused (no key configured,
never loaded), in a fork of this repository or a mirror of a Qualor release or image, needs no
subscription. Production use needs a subscription or a trial key, and is limited to what the key
enables: its features and its validity, grace period included. A trial key has no grace period.
Licence keys are sold through <https://qualor.dev/contact>.
Everything outside this directory is MIT. Outside contributions to this directory are not
accepted.

- `src/plugin.ts`: the plugin (`qualor-enterprise`). It implements `audit-log`, `audit-log.stream`,
  `sso`, `sso.multi`, `scim`, `compliance-export`, `portfolio`, `llm.auto-fix`, `support-bundle` and
  `license-policy`. It also declares `llm.fix-quota`, which is kept for licences already issued and
  no longer changes anything. `audit-log.stream` works only with `audit-log`, and `sso.multi` only
  with `sso`. The Business plan lists `sso`, `audit-log`, `support-bundle` and `license-policy`; the
  Enterprise plan lists those and the other six. Roles and project access are not here: they are
  core (MIT), in every edition.
- `pnpm --filter @qualor/enterprise build` writes `dist/plugin.js`, which the `qualor/server`
  image carries at `/app/enterprise/plugin.js`.
- It imports core only with `import type`; everything else comes from the plugin context.
