import { createAuditRecorder } from '../src/audit/recorder';
import { createLogger } from '../src/http/logger';
import type { FlowDeps } from '../src/sso/complete';
import type { TestContext } from './app';

/**
 * What the OIDC and SAML flows need, from an `ssoContext`: the recorder bound to the edition's
 * `audit-log`, as rbacPlugins builds it, and a logger whose lines land in `ctx.logs`.
 */
export function flowDeps(ctx: TestContext): FlowDeps {
  if (!ctx.edition) throw new Error('flowDeps needs a context with an edition (ssoContext)');
  const edition = ctx.edition;
  const log = createLogger('info', {
    write: (line: string) => {
      ctx.logs.push(line);
    },
  });
  return {
    db: ctx.db,
    config: ctx.config,
    edition,
    audit: createAuditRecorder({ isActive: () => edition.isFeatureActive('audit-log'), log }),
    log,
  };
}
