import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import Fastify, { type FastifyBaseLogger, type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { VERSION } from './index';
import { mcpEndpoint } from './mcp/endpoint';
import { MCP_PROMPTS } from './mcp/prompts';
import { InternalCalls } from './mcp/internal';
import { MCP_TOOLS } from './mcp/tools';
import { installAuthentication } from './auth/authenticate';
import { createAuditRecorder, type AuditRecorder } from './audit/recorder';
import { warmPasswordHashing } from './auth/password';
import type { Config } from './config';
import type { Db } from './db/client';
import { installExpectContinue } from './http/expect-continue';
import { createLogger } from './http/logger';
import type { LogBuffer } from './http/log-buffer';
import { openApiOptions } from './http/openapi';
import { installErrorHandling, ProblemError } from './http/problem';
import './http/route-config';
import { helmetOptions } from './http/security-headers';
import { registerUi, type UiAssets } from './http/ui';
import { fixedEdition, type Edition } from './license/edition';
import { communityLimits, type Limits } from './limits';
import { oauthRoutes } from './oauth/routes';
import { mcpUrls } from './oauth/urls';
import { mountPluginRoutes, type LoadedPlugins } from './plugins/mount';
import type { PluginRegistry } from './plugins/registry';
import type { ScmRuntime } from './scm/runtime';
import { registerRoutes } from './routes';
import type { UpdateSource } from './update-check/checker';

/** api.md §1: JSON bodies are limited to 1 MiB (report uploads stream separately). */
export const JSON_BODY_LIMIT = 1024 * 1024;

export interface AppDeps {
  config: Config;
  db: Db;
  logger?: FastifyBaseLogger;
  /** Fixed limits for tests; ignored when `edition` is given. */
  limits?: Limits;
  /** The run-time edition (main.ts); without it, a fixed edition with `limits` or community. */
  edition?: Edition;
  checkReady: () => Promise<boolean>;
  /** How long `/readyz` waits for `checkReady` before answering 503 (default 2 s). */
  readyTimeoutMs?: number;
  /** The built web UI (`QUALOR_UI_DIR`, loaded by main.ts); without it the server is API-only. */
  ui?: UiAssets;
  /** What the plugin loader committed (enterprise.md §10); its routes go under /api/v0/ee. */
  plugins?: PluginRegistry | LoadedPlugins;
  /**
   * The audit recorder: main.ts passes bootEnterprise's, the one the plugin services record
   * through (rbac-audit.md §15); without it, one that records while `audit-log` is active.
   */
  audit?: AuditRecorder;
  /** The in-memory tail of the server log (main.ts); without it the support bundle has no logs. */
  logBuffer?: LogBuffer;
  /** The update check (main.ts, only while telemetry is on); without it `/system/version` has no `latest`. */
  updates?: UpdateSource;
  /**
   * The `scm` worker's runtime (main.ts): the repository listing and the Azure DevOps project
   * mapping reuse its Microsoft Entra tokens instead of asking for one per request. Without it
   * (tests), each request has its own.
   */
  scmRuntime?: Pick<ScmRuntime, 'azureTokens'>;
}

/**
 * Every limit goes through `edition.limits()`, computed on each call (enterprise.md §7); every
 * audited change records through `audit` (rbac-audit.md §9).
 */
export type RouteDeps = Omit<AppDeps, 'limits' | 'edition' | 'plugins' | 'audit'> & {
  edition: Edition;
  audit: AuditRecorder;
};

/**
 * QUALOR_TRUST_PROXY → Fastify's `trustProxy`. Fastify 5.12 no longer honours a numeric hop count
 * (it fails closed), so a count becomes the equivalent function: trust the `hops` closest
 * addresses (the socket peer is hop 0). A hop count assumes clients can only reach the server
 * through those proxies; otherwise configure the proxies' addresses instead.
 */
export function fastifyTrustProxy(
  trustProxy: Config['trustProxy'],
): false | string[] | ((address: string, hop: number) => boolean) {
  if (typeof trustProxy !== 'number') return trustProxy;
  return (address, hop) => hop < trustProxy;
}

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const { limits, edition, plugins, audit, ...rest } = deps;
  const resolvedEdition = edition ?? fixedEdition(limits ?? communityLimits());
  const loggerInstance: FastifyBaseLogger = deps.logger ?? createLogger(deps.config.logLevel);
  const routeDeps: RouteDeps = {
    ...rest,
    edition: resolvedEdition,
    audit:
      audit ??
      createAuditRecorder({
        isActive: () => resolvedEdition.isFeatureActive('audit-log'),
        log: loggerInstance,
      }),
  };
  const app = Fastify({
    loggerInstance,
    bodyLimit: JSON_BODY_LIMIT,
    trustProxy: fastifyTrustProxy(deps.config.trustProxy),
    requestTimeout: deps.config.requestTimeoutMs,
    http: {
      // S11 fix round 2: Node only re-checks requestTimeout/headersTimeout on this interval
      // (default 30s), so a short configured timeout would otherwise fire up to 30s late. Check
      // at roughly twice the configured timeout's frequency, capped so it's never excessive for a
      // long configured timeout either.
      connectionsCheckingInterval: Math.min(deps.config.requestTimeoutMs / 2, 5_000),
    },
  });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  installErrorHandling(app);
  installExpectContinue(app);
  await app.register(helmet, helmetOptions());
  await app.register(cookie);
  await app.register(rateLimit, {
    global: false,
    errorResponseBuilder: (_request, context) =>
      new ProblemError(429, 'RATE_LIMITED', `Too many requests; retry in ${context.after}`),
  });
  await app.register(swagger, openApiOptions());
  const internalCalls = new InternalCalls();
  app.decorate('internalCalls', internalCalls);
  installAuthentication(app, routeDeps, internalCalls);
  await registerRoutes(app, routeDeps);
  const urls = mcpUrls(deps.config.publicUrl);
  if (urls) {
    await app.register(oauthRoutes, { deps: routeDeps, urls });
    await app.register(mcpEndpoint, {
      deps: routeDeps,
      urls,
      tools: MCP_TOOLS,
      prompts: MCP_PROMPTS,
      version: VERSION,
    });
  }
  if (plugins) await mountPluginRoutes(app, plugins, routeDeps.edition);
  if (deps.ui) registerUi(app, deps.ui);
  await warmPasswordHashing();
  return app;
}
