import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { requirePrincipal, requireUser } from '../auth/access';
import { ProblemError } from '../http/problem';
import { VERSION } from '../index';

const status = z.object({ status: z.literal('ok') });

/** `/readyz` answers 503 when the database has not answered within this time. */
export const READY_TIMEOUT_MS = 2_000;

export const systemRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/healthz',
    {
      config: { public: true },
      schema: {
        tags: ['system'],
        summary: 'Liveness (no database access)',
        security: [],
        response: { 200: status },
      },
    },
    async () => ({ status: 'ok' as const }),
  );

  app.get(
    '/readyz',
    {
      config: { public: true },
      schema: {
        tags: ['system'],
        summary: 'Database reachable and migrations current',
        security: [],
        response: { 200: status },
      },
    },
    async () => {
      let ready: boolean;
      let timer: NodeJS.Timeout | undefined;
      try {
        // An unresponsive PostgreSQL must not hang the health check (and the probe behind it).
        const timeout = new Promise<boolean>((resolve) => {
          timer = setTimeout(() => resolve(false), deps.readyTimeoutMs ?? READY_TIMEOUT_MS);
        });
        ready = await Promise.race([deps.checkReady(), timeout]);
      } catch {
        ready = false;
      } finally {
        clearTimeout(timer);
      }
      if (!ready)
        throw new ProblemError(
          503,
          'NOT_READY',
          'The database is unreachable or migrations are pending',
        );
      return { status: 'ok' as const };
    },
  );

  app.get(
    '/api/v0/system/info',
    {
      schema: {
        tags: ['system'],
        summary: 'Version, edition, active plugin features and UI extensions',
        response: {
          200: z.object({
            version: z.string(),
            edition: z.enum(['community', 'enterprise']),
            features: z.array(z.string()),
            extensions: z.array(
              z.object({
                point: z.literal('settings.nav'),
                id: z.string(),
                label: z.string(),
                path: z.string(),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      requireUser(request);
      return {
        version: VERSION,
        edition: deps.edition.edition(),
        features: deps.edition.activeFeatures(),
        extensions: deps.edition.uiExtensions(),
      };
    },
  );

  // Any authenticated caller, a project analysis token too: the scanner logs the server's version
  // when a scan starts and warns when its own release differs. Anonymous callers learn nothing.
  app.get(
    '/api/v0/system/version',
    {
      schema: {
        tags: ['system'],
        summary: "The server's version, for any token (the scanner checks it when a scan starts)",
        response: { 200: z.object({ version: z.string() }) },
      },
    },
    async (request) => {
      requirePrincipal(request);
      return { version: VERSION };
    },
  );

  app.get('/api/v0/openapi.json', { config: { public: true }, schema: { hide: true } }, async () =>
    app.swagger(),
  );
};
