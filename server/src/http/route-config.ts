import type { RouteOpenApi } from './openapi';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** Reachable without credentials (health checks, OpenAPI, login). Enforced from Task 6. */
    public?: boolean;
    /** The handler writes `100 Continue` itself (http/expect-continue.ts), after its own checks. */
    deferContinue?: boolean;
    /** Extra OpenAPI documentation (error statuses, a non-JSON request body); http/openapi.ts. */
    openapi?: RouteOpenApi;
  }
}

export {};
