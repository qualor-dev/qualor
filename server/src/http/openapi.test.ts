import { readFile } from 'node:fs/promises';
import { validate } from '@readme/openapi-parser';
import { beforeAll, describe, expect, it } from 'vitest';
import { OPENAPI_PATH, openApiDocument, serializeOpenApi } from './openapi-doc';

describe('OpenAPI document (api.md §6.1)', () => {
  it('is a valid OpenAPI 3.1 document', async () => {
    const doc = await openApiDocument();
    const result = await validate(structuredClone(doc) as Parameters<typeof validate>[0]);
    expect(result).toMatchObject({ valid: true });
  });

  describe('error responses (RFC 9457 problems)', () => {
    type Operation = {
      security?: unknown[];
      parameters?: { in: string; name: string; required?: boolean; schema?: unknown }[];
      requestBody?: { required?: boolean; content: Record<string, { schema: unknown }> };
      responses: Record<
        string,
        { description?: string; content?: Record<string, { schema: unknown }> }
      >;
    };
    type Doc = {
      components: { schemas: Record<string, { required?: string[] }> };
      paths: Record<string, Record<string, Operation>>;
    };
    const problemRef = { $ref: '#/components/schemas/Problem' };
    let doc: Doc;
    const op = (path: string, method: string): Operation => doc.paths[path]![method]!;
    const statuses = (o: Operation) => Object.keys(o.responses).sort();

    beforeAll(async () => {
      doc = (await openApiDocument()) as Doc;
    });

    it('defines one shared Problem schema', () => {
      expect(doc.components.schemas.Problem!.required).toEqual(['type', 'title', 'status', 'code']);
    });

    it('declares 401 and 403 problems on every authenticated operation', () => {
      for (const [path, item] of Object.entries(doc.paths)) {
        for (const [method, operation] of Object.entries(item)) {
          if (operation.security?.length === 0) continue; // public
          for (const status of ['401', '403']) {
            expect(operation.responses[status]?.content, `${method} ${path} ${status}`).toEqual({
              'application/problem+json': { schema: problemRef },
            });
          }
        }
      }
    });

    it('declares the statuses each route can produce', () => {
      expect(statuses(op('/api/v0/auth/login', 'post'))).toEqual([
        '204',
        '401',
        '409',
        '422',
        '429',
      ]);
      expect(statuses(op('/api/v0/projects/{id}', 'patch'))).toEqual([
        '200',
        '401',
        '403',
        '404',
        '409',
        '422',
      ]);
      expect(statuses(op('/api/v0/branches/{id}', 'delete'))).toContain('409');
      expect(statuses(op('/api/v0/organizations', 'post'))).toContain('409');
      expect(statuses(op('/api/v0/projects/by-key', 'get'))).toContain('404');
      // A profile deleted while it is being assigned is a 409 CONFLICT.
      expect(statuses(op('/api/v0/projects/{id}/quality-profiles/{language}', 'put'))).toContain(
        '409',
      );
    });

    it('documents 409 AUDIT_CHAIN_ANCHOR_MALFORMED on every audited core change, and on no other (rbac-audit.md §10.2)', () => {
      const text = (path: string, method: string) =>
        op(path, method).responses['409']?.description ?? '';
      for (const [path, method] of [
        ['/api/v0/auth/login', 'post'],
        ['/api/v0/quality-gates', 'post'],
        ['/api/v0/quality-gates/{id}/conditions/{condId}', 'patch'],
        ['/api/v0/organizations/{id}/members/{userId}', 'put'],
        ['/api/v0/projects/{id}/members/{userId}', 'put'],
        ['/api/v0/users/{id}', 'patch'],
        ['/api/v0/issues/bulk-transition', 'post'],
      ] as const) {
        expect(text(path, method), `${method} ${path}`).toContain('AUDIT_CHAIN_ANCHOR_MALFORMED');
      }
      // A route's own 409 keeps its text first.
      expect(text('/api/v0/organizations/{id}/members/{userId}', 'put')).toMatch(/^LAST_ADMIN/);
      expect(text('/api/v0/projects/{id}/members/{userId}', 'put')).toMatch(
        /^PROJECT_GRANT_LIMIT_REACHED/,
      );
      // sso-scim.md §10.3: a user change names both last-admin refusals.
      expect(text('/api/v0/users/{id}', 'patch')).toMatch(/^LAST_ADMIN .*LAST_BREAK_GLASS_ADMIN/);
      // §10.2.1: a route whose only event removes access is never refused for the anchor.
      expect(text('/api/v0/organizations/{id}/members/{userId}', 'delete')).toMatch(/^LAST_ADMIN/);
      // Removing a grant has no 409 at all (rbac-audit.md §16).
      expect(
        op('/api/v0/projects/{id}/members/{userId}', 'delete').responses['409'],
      ).toBeUndefined();
      for (const [path, method] of [
        ['/api/v0/analyses', 'post'],
        ['/api/v0/scm-connections/{id}/test', 'post'],
        ['/api/v0/system/llm/test', 'post'],
        ['/api/v0/projects/{id}', 'get'],
        ['/api/v0/auth/logout', 'post'],
        ['/api/v0/tokens/{id}', 'delete'],
        ['/api/v0/projects/{id}/tokens/{tokenId}', 'delete'],
        ['/api/v0/organizations/{id}/members/{userId}', 'delete'],
      ] as const) {
        expect(text(path, method), `${method} ${path}`).not.toContain('AUDIT_CHAIN');
      }
    });

    it('describes the report upload: gzip body, its content type, and every rejection', () => {
      const upload = op('/api/v0/analyses', 'post');
      expect(statuses(upload)).toEqual(['202', '401', '403', '404', '413', '415', '422', '503']);
      expect(upload.requestBody?.required).toBe(true);
      expect(Object.keys(upload.requestBody!.content)).toEqual([
        'application/vnd.qualor.report+json',
      ]);
      expect(upload.parameters).toContainEqual(
        expect.objectContaining({ in: 'header', name: 'Content-Encoding', required: true }),
      );
    });
  });

  it('matches the committed server/openapi.json (run `pnpm openapi` to update it)', async () => {
    expect(await readFile(OPENAPI_PATH, 'utf8')).toBe(serializeOpenApi(await openApiDocument()));
  });
});
