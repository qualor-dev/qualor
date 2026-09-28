// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { serializeOpenApi } from '../../server/src/http/openapi-doc';
import { ENTERPRISE_OPENAPI_PATH, enterpriseOpenApiDocument } from './openapi-doc';

type Operation = {
  tags?: string[];
  security?: unknown[];
  externalDocs?: { url: string };
  responses?: Record<string, { description?: string; content?: Record<string, unknown> }>;
};
type Doc = { paths: Record<string, Record<string, Operation>> };

describe('enterprise/openapi.json (rbac-audit.md §17)', () => {
  it('holds the audit-log, sso and scim operations under /api/v0/ee only', async () => {
    const doc = (await enterpriseOpenApiDocument()) as Doc;
    const operations = Object.entries(doc.paths).flatMap(([path, item]) =>
      Object.keys(item).map((method) => `${method.toUpperCase()} ${path}`),
    );
    expect(operations.sort()).toEqual(
      [
        // No rbac routes under /api/v0/ee since 5B: the grant routes are core (rbac-audit.md §16).
        'GET /api/v0/ee/audit/events',
        'GET /api/v0/ee/audit/export',
        'GET /api/v0/ee/audit/head',
        'GET /api/v0/ee/audit/verify',
        'GET /api/v0/ee/audit/settings',
        'PUT /api/v0/ee/audit/settings',
        'POST /api/v0/ee/audit/settings/stream/regenerate-secret',
        'POST /api/v0/ee/audit/settings/stream/test',
        // sso-scim.md §17.2, feature sso
        'GET /api/v0/ee/sso/connections',
        'POST /api/v0/ee/sso/connections',
        'GET /api/v0/ee/sso/connections/{id}',
        'PATCH /api/v0/ee/sso/connections/{id}',
        'DELETE /api/v0/ee/sso/connections/{id}',
        'POST /api/v0/ee/sso/connections/{id}/test',
        'POST /api/v0/ee/sso/connections/{id}/saml/metadata',
        'GET /api/v0/ee/sso/connections/{id}/mappings',
        'PUT /api/v0/ee/sso/connections/{id}/mappings',
        'GET /api/v0/ee/sso/settings',
        'PUT /api/v0/ee/sso/settings',
        'GET /api/v0/ee/sso/users/{userId}/identities',
        'DELETE /api/v0/ee/sso/users/{userId}/identities/{identityId}',
        'GET /api/v0/ee/sso/me/identities',
        'DELETE /api/v0/ee/sso/me/identities/{identityId}',
        'POST /api/v0/ee/sso/connections/{id}/link',
        'GET /api/v0/ee/sso/{id}/start',
        'GET /api/v0/ee/sso/oidc/{id}/callback',
        'GET /api/v0/ee/sso/saml/{id}/metadata',
        'POST /api/v0/ee/sso/saml/{id}/acs',
        'GET /api/v0/ee/sso/finish',
        // feature scim
        'GET /api/v0/ee/scim/tokens',
        'POST /api/v0/ee/scim/tokens',
        'DELETE /api/v0/ee/scim/tokens/{id}',
        'GET /api/v0/ee/scim/v2/{*}',
        'POST /api/v0/ee/scim/v2/{*}',
        'PUT /api/v0/ee/scim/v2/{*}',
        'PATCH /api/v0/ee/scim/v2/{*}',
        'DELETE /api/v0/ee/scim/v2/{*}',
      ].sort(),
    );
  }, 60_000);

  it('documents 409 AUDIT_CHAIN_ANCHOR_MALFORMED where a route records or reads the anchor (rbac-audit.md §10.2)', async () => {
    const doc = (await enterpriseOpenApiDocument()) as Doc;
    for (const [path, method] of [
      ['/api/v0/ee/audit/export', 'get'],
      ['/api/v0/ee/audit/head', 'get'],
      ['/api/v0/ee/audit/settings', 'put'],
      ['/api/v0/ee/audit/settings/stream/regenerate-secret', 'post'],
      ['/api/v0/ee/sso/connections', 'post'],
      ['/api/v0/ee/sso/connections/{id}', 'patch'],
      ['/api/v0/ee/sso/connections/{id}/mappings', 'put'],
      ['/api/v0/ee/sso/settings', 'put'],
      ['/api/v0/ee/scim/tokens', 'post'],
    ] as const) {
      expect(
        doc.paths[path]?.[method]?.responses?.['409']?.description,
        `${method} ${path}`,
      ).toContain('AUDIT_CHAIN_ANCHOR_MALFORMED');
    }
  }, 60_000);

  it('lists the public browser flows and SCIM with their own answers, never a derived problem (sso-scim.md §17.2)', async () => {
    const doc = (await enterpriseOpenApiDocument()) as Doc;
    const flows = [
      ['/api/v0/ee/sso/{id}/start', 'get', ['302', '303', '403']],
      ['/api/v0/ee/sso/oidc/{id}/callback', 'get', ['303', '403']],
      ['/api/v0/ee/sso/saml/{id}/acs', 'post', ['303', '403']],
      ['/api/v0/ee/sso/finish', 'get', ['303', '403']],
      ['/api/v0/ee/sso/saml/{id}/metadata', 'get', ['200', '403', '404']],
      ...['get', 'post', 'put', 'patch', 'delete'].map(
        (m) => ['/api/v0/ee/scim/v2/{*}', m, ['403', 'default']] as const,
      ),
    ] as const;
    for (const [path, method, statuses] of flows) {
      const operation = doc.paths[path]?.[method];
      expect(operation?.security, `${method} ${path}`).toEqual([]);
      expect(Object.keys(operation?.responses ?? {}).sort(), `${method} ${path}`).toEqual([
        ...statuses,
      ]);
      expect(operation?.responses?.['403']?.description).toContain('FEATURE_NOT_LICENSED');
    }
    const scim = doc.paths['/api/v0/ee/scim/v2/{*}']?.post;
    expect(scim?.externalDocs?.url).toBe('https://www.rfc-editor.org/rfc/rfc7644');
    expect(Object.keys(scim?.responses?.['default']?.content ?? {})).toEqual([
      'application/scim+json',
    ]);
    expect(
      Object.keys(
        doc.paths['/api/v0/ee/sso/saml/{id}/metadata']?.get?.responses?.['200']?.content ?? {},
      ),
    ).toEqual(['application/samlmetadata+xml']);
  }, 60_000);

  it('matches the committed file (run `pnpm --filter @qualor/enterprise openapi` to update it)', async () => {
    expect(await readFile(ENTERPRISE_OPENAPI_PATH, 'utf8')).toBe(
      serializeOpenApi(await enterpriseOpenApiDocument()),
    );
  }, 60_000);
});
