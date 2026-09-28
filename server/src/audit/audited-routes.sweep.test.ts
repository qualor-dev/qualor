import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { routeSources } from '../../test/route-source';
import { ACCESS_REMOVING_MUTATIONS, isAuditedMutation, UNAUDITED_MUTATIONS } from './routes';

/** A route that records: it reaches the recorder (`deps.audit`) or a route file's `audit(` helper. */
const RECORDS = /\bdeps\.audit\b|\baudit\(/;

/**
 * rbac-audit.md §10.2: the OpenAPI document marks every core mutating route that records an
 * event with 409 AUDIT_CHAIN_ANCHOR_MALFORMED, from UNAUDITED_MUTATIONS. This keeps that list
 * true to the routes' code, so a new audited route cannot go undocumented.
 */
describe('the audited core routes (rbac-audit.md §8, §10.2)', () => {
  const { routes, unclosed } = routeSources();
  const mutations = routes.filter((r) => !r.id.startsWith('GET '));

  it('reads every route to its end', () => {
    expect(unclosed).toEqual([]);
    expect(mutations.length).toBeGreaterThan(40);
  });

  it('lists exactly the mutating routes that never reach the recorder', () => {
    const unaudited = mutations.filter((r) => !RECORDS.test(r.text)).map((r) => r.id);
    expect(unaudited.sort()).toEqual([...UNAUDITED_MUTATIONS].sort());
  });

  it('lists exactly the routes that record only through recordOrSkipWhenAnchorMalformed (§10.2.1)', () => {
    const ALWAYS = /\bdeps\.audit\.record\(|\baudit\(/;
    // The grant routes record through the grants service, which records only this way (below).
    const SKIPS = /\bdeps\.audit\.recordOrSkipWhenAnchorMalformed\(|\b(set|remove)ProjectGrant\(/;
    const removing = mutations
      .filter((r) => SKIPS.test(r.text))
      .filter((r) => !ALWAYS.test(r.text))
      .map((r) => r.id);
    // These three also record events that do not remove access (an addition, a promotion, another
    // field), which the recorder refuses as `record` does: they stay audited in OpenAPI.
    const mixed = [
      'PATCH /users/:id',
      'PUT /organizations/:id/members/:userId',
      'PUT /projects/:id/members/:userId',
    ];
    expect(removing.sort()).toEqual([...ACCESS_REMOVING_MUTATIONS, ...mixed].sort());
    for (const id of mixed) expect(ACCESS_REMOVING_MUTATIONS.has(id)).toBe(false);
  });

  it('the grants service records only through recordOrSkipWhenAnchorMalformed', () => {
    const source = readFileSync(new URL('../rbac/grants.ts', import.meta.url), 'utf8');
    expect(source.match(/\.recordOrSkipWhenAnchorMalformed\(/g)).toHaveLength(2);
    expect(source).not.toMatch(/\.record\(/);
  });

  it('answers isAuditedMutation from the OpenAPI path, with or without the /api/v0 prefix', () => {
    expect(isAuditedMutation('post', '/api/v0/auth/login')).toBe(true);
    expect(isAuditedMutation('patch', '/api/v0/quality-gates/{id}/conditions/{condId}')).toBe(true);
    expect(isAuditedMutation('post', '/api/v0/analyses')).toBe(false);
    expect(isAuditedMutation('post', '/api/v0/github/webhooks/{connectionId}')).toBe(false);
    expect(isAuditedMutation('get', '/api/v0/projects/{id}')).toBe(false);
    expect(isAuditedMutation('put', '/api/v0/ee/audit/settings')).toBe(false);
    expect(isAuditedMutation('post', '/api/v0/auth/logout')).toBe(false);
    expect(isAuditedMutation('delete', '/api/v0/organizations/{id}/members/{userId}')).toBe(false);
    expect(isAuditedMutation('patch', '/api/v0/users/{id}')).toBe(true);
    expect(isAuditedMutation('put', '/api/v0/organizations/{id}/members/{userId}')).toBe(true);
    expect(isAuditedMutation('put', '/api/v0/projects/{id}/members/{userId}')).toBe(true);
    expect(isAuditedMutation('delete', '/api/v0/projects/{id}/members/{userId}')).toBe(false);
  });
});
