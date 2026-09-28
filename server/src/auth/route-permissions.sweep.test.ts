import { describe, expect, it } from 'vitest';
import { callsOf, routeSources } from '../../test/route-source';
import {
  GUARDED_HELPERS,
  IMPLICIT_PERMISSIONS,
  LIST_CONDITIONS,
  ROUTE_PERMISSIONS,
} from './route-permissions';

/**
 * rbac-audit.md §5: every route of server/src/routes/, reads included, has a rule in
 * ROUTE_PERMISSIONS and checks it through the policy. A new route that does not fails here.
 */
describe('every route checks its rule through the policy module (rbac-audit.md §3.4, §5)', () => {
  const { routes, unclosed } = routeSources();

  it('reads every route to its end', () => {
    expect(routes.length).toBeGreaterThan(90);
    expect(unclosed).toEqual([]);
  });

  it('has a rule for every route and a route for every rule', () => {
    expect(routes.map((r) => r.id).sort()).toEqual(Object.keys(ROUTE_PERMISSIONS).sort());
  });

  it.each(routes.map((r) => [r.id, r.text] as const))('%s', (id, text) => {
    const rule = ROUTE_PERMISSIONS[id]!;
    expect(text, `${id} calls organizationRole( directly`).not.toMatch(/\borganizationRole\(/);
    if (rule === 'public') return void expect(text).toMatch(/public:\s*true/);
    if (rule === 'authenticated')
      return void expect(text).toMatch(/\b(requireUser|requirePrincipal)\(/);
    if (rule === 'self') return void expect(text).toMatch(/\b(requireUser|requireSession)\(/);
    if (rule === 'instance-admin') return void expect(text).toMatch(/\brequireInstanceAdmin\(/);
    if (rule.startsWith('list:')) {
      return void expect(text, `${id} must filter with ${LIST_CONDITIONS[rule]}`).toContain(
        `${LIST_CONDITIONS[rule]}(`,
      );
    }
    const checked = GUARDED_HELPERS.some((helper) =>
      callsOf(text, helper).some(
        (call) => call.includes(`'${rule}'`) || IMPLICIT_PERMISSIONS[helper] === rule,
      ),
    );
    expect(checked, `${id} does not check ${rule} through a guarded helper`).toBe(true);
  });
});
