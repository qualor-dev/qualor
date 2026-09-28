import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ORGANIZATION_PERMISSIONS,
  ORGANIZATION_ROLES,
  organizationPermissions,
  PROJECT_PERMISSIONS,
  PROJECT_ROLES,
  projectPermissions,
  permissionScope,
  type AccessFacts,
} from './policy';

const facts = (over: Partial<AccessFacts>): AccessFacts => ({
  instanceAdmin: false,
  organizationRole: null,
  projectRole: null,
  hasProjectGrantInOrganization: false,
  ...over,
});

// The design specs are kept outside the public repository; their parity checks run where they exist.
const SPEC = new URL('../../../docs/spec/rbac-audit.md', import.meta.url);

/** rbac-audit.md §3.1: `| \`permission\` | \`scope\` | what it allows |` rows. */
function specScopes(): Record<string, string> {
  const text = readFileSync(SPEC, 'utf8');
  const start = text.indexOf('### 3.1 Permissions');
  const end = text.indexOf('\n### ', start + 1);
  if (start < 0 || end < 0) throw new Error('rbac-audit.md: §3.1 Permissions not found');
  const rows: Record<string, string> = {};
  for (const m of text
    .slice(start, end)
    .matchAll(/^\|\s*`([a-z.]+)`\s*\|\s*`([a-z:]+)`\s*\|[^\n]*\|\s*$/gm)) {
    if (m[1]! in rows) throw new Error(`rbac-audit.md §3.1 lists ${m[1]!} twice`);
    rows[m[1]!] = m[2]!;
  }
  return rows;
}

const sorted = (s: ReadonlySet<string>) => [...s].sort();

describe('the policy module (rbac-audit.md §3–§4)', () => {
  it('gives the admin every permission and the member exactly the pre-4C set (§3.5)', () => {
    expect(sorted(organizationPermissions(facts({ organizationRole: 'admin' })))).toEqual(
      [...ORGANIZATION_PERMISSIONS].sort(),
    );
    expect(sorted(projectPermissions(facts({ organizationRole: 'admin' })))).toEqual(
      [...PROJECT_PERMISSIONS].sort(),
    );
    expect(sorted(organizationPermissions(facts({ organizationRole: 'member' })))).toEqual([
      'org.read',
    ]);
    expect(sorted(projectPermissions(facts({ organizationRole: 'member' })))).toEqual([
      'ai.use',
      'issue.triage',
      'project.analyze',
      'project.read',
    ]);
  });

  it('gives an instance admin everything, whatever the memberships', () => {
    expect(organizationPermissions(facts({ instanceAdmin: true })).size).toBe(
      ORGANIZATION_PERMISSIONS.length,
    );
    expect(projectPermissions(facts({ instanceAdmin: true })).size).toBe(
      PROJECT_PERMISSIONS.length,
    );
  });

  it.each([
    [
      'project_admin',
      [
        'ai.use',
        'issue.triage',
        'project.analyze',
        'project.branches.delete',
        'project.issues.import',
        'project.read',
        'project.settings',
        'project.tokens.manage',
      ],
    ],
    ['viewer', ['project.read']],
  ] as const)('gives an organisation-level %s its project permissions (§3.2)', (role, expected) => {
    expect(sorted(projectPermissions(facts({ organizationRole: role })))).toEqual(expected);
    expect(sorted(organizationPermissions(facts({ organizationRole: role })))).toEqual([
      'org.read',
    ]);
  });

  it('every role at organisation and project level gives the §3.2 row, over every combination of organisation role, project role and hasProjectGrantInOrganization', () => {
    // §3.2, written out here rather than read from ROLE_PERMISSIONS, so a change there fails.
    const maintain = ['project.read', 'project.analyze', 'issue.triage', 'ai.use'];
    const administerProject = [
      ...maintain,
      'project.settings',
      'project.tokens.manage',
      'project.branches.delete',
      'project.issues.import',
    ];
    const orgRow: Record<string, readonly string[]> = {
      admin: ORGANIZATION_PERMISSIONS,
      project_admin: ['org.read'],
      member: ['org.read'],
      viewer: ['org.read'],
    };
    const projectRow: Record<string, readonly string[]> = {
      admin: PROJECT_PERMISSIONS,
      project_admin: administerProject,
      member: maintain,
      viewer: ['project.read'],
    };
    let checked = 0;
    for (const organizationRole of [null, ...ORGANIZATION_ROLES])
      for (const projectRole of [null, ...PROJECT_ROLES])
        for (const hasProjectGrantInOrganization of [false, true]) {
          const input = facts({ organizationRole, projectRole, hasProjectGrantInOrganization });
          const org = new Set(organizationRole ? orgRow[organizationRole] : []);
          if (hasProjectGrantInOrganization) org.add('org.read');
          const project = new Set([
            ...(organizationRole ? projectRow[organizationRole]! : []),
            ...(projectRole ? projectRow[projectRole]! : []),
          ]);
          expect(sorted(organizationPermissions(input))).toEqual(sorted(org));
          expect(sorted(projectPermissions(input))).toEqual(sorted(project));
          // An instance admin holds everything, whatever the rest says.
          const root = { ...input, instanceAdmin: true };
          expect(sorted(organizationPermissions(root))).toEqual(
            [...ORGANIZATION_PERMISSIONS].sort(),
          );
          expect(sorted(projectPermissions(root))).toEqual([...PROJECT_PERMISSIONS].sort());
          checked++;
        }
    expect(checked).toBe(5 * 4 * 2);
  });

  it('adds a project grant to the organisation role and never narrows it', () => {
    const widened = projectPermissions(
      facts({ organizationRole: 'viewer', projectRole: 'member' }),
    );
    expect(widened.has('issue.triage')).toBe(true);
    const kept = projectPermissions(facts({ organizationRole: 'admin', projectRole: 'viewer' }));
    expect(kept.has('project.delete')).toBe(true);
  });

  it("a grant-only user holds org.read and the grant's project set", () => {
    expect(sorted(organizationPermissions(facts({ hasProjectGrantInOrganization: true })))).toEqual(
      ['org.read'],
    );
    expect(
      sorted(
        projectPermissions(
          facts({ projectRole: 'project_admin', hasProjectGrantInOrganization: true }),
        ),
      ),
    ).toEqual([
      'ai.use',
      'issue.triage',
      'project.analyze',
      'project.branches.delete',
      'project.issues.import',
      'project.read',
      'project.settings',
      'project.tokens.manage',
    ]);
    expect(
      sorted(
        projectPermissions(facts({ projectRole: 'viewer', hasProjectGrantInOrganization: true })),
      ),
    ).toEqual(['project.read']);
  });

  it('a stored viewer stays read-only (§6.2)', () => {
    expect(sorted(projectPermissions(facts({ organizationRole: 'viewer' })))).toEqual([
      'project.read',
    ]);
  });

  it('names the token scope of each permission (§3.1)', () => {
    expect(permissionScope('project.read')).toBe('read');
    expect(permissionScope('org.read')).toBe('read');
    expect(permissionScope('issue.triage')).toBe('write');
    expect(permissionScope('ai.use')).toBe('write');
    expect(permissionScope('project.analyze')).toBe('analysis:write');
    expect(permissionScope('project.settings')).toBe('admin');
    expect(permissionScope('org.members.read')).toBe('admin');
  });

  it.runIf(existsSync(SPEC))(
    'gives every permission the token scope of the spec table, in both directions (§3.1)',
    () => {
      const spec = specScopes();
      const all = [...ORGANIZATION_PERMISSIONS, ...PROJECT_PERMISSIONS];
      expect(Object.keys(spec).sort()).toEqual([...all].sort());
      expect(Object.fromEntries(all.map((p) => [p, permissionScope(p)]))).toEqual(spec);
    },
  );

  it('returns sets a caller cannot use to change the policy', () => {
    const a = projectPermissions(facts({ organizationRole: 'member' })) as Set<string>;
    a.add('project.delete');
    expect(projectPermissions(facts({ organizationRole: 'member' })).has('project.delete')).toBe(
      false,
    );
  });
});
