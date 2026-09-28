import { can, roleLabel } from './permissions';

describe('permissions and role labels (rbac-audit.md §17)', () => {
  it('allows only what the list names', () => {
    expect(can(['project.read'], 'project.read')).toBe(true);
    expect(can(['project.read'], 'issue.triage')).toBe(false);
    expect(can(undefined, 'project.read')).toBe(false);
  });

  it('names the four roles the same in every edition', () => {
    expect(roleLabel('admin')).toBe('Organization admin');
    expect(roleLabel('project_admin')).toBe('Project admin');
    expect(roleLabel('member')).toBe('Maintainer');
    expect(roleLabel('viewer')).toBe('Viewer');
  });

  it('names a grant-only organisation', () => {
    expect(roleLabel(null)).toBe('Project access only');
  });
});
