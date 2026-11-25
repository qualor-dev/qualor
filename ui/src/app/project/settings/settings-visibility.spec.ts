import { settingsVisible } from './settings-visibility';

describe('settingsVisible', () => {
  it('follows each permission on its own', () => {
    expect(settingsVisible([], false)).toBe(false);
    // A reader sees the Cleanup panel, read-only (issue #38).
    expect(settingsVisible(['project.read'], false)).toBe(true);
    expect(settingsVisible(['project.read', 'project.delete'], false)).toBe(true);
    expect(settingsVisible(['project.read', 'project.settings'], false)).toBe(true);
    expect(settingsVisible(['project.read', 'project.tokens.manage'], false)).toBe(true);
    expect(settingsVisible(['project.read'], true)).toBe(true);
  });
});
