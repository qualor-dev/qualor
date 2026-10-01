import { settingsVisible } from './settings-visibility';

describe('settingsVisible', () => {
  it('follows each permission on its own', () => {
    expect(settingsVisible(['project.read'], false)).toBe(false);
    expect(settingsVisible(['project.read', 'project.delete'], false)).toBe(true);
    expect(settingsVisible(['project.read', 'project.settings'], false)).toBe(true);
    expect(settingsVisible(['project.read', 'project.tokens.manage'], false)).toBe(true);
    expect(settingsVisible(['project.read'], true)).toBe(true);
  });
});
