import { newMarkerText } from './new-marker';

describe('newMarkerText', () => {
  it('is null when nothing is new', () => {
    expect(newMarkerText({ main: false, branches: 0, versions: 0 })).toBeNull();
  });

  it('names main alone', () => {
    expect(newMarkerText({ main: true, branches: 0, versions: 0 })).toBe(
      'New vulnerabilities in main',
    );
  });

  it('counts versions alone', () => {
    expect(newMarkerText({ main: false, branches: 0, versions: 3 })).toBe(
      'New vulnerabilities in 3 versions',
    );
  });

  it('joins main and versions with "and"', () => {
    expect(newMarkerText({ main: true, branches: 0, versions: 2 })).toBe(
      'New vulnerabilities in main and 2 versions',
    );
  });

  it('uses the singular for one branch and one version', () => {
    expect(newMarkerText({ main: false, branches: 1, versions: 1 })).toBe(
      'New vulnerabilities in 1 branch and 1 version',
    );
  });

  it('lists main, branches and versions in that order', () => {
    expect(newMarkerText({ main: true, branches: 1, versions: 2 })).toBe(
      'New vulnerabilities in main and 1 branch and 2 versions',
    );
  });
});
