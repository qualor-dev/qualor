import { describe, expect, it } from 'vitest';
import { assertNever, azureProjectKey } from './scm';

describe('assertNever', () => {
  it('throws with the value named', () => {
    expect(() => assertNever('x' as never, 'provider')).toThrow('unexpected provider: x');
  });

  it('prints the provider of an object, not [object Object]', () => {
    expect(() => assertNever({ provider: 'bitbucket', id: 1 } as never, 'provider')).toThrow(
      'unexpected provider: bitbucket',
    );
  });
});

describe('azureProjectKey', () => {
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';

  it('keeps a name of key characters as it is', () => {
    expect(azureProjectKey('Shop/web', id)).toBe('Shop/web');
    expect(azureProjectKey('Web.App/api_v2:x', id)).toBe('Web.App/api_v2:x');
  });

  it('makes every other character -, collapses runs and trims the ends', () => {
    expect(azureProjectKey('Fabrikam Fiber/My Repo', id)).toBe('Fabrikam-Fiber/My-Repo');
    expect(azureProjectKey('a  -- b/c', id)).toBe('a-b/c');
    expect(azureProjectKey(' Team 🚀/app ', id)).toBe('Team-/app');
  });

  it('replaces non-ASCII letters', () => {
    expect(azureProjectKey('My Project/Repo é', id)).toBe('My-Project/Repo');
    expect(azureProjectKey('Café/Säännöt', id)).toBe('Caf-/S-nn-t');
  });

  it('is the repository id, lower-cased, when no letter or digit is left', () => {
    expect(azureProjectKey('Проект/Репо', id.toUpperCase())).toBe(id);
    expect(azureProjectKey('😀/--', id)).toBe(id);
  });
});
