import { describe, expect, it } from 'vitest';
import { autoloadVerdict } from './autoload-smoke';

describe('autoloadVerdict (ruling V8)', () => {
  it('passes only when the control loaded .env and the hardened binary did not', () => {
    expect(autoloadVerdict('null\n', '"from-repo"\n')).toBeNull();
    expect(autoloadVerdict('"from-repo"\n', '"from-repo"\n')).toMatch(/loaded \.env/);
    expect(autoloadVerdict('null\n', 'null\n')).toMatch(/proves nothing/);
  });
});
