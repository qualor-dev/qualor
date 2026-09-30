import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { VENDORED_GRAMMARS } from './vendored';

const GRAMMARS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../grammars');

describe('vendored grammars (plan 8F)', () => {
  it('are the upstream release files, byte for byte', () => {
    for (const [id, g] of Object.entries(VENDORED_GRAMMARS)) {
      const bytes = readFileSync(path.join(GRAMMARS_DIR, g.file));
      expect(createHash('sha256').update(bytes).digest('hex'), id).toBe(g.sha256);
      expect(g.url, id).toBe(
        `https://github.com/alex-pinkus/${g.name}/releases/download/${g.version}/${g.file}`,
      );
    }
  });
});
