import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generatedSchemas } from './schemas';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../schema');

describe('committed JSON Schemas', () => {
  it.each(Object.entries(generatedSchemas()))(
    '%s is up to date (run `pnpm schemas`)',
    (name, content) => {
      expect(readFileSync(path.join(dir, name), 'utf8')).toBe(content);
    },
  );
});
