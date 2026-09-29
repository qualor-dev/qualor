import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Pages open their dialogs with `openAfterRender` (ui/src/app/shared/dialog.ts), never with
 * `openModal` itself: a dialog opened before Angular renders what the page just set is announced
 * with its last title or question (UI redesign, steps 5 and 9 reviews).
 */
const app = fileURLToPath(new URL('../../ui/src/app/', import.meta.url));

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sources(full);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts') ? [full] : [];
  });
}

describe('dialogs', () => {
  it('open through openAfterRender in every page', () => {
    const direct = sources(app)
      .filter((file) => !file.endsWith(path.join('shared', 'dialog.ts')))
      .flatMap((file) =>
        readFileSync(file, 'utf8')
          .split('\n')
          .map((line, index) => ({ line, index }))
          .filter(({ line }) => /\bopenModal\(/.test(line))
          .map(({ index }) => `${path.relative(app, file)}:${index + 1}`),
      );
    expect(direct).toEqual([]);
  });
});
