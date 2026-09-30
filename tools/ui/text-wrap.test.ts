import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * Names people and servers choose — user names, rule keys, paths — may have no break point
 * ("a.very.long.user_name"). The messages that quote them wrap anywhere, so a long name never
 * widens a dialog or the page on a phone (UI redesign, step 5 review).
 */
const styles = readFileSync(new URL('../../ui/src/styles.css', import.meta.url), 'utf8');

function rule(selector: string): string {
  const at = styles.indexOf(`\n${selector} {`);
  if (at < 0) throw new Error(`no ${selector} rule in styles.css`);
  return styles.slice(at, styles.indexOf('}', at));
}

describe('messages that quote names', () => {
  for (const selector of ['.alert', '.field-error']) {
    it(`${selector} wraps a word that has no break point`, () => {
      expect(rule(selector)).toMatch(/overflow-wrap:\s*anywhere/);
    });
  }
});
