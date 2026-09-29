import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The guide names the screens as they are (AGENTS.md rule 9). A name the redesign removed must not
 * survive anywhere in it, however the Markdown wraps it: each page is read with its emphasis
 * dropped and its line breaks folded into spaces (UI redesign, step 8 review).
 */
const REMOVED = [
  // Step 8: the form under Settings → Users became "Reset password" on the user's row.
  'Settings → Users → Reset a password',
  // Step 9: SCIM tokens are made in the "New token" dialog of the connection's panel.
  "in the connection's section, give a Token name",
];

const guide = new URL('../../docs/guide/', import.meta.url);
const pages = readdirSync(guide)
  .filter((name) => name.endsWith('.md'))
  .map((name) => ({
    name,
    text: readFileSync(new URL(name, guide), 'utf8').replaceAll('**', '').replace(/\s+/g, ' '),
  }));

describe('the user guide', () => {
  it('has pages to read', () => {
    expect(pages.length).toBeGreaterThan(0);
  });

  for (const removed of REMOVED) {
    it(`never names "${removed}"`, () => {
      expect(pages.filter((page) => page.text.includes(removed)).map((page) => page.name)).toEqual(
        [],
      );
    });
  }
});
