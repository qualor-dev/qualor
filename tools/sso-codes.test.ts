import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SSO_ERROR_REASONS } from '../server/src/audit/catalogue';
import { SSO_TEST_PROBLEM_CODES } from '../server/src/sso/connections';
import { SAML_METADATA_PROBLEM_CODES } from '../server/src/sso/saml';

/**
 * The UI never imports the server (AGENTS.md rule 5), so it keeps its own copies of the single
 * sign-on codes (sso-scim.md §7.7, §4.2). This test reads the UI's sources as text and keeps the
 * copies equal to the server's lists.
 */
const read = (file: string): string => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');

/** The text between `start` and the first `end` after it. */
function block(source: string, start: string, end: string): string {
  const from = source.indexOf(start);
  expect(from, start).toBeGreaterThanOrEqual(0);
  const to = source.indexOf(end, from + start.length);
  expect(to, end).toBeGreaterThan(from);
  return source.slice(from + start.length, to);
}

describe('the UI and the server name the same SSO codes', () => {
  const ssoText = read('ui/src/app/auth/sso-text.ts');

  it('SSO_ERROR_CODES equals SSO_ERROR_REASONS, in order', () => {
    const list = block(ssoText, 'export const SSO_ERROR_CODES = [', '] as const');
    const uiCodes = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(uiCodes).toEqual([...SSO_ERROR_REASONS]);
  });

  it('SSO_ERROR_TEXT has a message for every code, and for no other', () => {
    const texts = block(ssoText, 'export const SSO_ERROR_TEXT', '\n};');
    const keys = [...texts.matchAll(/^\s+(\w+): \$localize/gm)].map((m) => m[1]);
    expect([...keys].sort()).toEqual([...SSO_ERROR_REASONS].sort());
  });

  it('every problem code of the connection Test has a case in testProblemText', () => {
    const settingsText = read('ui/src/app/settings/sso-settings-text.ts');
    const fn = block(settingsText, 'export function testProblemText', '\n}\n');
    const cases = new Set([...fn.matchAll(/case '([^']+)':/g)].map((m) => m[1]));
    const missing = SSO_TEST_PROBLEM_CODES.filter((code) => !cases.has(code));
    expect(missing).toEqual([]);
    // And the UI names no code the server does not produce.
    const known: ReadonlySet<string> = new Set(SSO_TEST_PROBLEM_CODES);
    expect([...cases].filter((code) => !known.has(code!))).toEqual([]);
  });

  it('every reason of a refused Read metadata has a text in metadataProblemText', () => {
    const settingsText = read('ui/src/app/settings/sso-settings-text.ts');
    const fn = block(settingsText, 'export function metadataProblemText', '\n}\n');
    const cases = new Set([...fn.matchAll(/case '([^']+)':/g)].map((m) => m[1]));
    // A failed request is answered with the Test's text (checked above).
    const own = SAML_METADATA_PROBLEM_CODES.filter((code) => !code.startsWith('fetch.'));
    expect([...cases].sort()).toEqual([...own].sort());
    expect(fn).toContain("reason?.startsWith('fetch.') ? testProblemText(reason)");
  });
});
