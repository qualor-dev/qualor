// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { describe, expect, it } from 'vitest';
import { text } from '../../server/src/http/schemas';
import { eventsQuery } from '../src/audit-routes';

/**
 * rbac-audit.md §13: the plugin cannot import core's text() at run time (enterprise.md §12), so
 * its free-text filters carry their own check. This keeps the two in step.
 */
describe('the free-text filters match core text() (api.md §2.1)', () => {
  const messages = (result: { success: boolean; error?: { issues: { message: string }[] } }) =>
    result.success ? [] : result.error!.issues.map((i) => i.message);

  it.each([
    ['a\0b'],
    ['a\ud800b'],
    ['a\udc00'],
    ['\0\ud800'],
    ['\ud800\ud800\udc00'],
    ['a\u{1f600}b'],
    [''],
    ['x'.repeat(201)],
  ])('gives %j the same answer as text(200)', (value) => {
    const ours = eventsQuery.shape.targetId.unwrap().safeParse(value);
    const core = text(200).safeParse(value);
    expect(ours.success).toBe(core.success);
    expect(messages(ours)).toEqual(messages(core));
  });
});
