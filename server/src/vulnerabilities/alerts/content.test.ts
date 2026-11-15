import { describe, expect, it } from 'vitest';

import type { VulnerabilityMailRow } from '../../mail/templates/notify-vulnerability-common';
import type { Watcher } from '../../notifications/recipients';
import { watcherSections } from './content';

describe('watcherSections', () => {
  it('leaves out a project without a name', () => {
    const id = '0198a1c0-0000-7000-8000-000000000001';
    const rows: VulnerabilityMailRow[] = [
      {
        vulnerabilityId: 'CVE-2026-0001',
        severity: 'high',
        title: null,
        exploited: null,
        packageName: 'lodash',
        installedVersions: ['4.17.0'],
        fixedVersion: null,
        targets: ['main'],
      },
    ];
    const watcher: Watcher = {
      userId: 'u1',
      email: 'a@example.test',
      username: 'a',
      displayName: null,
    };
    expect(
      watcherSections([{ ...watcher, projectId: id }], new Map(), new Map([[id, rows]])),
    ).toEqual([]);
  });
});
