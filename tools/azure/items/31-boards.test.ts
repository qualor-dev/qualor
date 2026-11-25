import { reportSchema } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  codeIssueWorkItem,
  keyOfDescription,
  reconciliationKey,
  workItemOps,
} from '../../../server/src/boards/content';
import { ITEMS } from './index.js';
import {
  BOARDS_PROJECT_KEY,
  boardsReport,
  ENGINE,
  FILE,
  hyperlinkTo,
  isWorkItemUrl,
  lastParagraph,
  mappingBody,
  MARKUP,
  MESSAGE,
  referenceOf,
  RULE,
  strayTags,
  TAG,
  targetState,
  unescapedMarkup,
} from './31-boards.js';

const LINK_ID = '0192aaaa-bbbb-7ccc-8ddd-eeeeffff0000';
const PROJECT_ID = '0192aaaa-0000-7000-8000-000000000001';
const ISSUE_ID = '0192aaaa-0000-7000-8000-000000000002';
const PUBLIC = 'https://qualor.example.invalid';

/** The description Qualor sends for the item's finding, as Azure stores it (a space before `</p>`). */
function storedDescription(generation = 1): string {
  const content = codeIssueWorkItem(
    {
      issueId: ISSUE_ID,
      projectId: PROJECT_ID,
      projectName: 'Bench boards',
      projectKey: BOARDS_PROJECT_KEY,
      branchName: 'main',
      path: FILE,
      line: 3,
      ruleKey: `${ENGINE}:${RULE}`,
      ruleName: 'Qualor probe item 31: markup in a finding',
      severity: 'high',
      quality: 'security',
      message: MESSAGE,
      firstSeenAt: new Date('2026-11-25T00:00:00Z'),
      closedAt: null,
      lastSeenAt: null,
    },
    PUBLIC,
    reconciliationKey(LINK_ID, generation),
  );
  return content.descriptionHtml.replace(/<\/p>/g, ' </p>');
}

describe('item 31 helpers', () => {
  it('is registered', () => {
    expect(ITEMS.map((i) => i.id)).toContain(31);
  });

  it("uploads a report the server's schema takes: main, one finding of its own rule with the markup text", () => {
    const report = boardsReport(BOARDS_PROJECT_KEY, '20261125010203', new Date());
    expect(reportSchema.safeParse(report).success).toBe(true);
    expect(report.project.key).toBe(BOARDS_PROJECT_KEY);
    expect(report.scm).toMatchObject({ branch: 'main', mainBranch: 'main', mergeRequest: null });
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({ engineId: ENGINE, ruleId: RULE, message: MESSAGE });
    expect(report.engines[0]).toMatchObject({ id: ENGINE, kind: 'external' });
    for (const m of MARKUP) expect(MESSAGE).toContain(m);
  });

  it('keeps the finding across runs (fixed hashes) while the revision is the run’s', () => {
    const a = boardsReport('k', '20261125010203', new Date());
    const b = boardsReport('k', '20261126010203', new Date());
    expect(a.scm.revision).not.toBe(b.scm.revision);
    expect(a.scm.revision).toMatch(/^[0-9a-f]{40}$/);
    expect(a.findings[0]?.lineHash).toBe(b.findings[0]?.lineHash);
    expect(a.findings[0]?.contextHash).toBe(b.findings[0]?.contextHash);
  });

  it('maps with the roots, the given tags and no automatic rule', () => {
    expect(
      mappingBody('c1', { id: 'g', name: 'n' }, 'Microsoft.VSTS.WorkItemTypes.Bug', [TAG]),
    ).toEqual({
      connectionId: 'c1',
      azureProject: { id: 'g', name: 'n' },
      workItemType: { referenceName: 'Microsoft.VSTS.WorkItemTypes.Bug' },
      areaPath: null,
      iterationPath: null,
      tags: [TAG],
      autoCreate: { minSeverity: null, exploited: false },
    });
  });

  it("reads the reference line of Qualor's description as Azure stores it", () => {
    const html = storedDescription(2);
    expect(lastParagraph(html)).toBe(`Qualor reference: qualor-${LINK_ID.replaceAll('-', '')}-2`);
    expect(referenceOf(html)).toEqual({
      key: reconciliationKey(LINK_ID, 2),
      linkHex: LINK_ID.replaceAll('-', ''),
      generation: 2,
    });
    // The server's own reader agrees.
    expect(keyOfDescription(html)).toBe(referenceOf(html)?.key);
  });

  it('finds no reference line when the key is not the last paragraph', () => {
    const key = reconciliationKey(LINK_ID, 1);
    expect(referenceOf(`<p>Qualor reference: ${key}</p><p>edited by a person</p>`)).toBeNull();
    expect(referenceOf(`<pre>Qualor reference: ${key}</pre>`)).toBeNull();
    expect(referenceOf('<p>Qualor reference: qualor-ABC-1</p>')).toBeNull();
    expect(lastParagraph('no paragraph')).toBeNull();
  });

  it("sees no stray markup in Qualor's description, and every markup part escaped", () => {
    const html = storedDescription();
    expect(strayTags(html)).toEqual([]);
    expect(unescapedMarkup(html)).toEqual([]);
    // Azure may wrap text in div, span or br.
    expect(strayTags(`<div>${html}<br/><span>x</span></div>`)).toEqual([]);
  });

  it('names the markup a description would hold unescaped', () => {
    const raw = `<h3>r</h3><pre>${MESSAGE}</pre><p>Qualor reference: x</p>`;
    expect(strayTags(raw).sort()).toEqual(['b', 'img', 'script']);
    expect(unescapedMarkup(raw)).toEqual(MARKUP);
  });

  it("finds the Hyperlink Qualor's ops add, and only a Hyperlink", () => {
    const path = `/projects/${PROJECT_ID}/issues/${ISSUE_ID}`;
    const ops = workItemOps(
      { title: 't', descriptionHtml: storedDescription(), link: `${PUBLIC}${path}` },
      { tags: [TAG], areaPath: null, iterationPath: null },
      true,
    );
    const relation = ops.find((o) => o.path === '/relations/-')?.value as {
      rel: string;
      url: string;
    };
    expect(hyperlinkTo([relation], path)).toBe(`${PUBLIC}${path}`);
    expect(hyperlinkTo([{ rel: 'ArtifactLink', url: `${PUBLIC}${path}` }], path)).toBeUndefined();
    expect(hyperlinkTo(null, path)).toBeUndefined();
    expect(hyperlinkTo([{ rel: 'Hyperlink', url: `${PUBLIC}/projects/x` }], path)).toBeUndefined();
  });

  it('picks an in-progress state other than the current one', () => {
    const agileBug = [
      { name: 'New', category: 'Proposed' },
      { name: 'Active', category: 'InProgress' },
      { name: 'Resolved', category: 'Resolved' },
      { name: 'Closed', category: 'Completed' },
    ];
    expect(targetState(agileBug, 'New')).toBe('Active');
    expect(targetState(agileBug, 'active')).toBe('New');
    const basicIssue = [
      { name: 'To Do', category: 'Proposed' },
      { name: 'Doing', category: 'InProgress' },
      { name: 'Done', category: 'Completed' },
    ];
    expect(targetState(basicIssue, 'To Do')).toBe('Doing');
    const scrumBug = [
      { name: 'New', category: 'Proposed' },
      { name: 'Approved', category: 'Proposed' },
      { name: 'Committed', category: 'InProgress' },
      { name: 'Done', category: 'Completed' },
      { name: 'Removed', category: 'Removed' },
    ];
    expect(targetState(scrumBug, 'New')).toBe('Committed');
    expect(targetState([{ name: 'New', category: 'Proposed' }], 'New')).toBeUndefined();
    expect(
      targetState(
        [
          { name: 'New', category: 'Proposed' },
          { name: 'Removed', category: 'Removed' },
        ],
        'New',
      ),
    ).toBeUndefined();
  });

  it("knows the work item's web page, whatever the case or a trailing slash", () => {
    const g = 'AbCdEf00-0000-4000-8000-000000000031';
    expect(
      isWorkItemUrl(
        `https://dev.azure.com/org/${g.toLowerCase()}/_workitems/edit/42`,
        'https://dev.azure.com/Org/',
        g,
        42,
      ),
    ).toBe(true);
    expect(
      isWorkItemUrl(
        `https://dev.azure.com/org/${g}/_workitems/edit/43`,
        'https://dev.azure.com/org',
        g,
        42,
      ),
    ).toBe(false);
    expect(isWorkItemUrl(null, 'https://dev.azure.com/org', g, 42)).toBe(false);
  });
});
