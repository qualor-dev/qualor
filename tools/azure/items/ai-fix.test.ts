import { describe, expect, it } from 'vitest';
import { AI_FIX_MARKER, aiFixMarker as serverMarker } from '../../../server/src/llm/render';
import { FINDING_LINE, type Thr } from './19-decoration.js';
import {
  aiFixMarker,
  discussionIdOf,
  expectedRange,
  fixSource,
  judgeAiFixThread,
  markedThreads,
  pickFinding,
} from './25-ai-fix.js';

const SP = '7c429e0c-e3c7-43e0-8633-fa6e0000136d';
const OTHER = '99999999-2222-4333-8444-555555555555';
const ISSUE = '11111111-2222-4333-8444-555555555555';
const REQUEST = '22222222-3333-4444-8555-666666666666';
const FILE = '/probe/item-25-20261124120000.js';

describe('item 25 file', () => {
  it('has the empty function on the line item 19 and 21 find it on', () => {
    const lines = fixSource('20261124120000').split('\n');
    expect(FINDING_LINE).toBe(2);
    expect(lines[FINDING_LINE - 1]).toBe('export function emptyHandler() {');
    expect(lines[FINDING_LINE]).toBe('}');
    expect(lines.at(-1)).toBe('');
  });
});

describe('item 25 marker and range', () => {
  it("writes the server's ai-fix marker", () => {
    expect(aiFixMarker(ISSUE, REQUEST)).toBe(serverMarker(ISSUE, REQUEST));
    expect(AI_FIX_MARKER.test(aiFixMarker(ISSUE, REQUEST))).toBe(true);
  });

  it('selects whole lines: offset 1 on the first, the end line length + 1 on the last', () => {
    const source = fixSource('x');
    expect(expectedRange(source, 2, 3)).toEqual({
      start: { line: 2, offset: 1 },
      end: { line: 3, offset: 2 },
    });
    expect(expectedRange(source, 2, 2).end).toEqual({
      line: 2,
      offset: 'export function emptyHandler() {'.length + 1,
    });
  });

  it('picks the S1186 finding on the line, else any issue there', () => {
    const issue = (id: string, key: string, startLine: number | null) => ({
      id,
      rule: { key },
      startLine,
    });
    expect(
      pickFinding(
        [issue('a', 'sonarjs:S1481', 2), issue('b', 'sonarjs:S1186', 2), issue('c', 'x', 3)],
        2,
      )?.id,
    ).toBe('b');
    expect(pickFinding([issue('a', 'sonarjs:S1481', 2)], 2)?.id).toBe('a');
    expect(pickFinding([issue('c', 'sonarjs:S1186', 3)], 2)).toBeUndefined();
  });

  it("reads the thread id of a post's url", () => {
    expect(
      discussionIdOf('https://ado.example.invalid/o/p/_git/r/pullrequest/7?discussionId=12'),
    ).toBe(12);
    expect(discussionIdOf('https://x.invalid/pullrequest/7?a=1&discussionId=5#c')).toBe(5);
    expect(discussionIdOf('https://x.invalid/pullrequest/7?discussionId=')).toBeUndefined();
    expect(discussionIdOf(null)).toBeUndefined();
  });
});

describe('item 25 judgeAiFixThread', () => {
  const source = fixSource('20261124120000');
  const body = [
    aiFixMarker(ISSUE, REQUEST),
    '**AI-generated fix suggestion** from Qualor (model `m`). It may be wrong: review it before applying.',
    '',
    '```suggestion',
    'export function emptyHandler() {',
    '  return undefined;',
    '}',
    '```',
  ].join('\n');
  const thread = (
    over: {
      id?: number;
      content?: string;
      author?: string;
      start?: number;
      end?: [number, number];
      file?: string;
    } = {},
  ): Thr => ({
    id: over.id ?? 12,
    status: 'active',
    threadContext: {
      filePath: over.file ?? FILE,
      rightFileStart: { line: over.start ?? 2, offset: 1 },
      rightFileEnd: { line: (over.end ?? [3, 2])[0], offset: (over.end ?? [3, 2])[1] },
    },
    comments: [{ id: 1, content: over.content ?? body, author: { id: over.author ?? SP } }],
  });
  const want: Parameters<typeof judgeAiFixThread>[1] = {
    spId: SP,
    issueId: ISSUE,
    requestId: REQUEST,
    filePath: FILE,
    source,
    startLine: 2,
    endLine: 3,
    postUrl: 'https://ado.example.invalid/o/p/_git/r/pullrequest/7?discussionId=12',
  };
  const verdicts = (threads: Thr[], over: Partial<typeof want> = {}) =>
    judgeAiFixThread(threads, { ...want, ...over }).map((c) => c.pass);

  it('passes the posted shape: the marker, the whole-line range, the fence, the url', () => {
    expect(verdicts([thread()])).toEqual([true, true, true, true]);
    expect(verdicts([thread({ content: body.replace(/\n/g, '\r\n') })])).toEqual([
      true,
      true,
      true,
      true,
    ]);
  });

  it("ignores another identity's thread and another request's marker", () => {
    expect(markedThreads([thread({ author: OTHER })], SP, aiFixMarker(ISSUE, REQUEST))).toEqual([]);
    expect(verdicts([thread({ content: body.replace(REQUEST, ISSUE) })])).toEqual([
      false,
      false,
      false,
      false,
    ]);
    expect(verdicts([thread(), thread({ id: 13 })])[0]).toBe(false);
  });

  it('fails a range off the stored lines or the end line length', () => {
    expect(verdicts([thread({ end: [3, 3] })])[1]).toBe(false);
    expect(verdicts([thread({ start: 1 })])[1]).toBe(false);
    expect(verdicts([thread({ file: '/other.js' })])[1]).toBe(false);
    expect(verdicts([thread({ end: [2, 33] })], { endLine: 2 })).toEqual([true, true, true, true]);
  });

  it('fails a thread without the suggestion fence, and a url that names no thread or another', () => {
    expect(verdicts([thread({ content: body.replace('```suggestion', '```js') })])[2]).toBe(false);
    expect(verdicts([thread()], { postUrl: 'https://x.invalid/pullrequest/7' })[3]).toBe(false);
    expect(
      verdicts([thread()], { postUrl: 'https://x.invalid/pullrequest/7?discussionId=13' })[3],
    ).toBe(false);
    expect(verdicts([thread()], { postUrl: null })[3]).toBe(false);
  });
});
