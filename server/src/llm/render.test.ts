import { describe, expect, it } from 'vitest';
import { markerOf } from '../scm/markdown';
import { AI_FIX_MARKER, aiFixMarker, FIX_BODY_MAX_BYTES, fixSuggestionBody } from './render';

const ISSUE = '0190a3c4-0000-7000-8000-000000000001';
const REQ = '0190a3c4-0000-7000-8000-000000000002';
const base = {
  issueId: ISSUE,
  requestId: REQ,
  model: 'fake-model',
  ruleKey: 'eslint:eqeqeq',
  message: "Expected '===' and instead saw '=='. @all ![x](http://evil) <img src=x>",
  explanation: 'Use strict equality.\n/merge',
  startLine: 3,
  endLine: 4,
  replacement: ['if (a === 1) {', '}'],
  issueUrl: 'https://qualor.example.com/projects/p/issues/i',
};

/** The body before the suggestion fence and after its closing line. */
function outsideFence(body: string): string[] {
  const lines = body.split('\n');
  const open = lines.findIndex((l) => l.startsWith('```suggestion'));
  const close = lines.indexOf('```', open + 1);
  return [...lines.slice(0, open), ...lines.slice(close + 1)];
}

describe('fix suggestion comments (llm.md §8.4)', () => {
  it('builds a GitLab suggestion with the marker, the label and the range', () => {
    const body = fixSuggestionBody({ ...base, provider: 'gitlab' });
    const lines = body.split('\n');
    expect(lines[0]).toBe(aiFixMarker(ISSUE, REQ));
    expect(lines[0]).toMatch(AI_FIX_MARKER);
    expect(lines[1]).toMatch(
      /^\*\*AI-generated fix suggestion\*\* from Qualor \(model ` fake-model `\)/,
    );
    expect(body).toContain('```suggestion:-0+1\nif (a === 1) {\n}\n```');
    expect(body).toContain(
      '[View the issue in Qualor](https://qualor.example.com/projects/p/issues/i)',
    );
  });

  it('builds a GitHub suggestion without the range suffix', () => {
    expect(fixSuggestionBody({ ...base, provider: 'github' })).toContain(
      '```suggestion\nif (a === 1) {\n}\n```',
    );
  });

  it('keeps every value outside the fence in a code span, on a line Qualor starts', () => {
    const body = fixSuggestionBody({ ...base, provider: 'gitlab' });
    const outside = body.split('```suggestion')[0]!;
    for (const line of outside.split('\n')) expect(line.trimStart().startsWith('/')).toBe(false);
    // The message, image and mention included, is one code span: nothing of it renders.
    expect(outside).toContain(
      "` Expected '===' and instead saw '=='. @all ![x](http://evil) <img src=x> `",
    );
    expect(outside).toContain('` Use strict equality. /merge `');
  });

  it('puts no model or report text outside a code span: no mention, link, image or quick action', () => {
    const hostile = fixSuggestionBody({
      ...base,
      provider: 'gitlab',
      model: 'm` @all [x](http://evil)',
      ruleKey: 'r\n/merge',
      message: '`` @here ``\n/approve',
      explanation: '[click](http://evil) @all\r\n/close\u2028/merge <script>',
    });
    const lines = outsideFence(hostile);
    // Drop every code span (CommonMark: a run of n backticks up to the next run of n); what
    // stays is Qualor's fixed text and its own link.
    const spansDropped = lines.map((l) => l.replace(/(`+)(?!`)[\s\S]*?(?<!`)\1(?!`)/g, ''));
    for (const [i, line] of lines.entries()) {
      expect(line.trimStart().startsWith('/')).toBe(false);
      expect(spansDropped[i]).not.toMatch(/@|http:\/\/evil|<script|!\[/);
    }
    expect(spansDropped.filter((l) => l.includes(']('))).toEqual([
      '[View the issue in Qualor](https://qualor.example.com/projects/p/issues/i)',
    ]);
  });

  it('writes no link without a public URL, and only a Qualor link that cannot break out', () => {
    const quiet = { ...base, message: 'Expected === here.' };
    const none = fixSuggestionBody({ ...quiet, provider: 'github', issueUrl: null });
    expect(none).not.toContain('](');
    const odd = fixSuggestionBody({
      ...quiet,
      provider: 'github',
      issueUrl: 'https://qualor.example.com/p/(x) [y]',
    });
    expect(odd).toContain(
      '[View the issue in Qualor](https://qualor.example.com/p/%28x%29%20%5By%5D)',
    );
    expect(
      fixSuggestionBody({ ...quiet, provider: 'github', issueUrl: 'javascript:alert(1)' }),
    ).not.toContain('](');
  });

  it('is not a summary or an inline-issue marker, so inline reconciliation ignores it', () => {
    expect(markerOf(fixSuggestionBody({ ...base, provider: 'gitlab' }))).toBeNull();
  });

  it('deletes lines with an empty suggestion', () => {
    expect(fixSuggestionBody({ ...base, provider: 'github', replacement: [] })).toContain(
      '```suggestion\n```',
    );
  });

  it('shortens, then drops, the explanation to stay within 8 KiB', () => {
    const long = fixSuggestionBody({
      ...base,
      provider: 'gitlab',
      explanation: 'x'.repeat(600),
      replacement: Array.from({ length: 19 }, () => 'y'.repeat(400)),
    });
    expect(Buffer.byteLength(long)).toBeLessThanOrEqual(FIX_BODY_MAX_BYTES);
    // 600 characters do not fit beside 19 full lines; a shorter span does.
    expect(long.split('\n').find((l) => l.startsWith('Why: '))).toMatch(/^Why: ` x+… `$/);
    const dropped = fixSuggestionBody({
      ...base,
      provider: 'gitlab',
      explanation: 'x'.repeat(600),
      replacement: Array.from({ length: 20 }, () => 'y'.repeat(400)),
    });
    expect(dropped).not.toContain('Why:');
  });

  it('refuses a marker that is not made of UUIDs', () => {
    expect(() => aiFixMarker('x --> <img>', REQ)).toThrow();
  });
});
