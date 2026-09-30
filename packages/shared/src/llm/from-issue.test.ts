import { describe, expect, it } from 'vitest';
import { llmInputFrom, type RawIssueInput } from './from-issue';
import { llmIssueInputSchema } from './input';

const raw: RawIssueInput = {
  rule: { key: 'eslint:eqeqeq', name: 'eqeqeq', description: null, cwe: [0, 95, 96] },
  severity: 'medium',
  quality: 'reliability',
  kind: 'issue',
  message: 'm'.repeat(1_500),
  path: 'src/a.ts',
  startLine: 2,
  endLine: 2,
  language: 'cobol',
  snippet: { startLine: 1, lines: ['a', 'b'] },
};

describe('llmInputFrom (llm.md §5.1)', () => {
  it('bounds and normalises what goes into a prompt', () => {
    const input = llmInputFrom(raw);
    expect([...input.message]).toHaveLength(1_000);
    expect(input.rule).toEqual({
      key: 'eslint:eqeqeq',
      name: 'eqeqeq',
      description: '',
      cwe: [95, 96],
    });
    expect(input.language).toBeNull();
    expect(input.snippet).toEqual({ startLine: 1, lines: ['a', 'b'] });
  });

  it('always returns an input the schema accepts: an empty rule key, astral characters', () => {
    const empty = llmInputFrom({ ...raw, rule: { ...raw.rule, key: '' } });
    expect(llmIssueInputSchema.safeParse(empty).success).toBe(true);
    const emoji = '\u{1F600}';
    const astral = llmInputFrom({
      ...raw,
      rule: { ...raw.rule, key: emoji.repeat(300) },
      message: emoji.repeat(1_500),
    });
    expect([...astral.rule.key]).toHaveLength(200);
    expect([...astral.message]).toHaveLength(1_000);
    expect(llmIssueInputSchema.safeParse(astral).success).toBe(true);
  });

  it('treats a snippet of another shape as none', () => {
    expect(llmInputFrom({ ...raw, snippet: { lines: 'x' } }).snippet).toBeNull();
    expect(llmInputFrom({ ...raw, snippet: null }).snippet).toBeNull();
  });
});
