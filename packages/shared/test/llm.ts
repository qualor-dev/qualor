import type { LlmIssueInput } from '../src/llm/input';

/** One ESLint `eqeqeq` issue on line 2 of a three-line snippet: the base of the LLM unit tests. */
export const sampleInput = (over: Partial<LlmIssueInput> = {}): LlmIssueInput => ({
  rule: {
    key: 'eslint:eqeqeq',
    name: 'Require === and !==',
    description: 'Use strict equality.',
    cwe: [],
  },
  severity: 'medium',
  quality: 'reliability',
  kind: 'issue',
  message: "Expected '===' and instead saw '=='.",
  path: 'src/a.ts',
  startLine: 2,
  endLine: 2,
  language: 'typescript',
  snippet: { startLine: 1, lines: ['const a = 1;', 'if (a == 1) {}', 'export {};'] },
  ...over,
});
