import { codeSpan, MAX_MESSAGE_CHARS, qualorLink } from '../scm/markdown';

/**
 * llm.md §8.4: the first line of a posted fix suggestion. Neither a summary nor an issue marker
 * (`markerOf` reads it as none), so inline reconciliation never resolves, reopens or edits it.
 */
export const AI_FIX_MARKER = /^<!-- qualor:ai-fix ([0-9a-f-]{36}) ([0-9a-f-]{36}) -->$/;
/** llm.md §8.4: a comment is at most this long (the explanation is shortened, then dropped). */
export const FIX_BODY_MAX_BYTES = 8 * 1024;
/** The explanation's code span, longest first; 0 leaves it out. */
const EXPLANATION_CHARS = [600, 300, 100, 0] as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function aiFixMarker(issueId: string, requestId: string): string {
  if (!UUID.test(issueId) || !UUID.test(requestId)) {
    throw new Error('an ai-fix marker holds UUIDs only');
  }
  return `<!-- qualor:ai-fix ${issueId} ${requestId} -->`;
}

export interface FixSuggestionInput {
  provider: 'gitlab' | 'github';
  issueId: string;
  requestId: string;
  model: string;
  ruleKey: string;
  message: string;
  explanation: string;
  startLine: number;
  endLine: number;
  /** Lines `checkFix` accepted (llm.md §9.5): they go inside the fence unchanged. */
  replacement: string[];
  /** Qualor's own link to the issue (`issueUrl` of decoration-data.ts), or null. */
  issueUrl: string | null;
}

/**
 * llm.md §8.4. Everything outside the suggestion fence is Qualor's fixed text, a code span
 * (`codeSpan`: the model name, the rule key, the message and the model's explanation, each on one
 * line, so none can start a quick action, mention anyone, link or render), or Qualor's own link
 * (`qualorLink`). The replacement lines were accepted by `checkFix`, which refuses a fence, a
 * quick action, a hidden character and a secret; the caller checks the whole body's size.
 */
export function fixSuggestionBody(input: FixSuggestionInput): string {
  // GitLab: `-0+N` covers the commented line and the N below it (the range startLine..endLine).
  const fence =
    input.provider === 'gitlab'
      ? `\`\`\`suggestion:-0+${input.endLine - input.startLine}`
      : '```suggestion';
  const head = [
    aiFixMarker(input.issueId, input.requestId),
    `**AI-generated fix suggestion** from Qualor (model ${codeSpan(input.model)}). It may be wrong: review it before applying.`,
    '',
    `Issue: ${codeSpan(input.ruleKey)} · ${codeSpan(input.message, MAX_MESSAGE_CHARS)}`,
  ];
  const tail = ['', fence, ...input.replacement, '```'];
  const link = qualorLink('View the issue in Qualor', input.issueUrl);
  if (link !== null) tail.push('', link);
  let body = '';
  for (const max of EXPLANATION_CHARS) {
    const why = max > 0 ? [`Why: ${codeSpan(input.explanation, max)}`] : [];
    body = [...head, ...why, ...tail].join('\n');
    if (Buffer.byteLength(body, 'utf8') <= FIX_BODY_MAX_BYTES) break;
  }
  return body;
}
