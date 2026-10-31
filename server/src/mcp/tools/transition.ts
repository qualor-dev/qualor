import { z } from 'zod';
import { VEX_JUSTIFICATIONS } from '../../vulnerabilities/decisions';
import { issueLine, type IssueListItem } from '../format';
import { clientLabel, unwrap } from '../inject';
import type { McpTool } from '../tool';

/** The line appended to every comment the tool stores, so reviewers see the change came from an agent. */
export const MCP_VIA_LINE = (clientName: string): string => `via MCP · ${clientLabel(clientName)}`;

/**
 * Room left for the agent's own words: the route stores at most 2 000 characters (UTF-16 units)
 * per change comment (data-model.md §6), and the via line is a blank line, 10 units of prefix and
 * a client name of at most 64 code points (128 units): 1 850 + 2 + 10 + 128 <= 2 000.
 */
const COMMENT_MAX = 1_850;

const input = z.object({
  issueId: z.uuid().describe('From qualor_issues'),
  to: z
    .enum(['false_positive', 'wont_fix', 'open'])
    .describe('false_positive, wont_fix, or open to reopen'),
  comment: z.string().trim().min(1).max(COMMENT_MAX).describe('Why; reviewers read it'),
  reason: z
    .enum(VEX_JUSTIFICATIONS)
    .optional()
    .describe(
      'The VEX justification; required for false_positive on a Trivy issue of main or a tracked branch, whose decision covers the whole project',
    ),
});

/** Spec §5, ruling R2: the one write tool; the project role decides, exactly as for a person. */
export const transitionTool: McpTool<typeof input> = {
  name: 'qualor_transition_issue',
  title: 'Change an issue’s status',
  description:
    'Marks an issue false positive or won’t fix, or reopens it, with a mandatory comment. Your role in the project decides whether you may. ' +
    'Prefer fixing the code; use this only with a reason a reviewer would accept.',
  access: 'write',
  inputSchema: input,
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  async run({ issueId, to, comment, reason }, { call, principal }) {
    const issue = unwrap(
      await call.post<IssueListItem>(`/api/v0/issues/${issueId}/transition`, {
        to,
        comment: `${comment}\n\n${MCP_VIA_LINE(principal.clientName)}`,
        ...(reason === undefined ? {} : { reason }),
      }),
    );
    return { text: `Now ${issue.status}: ${issueLine(issue)}`, structured: { issue } };
  },
};
