import { z } from 'zod';
import type { UsageRow, UsagesAnswer } from '../../packages/usages';
import { truncate } from '../format';
import { unwrap } from '../inject';
import type { McpTool } from '../tool';

/** The rows one answer lists; the total says how many more match. */
const PAGE = 50;

const input = z.object({
  query: z
    .string()
    .min(1)
    .max(300)
    .describe(
      'A package name (3 or more characters match anywhere in a name, 1–2 a whole name), or a package URL such as pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
    ),
  ecosystem: z
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .optional()
    .describe('A purl type: npm, pypi, maven, nuget, golang, cargo, deb, rpm, apk, …'),
  version: z.string().min(1).max(256).optional().describe('An exact version'),
});

/** `log4j-core@2.14.1 (pom) in shop, branch main (main), pom.xml: 3 open vulnerabilities`. */
function usageLine(r: UsageRow): string {
  const main = r.target.main ? ' (main)' : '';
  const path = r.path === '' ? '' : `, ${r.path}`;
  const vulnerabilities =
    r.vulnerabilities === null ? 'not checked' : `${r.vulnerabilities} open vulnerabilities`;
  return `${r.name}@${r.version} (${r.ecosystem}) in ${r.project.key}, ${r.target.kind} ${r.target.name}${main}${path}: ${vulnerabilities}`;
}

/** Spec §6.8: where used, across every project the user can see. */
export const packageUsagesTool: McpTool<typeof input> = {
  name: 'qualor_package_usages',
  title: 'Find where a package is used',
  description:
    'Where a package is used: every branch and released version, in every Qualor project you can see, whose dependencies hold it, with its open vulnerabilities there. ' +
    `Lists the first ${PAGE} matches by name, version and project, and how many more there are.`,
  access: 'read',
  inputSchema: input,
  annotations: { readOnlyHint: true, openWorldHint: false },
  async run({ query, ecosystem, version }, { call }) {
    const answer = unwrap(
      await call.get<UsagesAnswer>('/api/v0/packages/usages', {
        q: query,
        ecosystem,
        version,
        pageSize: PAGE,
      }),
    );
    const { rows, total, totalCapped } = answer;
    if (rows.length === 0) {
      return { text: 'No package you can see matches.', structured: { rows, total, totalCapped } };
    }
    const lines = rows.map(usageLine);
    const more = total - rows.length;
    if (totalCapped) {
      lines.push(`More than ${more} more match; narrow the search with ecosystem or version.`);
    } else if (more > 0) {
      lines.push(`${more} more match; narrow the search with ecosystem or version.`);
    }
    return { text: truncate(lines.join('\n')), structured: { rows, total, totalCapped } };
  },
};
