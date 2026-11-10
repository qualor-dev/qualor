import {
  branchUrl,
  issueUrl,
  projectsUrl,
  projectUrl,
  vulnerabilitiesUrl,
  type ChatLinks,
} from './format';
import type {
  ChatDigestMessage,
  ChatExploitedMessage,
  ChatGateMessage,
  ChatMessage,
  ChatTestMessage,
  DigestVulnerabilities,
} from './messages';
import {
  conditionText,
  digestGateLabel,
  exploitedRowText,
  exploitedTitle,
  gateTitle,
  vulnerabilityProjectCounts,
  vulnerabilitySummary,
  localDate,
  newCodeText,
  severityCounts,
  severityLabel,
  shortRevision,
  displayZone,
  teamsInline,
  teamsText,
  utcTime,
} from './text';

type Element =
  | {
      type: 'TextBlock';
      text: string;
      wrap: true;
      weight?: 'Bolder';
      size?: 'Medium';
      color?: 'Attention' | 'Good';
      spacing?: 'Medium';
    }
  | { type: 'FactSet'; facts: { title: string; value: string }[] };
interface Card {
  $schema: 'http://adaptivecards.io/schemas/adaptive-card.json';
  type: 'AdaptiveCard';
  version: '1.4';
  msteams: { width: 'Full' };
  body: Element[];
  actions?: { type: 'Action.OpenUrl'; title: string; url: string }[];
}
export interface TeamsBody {
  type: 'message';
  attachments: [
    { contentType: 'application/vnd.microsoft.card.adaptive'; contentUrl: null; content: Card },
  ];
}

const block = (
  text: string,
  extra: Partial<Extract<Element, { type: 'TextBlock' }>> = {},
): Element => ({
  type: 'TextBlock',
  text,
  ...extra,
  wrap: true,
});
const heading = (text: string): Element => block(text, { weight: 'Bolder', spacing: 'Medium' });
/** `[text](url)` with links, else the text. */
const link = (url: string | null, text: string): string =>
  url === null ? text : `[${text}](${url})`;

function message(body: Element[], url: string | null): TeamsBody {
  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        contentUrl: null,
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          msteams: { width: 'Full' },
          body,
          ...(url === null
            ? {}
            : { actions: [{ type: 'Action.OpenUrl' as const, title: 'Open in Qualor', url }] }),
        },
      },
    ],
  };
}

function gate(m: ChatGateMessage, links: ChatLinks): TeamsBody {
  const failed = m.event === 'gate.failed';
  const counts = newCodeText(m);
  const body: Element[] = [
    block(gateTitle(m, teamsText), {
      weight: 'Bolder',
      size: 'Medium',
      color: failed ? 'Attention' : 'Good',
    }),
  ];
  if (failed) {
    body.push(
      heading('Failing conditions'),
      block(
        [
          ...m.failed.map((c) => `- ${conditionText(c, teamsText)}`),
          ...(m.failedCount > m.failed.length
            ? [`- …and ${m.failedCount - m.failed.length} more`]
            : []),
        ].join('\n'),
      ),
    );
  } else {
    body.push(
      block(
        m.cause === 'reevaluation'
          ? 'All conditions pass after issues were changed.'
          : 'All conditions pass.',
      ),
    );
  }
  body.push({
    type: 'FactSet',
    facts: [
      ...(counts === null ? [] : [{ title: 'New code', value: counts }]),
      ...(m.gate.name === null ? [] : [{ title: 'Gate', value: teamsText(m.gate.name) }]),
      ...(shortRevision(m.revision) === null
        ? []
        : [{ title: 'Commit', value: shortRevision(m.revision) ?? '' }]),
      { title: 'Time', value: utcTime(m.at) },
    ],
  });
  return message(body, branchUrl(links, m.project.id, m.branch.id));
}

function pathAt(path: string, line: number | null): string {
  return line === null ? path : `${path}:${line}`;
}

/** The text for the projects with nothing new; `more` when other projects are listed above it. */
function quietText(count: number, more: boolean): string {
  const noun = count === 1 ? 'project' : 'projects';
  return `${count} ${more ? 'more ' : ''}${noun}: no new security issues, gate passed`;
}

/** The bytes the project lines of the digest's vulnerability section may use. */
const VULNERABILITY_BYTES = 5_000;

/** C8: the digest's vulnerability section, in the words of the Slack one. */
function vulnerabilitiesBlocks(v: DigestVulnerabilities, links: ChatLinks): Element[] {
  // Escaped text is up to 7 bytes a character, and the card shares its 28 KB with the digest's
  // other parts: lines are added while they fit a byte budget, the rest join the tail.
  let budget = VULNERABILITY_BYTES;
  const lines: string[] = [];
  for (const p of v.projects) {
    const name = link(vulnerabilitiesUrl(links, p.projectId), teamsText(p.name, 50));
    const line = `- ${name} — ${vulnerabilityProjectCounts(p, teamsInline)}`;
    const size = Buffer.byteLength(line, 'utf8') + 1;
    if (size > budget) break;
    budget -= size;
    lines.push(line);
  }
  const more = v.moreProjects + (v.projects.length - lines.length);
  return [
    heading('Vulnerabilities in tracked versions'),
    block(vulnerabilitySummary(v, (s) => s)),
    ...(lines.length + more > 0
      ? [block([...lines, ...(more > 0 ? [`- …and ${more} more projects`] : [])].join('\n'))]
      : []),
  ];
}

/** The bytes the exploited rows of one card may use (the card limit is 28 KB). */
const ROW_BYTES = 14_000;

/** C5: the exploited vulnerabilities of one run, a heading and a TextBlock per project. */
function exploited(m: ChatExploitedMessage, links: ChatLinks): TeamsBody {
  const [only] = m.projects;
  const url =
    m.projects.length === 1 && m.moreProjects === 0 && only !== undefined
      ? vulnerabilitiesUrl(links, only.id)
      : projectsUrl(links);
  const body: Element[] = [
    block(exploitedTitle(m, teamsText), { weight: 'Bolder', size: 'Medium', color: 'Attention' }),
  ];
  // Teams rejects a card over 28 KB, and escaped text is up to 7 bytes a character: rows are
  // added while they fit a byte budget, the rest are counted into the project's "more" line.
  let budget = ROW_BYTES;
  for (const p of m.projects) {
    const rows: string[] = [];
    for (const r of p.rows) {
      const line = `- ${exploitedRowText(r, teamsInline, (s) => s)}`;
      const size = Buffer.byteLength(line, 'utf8') + 1;
      if (size > budget) break;
      budget -= size;
      rows.push(line);
    }
    const more = p.more + (p.rows.length - rows.length);
    const lines = [...rows, ...(more > 0 ? [`- …and ${more} more`] : [])];
    body.push(
      heading(link(vulnerabilitiesUrl(links, p.id), teamsText(p.name, 50))),
      ...(lines.length > 0 ? [block(lines.join('\n'))] : []),
    );
  }
  if (m.moreProjects > 0) body.push(block(`…and ${m.moreProjects} more projects`));
  return message(body, url);
}

function digest(m: ChatDigestMessage, links: ChatLinks): TeamsBody {
  const scopeName = m.scope.project?.name ?? m.scope.organization.name;
  const t = m.totals;
  const zone = displayZone(m.timezone);
  const rows = m.rows.map((r) => {
    const name = link(projectUrl(links, r.projectId), teamsText(r.name, 50));
    const sev = r.newSecurity > 0 ? ` (${severityCounts(r.newBySeverity)})` : '';
    return `- ${name} — ${digestGateLabel(r.gate)} · ${r.newSecurity} new${sev} · ${r.openSecurity} open`;
  });
  const tail = [
    ...(m.moreProjects > 0 ? [`- …and ${m.moreProjects} more projects`] : []),
    ...(m.quietProjects > 0
      ? [`- ${quietText(m.quietProjects, m.rows.length + m.moreProjects > 0)}`]
      : []),
  ];
  const top = m.top.map((i) => {
    const where = i.path === null ? '' : ` — ${teamsText(pathAt(i.path, i.line), 120)}`;
    const rule = link(issueUrl(links, i.projectId, i.id), teamsText(i.ruleName, 80));
    return `- ${severityLabel(i.severity)} · ${teamsText(i.projectName, 50)} · ${rule}${where}`;
  });
  const body: Element[] = [
    block(`Weekly security digest — ${teamsText(scopeName)}`, { weight: 'Bolder', size: 'Medium' }),
    block(
      `Last 7 days · ${localDate(m.since, m.timezone)} – ${localDate(m.until, m.timezone)} (${zone})`,
    ),
    {
      type: 'FactSet',
      facts: [
        { title: 'New security issues', value: String(t.newSecurity) },
        { title: 'New by severity', value: severityCounts(t.newBySeverity) },
        { title: 'Failing quality gates', value: String(t.failing) },
        { title: 'Open security issues', value: String(t.openSecurity) },
      ],
    },
    ...(rows.length + tail.length > 0
      ? [heading('Projects'), block([...rows, ...tail].join('\n'))]
      : []),
    ...(m.vulnerabilities === undefined ? [] : vulnerabilitiesBlocks(m.vulnerabilities, links)),
    ...(top.length > 0 ? [heading('Top new issues'), block(top.join('\n'))] : []),
    block(`Sent every Monday at 09:00 ${zone}`),
  ];
  const url = m.scope.project === null ? projectsUrl(links) : projectUrl(links, m.scope.project.id);
  return message(body, url);
}

function test(m: ChatTestMessage): TeamsBody {
  const scope =
    m.project === null
      ? `every project of ${teamsText(m.organization.name)}`
      : `the project ${teamsText(m.project.name)}`;
  return message(
    [
      block('Qualor is connected', { weight: 'Bolder', size: 'Medium' }),
      block(
        `This channel will get quality gate failures and recoveries on the main branch, and the weekly security digest, for ${scope}.`,
      ),
    ],
    null,
  );
}

export function formatTeams(m: ChatMessage, links: ChatLinks): TeamsBody {
  switch (m.type) {
    case 'gate':
      return gate(m, links);
    case 'digest':
      return digest(m, links);
    case 'exploited':
      return exploited(m, links);
    case 'test':
      return test(m);
  }
}
