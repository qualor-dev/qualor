import {
  branchUrl,
  issueUrl,
  projectsUrl,
  projectUrl,
  vulnerabilitiesUrl,
  type ChatLinks,
} from './format';
import { MAX_PROJECT_NAME } from '../../mail/templates/notify-vulnerability-common';
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
  plainText,
  severityCounts,
  severityLabel,
  shortRevision,
  slackText,
  displayZone,
  utcTime,
} from './text';

type Text =
  | { type: 'mrkdwn'; text: string; verbatim: true }
  | { type: 'plain_text'; text: string; emoji?: boolean };
export type SlackBlock =
  | { type: 'header'; text: { type: 'plain_text'; text: string; emoji: false } }
  | { type: 'section'; text: Text }
  | { type: 'context'; elements: Text[] }
  | {
      type: 'actions';
      elements: {
        type: 'button';
        text: { type: 'plain_text'; text: string };
        url: string;
        style?: 'primary' | 'danger';
      }[];
    };
export interface SlackBody {
  /** R9: the notification text, and what a Workflow Builder trigger's `text` variable gets. */
  text: string;
  blocks: SlackBlock[];
}

/** Slack's limits: header text 150, section text 3000 characters. */
const HEADER_MAX = 150;
const SECTION_MAX = 3000;

const header = (text: string): SlackBlock => ({
  type: 'header',
  text: { type: 'plain_text', text: plainText(text, HEADER_MAX), emoji: false },
});
/**
 * Every mrkdwn text is `verbatim`: Slack then skips its own parsing (bare URLs into links,
 * `@here` and `#channel` into mentions), while the `<url|text>` links we write still work.
 */
const section = (text: string): SlackBlock => ({
  type: 'section',
  text: { type: 'mrkdwn', text: [...text].slice(0, SECTION_MAX).join(''), verbatim: true },
});
const context = (text: string): SlackBlock => ({
  type: 'context',
  elements: [{ type: 'mrkdwn', text: [...text].slice(0, SECTION_MAX).join(''), verbatim: true }],
});
const button = (url: string | null, style?: 'primary' | 'danger'): SlackBlock[] =>
  url === null
    ? []
    : [
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Open in Qualor' },
              url,
              ...(style ? { style } : {}),
            },
          ],
        },
      ];
/** `<url|text>` with links, else the text. */
const link = (url: string | null, text: string): string =>
  url === null ? text : `<${url}|${text}>`;

function failingConditions(m: ChatGateMessage): string {
  return [
    '*Failing conditions*',
    ...m.failed.map((c) => `• ${conditionText(c, slackText)}`),
    ...(m.failedCount > m.failed.length ? [`…and ${m.failedCount - m.failed.length} more`] : []),
  ].join('\n');
}

function passingConditions(m: ChatGateMessage): string {
  if (m.cause === 'reevaluation') return 'All conditions pass after issues were changed.';
  return 'All conditions pass.';
}

function gate(m: ChatGateMessage, links: ChatLinks): SlackBody {
  // The header is plain_text (never parsed): the raw names, one line, clipped.
  const raw = gateTitle(m, (s, max) => plainText(s, max ?? 80));
  const failed = m.event === 'gate.failed';
  const conditions = failed ? failingConditions(m) : passingConditions(m);
  const counts = newCodeText(m);
  const facts = [
    m.gate.name === null ? null : `Gate ${slackText(m.gate.name)}`,
    shortRevision(m.revision) === null ? null : `commit \`${shortRevision(m.revision)}\``,
    utcTime(m.at),
  ].filter((f): f is string => f !== null);
  return {
    text: gateTitle(m, slackText),
    blocks: [
      header(raw),
      section(conditions),
      ...(counts === null ? [] : [section(`*New code:* ${counts}`)]),
      context(facts.join(' · ')),
      ...button(branchUrl(links, m.project.id, m.branch.id), failed ? 'danger' : 'primary'),
    ],
  };
}

/** The leading lines that fit in a section after `used` characters; stops at the first misfit. */
function packLines(lines: string[], used: number): string[] {
  const kept: string[] = [];
  let total = used;
  for (const line of lines) {
    total += [...line].length + 1;
    if (total > SECTION_MAX) break;
    kept.push(line);
  }
  return kept;
}

function pathAt(path: string, line: number | null): string {
  return line === null ? path : `${path}:${line}`;
}

/** The line for the projects with nothing new; `more` when other projects are listed above it. */
function quietLine(count: number, more: boolean): string {
  const noun = count === 1 ? 'project' : 'projects';
  return `${count} ${more ? 'more ' : ''}${noun}: no new security issues, gate passed`;
}

/** C8: the digest's vulnerability section; project lines that do not fit fold into the tail. */
function vulnerabilitiesSection(v: DigestVulnerabilities, links: ChatLinks): SlackBlock {
  const head = `*Vulnerabilities in tracked versions*\n${vulnerabilitySummary(v, (s) => `*${s}*`)}`;
  const all = v.projects.map((p) => {
    const name = link(vulnerabilitiesUrl(links, p.projectId), slackText(p.name, 50));
    return `• ${name} — ${vulnerabilityProjectCounts(p, slackText)}`;
  });
  const lines = packLines(all, [...head].length + 200);
  const more = v.moreProjects + (all.length - lines.length);
  return section([head, ...lines, ...(more > 0 ? [`…and ${more} more projects`] : [])].join('\n'));
}

/** C5: the exploited vulnerabilities of one run, a section per project. */
function exploited(m: ChatExploitedMessage, links: ChatLinks): SlackBody {
  const raw = exploitedTitle(m, (s, max) => plainText(s, max ?? 80));
  const [only] = m.projects;
  const url =
    m.projects.length === 1 && m.moreProjects === 0 && only !== undefined
      ? vulnerabilitiesUrl(links, only.id)
      : projectsUrl(links);
  const sections = m.projects.map((p) => {
    const head = `*${link(vulnerabilitiesUrl(links, p.id), slackText(p.name, MAX_PROJECT_NAME))}*`;
    const all = p.rows.map((r) => `• ${exploitedRowText(r, slackText, (s) => `*${s}*`)}`);
    // 100 is room for the "…and N more" line.
    const rows = packLines(all, [...head].length + 100);
    const more = p.more + (all.length - rows.length);
    return section([head, ...rows, ...(more > 0 ? [`…and ${more} more`] : [])].join('\n'));
  });
  return {
    text: exploitedTitle(m, slackText),
    blocks: [
      header(raw),
      ...sections,
      ...(m.moreProjects > 0 ? [section(`…and ${m.moreProjects} more projects`)] : []),
      ...button(url, 'danger'),
    ],
  };
}

function digest(m: ChatDigestMessage, links: ChatLinks): SlackBody {
  const scopeName = m.scope.project?.name ?? m.scope.organization.name;
  const title = `Weekly security digest — ${plainText(scopeName, 80)}`;
  const t = m.totals;
  const zone = displayZone(m.timezone);
  const summary =
    `*Last 7 days* · ${localDate(m.since, m.timezone)} – ${localDate(m.until, m.timezone)} (${zone})\n` +
    `*${t.newSecurity}* new security issues · *${t.failing}* failing quality gate${t.failing === 1 ? '' : 's'} · *${t.openSecurity}* open security issues\n` +
    `New by severity: ${severityCounts(t.newBySeverity)}`;
  const allRows = m.rows.map((r) => {
    const name = link(projectUrl(links, r.projectId), slackText(r.name, 50));
    const sev = r.newSecurity > 0 ? ` (${severityCounts(r.newBySeverity)})` : '';
    return `• ${name} — ${digestGateLabel(r.gate)} · ${r.newSecurity} new${sev} · ${r.openSecurity} open`;
  });
  // A section holds 3000 characters: rows that do not fit are counted into "…and N more", never
  // cut in the middle (which would also lose the lines after them). 200 is room for the tail.
  const rows = packLines(allRows, '*Projects*'.length + 200);
  const moreProjects = m.moreProjects + (allRows.length - rows.length);
  const tail = [
    ...(moreProjects > 0 ? [`…and ${moreProjects} more projects`] : []),
    ...(m.quietProjects > 0
      ? [quietLine(m.quietProjects, allRows.length + m.moreProjects > 0)]
      : []),
  ];
  const allTop = m.top.map((i) => {
    const where = i.path === null ? '' : ` — \`${slackText(pathAt(i.path, i.line), 120)}\``;
    const rule = link(issueUrl(links, i.projectId, i.id), slackText(i.ruleName, 80));
    return `• ${severityLabel(i.severity)} · ${slackText(i.projectName, 50)} · ${rule}${where}`;
  });
  const top = packLines(allTop, '*Top new issues*'.length);
  const scopeUrl =
    m.scope.project === null ? projectsUrl(links) : projectUrl(links, m.scope.project.id);
  return {
    text: `Weekly security digest — ${slackText(scopeName)}: ${t.newSecurity} new security issues`,
    blocks: [
      header(title),
      section(summary),
      ...(rows.length + tail.length > 0
        ? [section(['*Projects*', ...rows, ...tail].join('\n'))]
        : []),
      ...(m.vulnerabilities === undefined
        ? []
        : [vulnerabilitiesSection(m.vulnerabilities, links)]),
      ...(top.length > 0 ? [section(['*Top new issues*', ...top].join('\n'))] : []),
      context(`Sent every Monday at 09:00 ${zone}`),
      ...button(scopeUrl),
    ],
  };
}

function test(m: ChatTestMessage): SlackBody {
  const scope =
    m.project === null
      ? `every project of ${slackText(m.organization.name)}`
      : `the project ${slackText(m.project.name)}`;
  return {
    text: 'Qualor is connected',
    blocks: [
      header('Qualor is connected'),
      section(
        `This channel will get quality gate failures and recoveries on the main branch, and the weekly security digest, for ${scope}.`,
      ),
    ],
  };
}

export function formatSlack(message: ChatMessage, links: ChatLinks): SlackBody {
  switch (message.type) {
    case 'gate':
      return gate(message, links);
    case 'digest':
      return digest(message, links);
    case 'exploited':
      return exploited(message, links);
    case 'test':
      return test(message);
  }
}
