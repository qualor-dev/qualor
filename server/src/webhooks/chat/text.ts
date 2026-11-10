import { SEVERITIES, type Severity } from '@qualor/shared';
import { clip, failsWhen, metricLabel, metricValue } from '../../mail/templates/notify-common';
import {
  MAX_INSTALLED_VERSIONS,
  MAX_PACKAGE_NAME,
  MAX_PROJECT_NAME,
  MAX_TARGETS,
} from '../../mail/templates/notify-vulnerability-common';
import { oneLine } from '../../mail/text';
import type {
  ChatExploitedMessage,
  ChatGateMessage,
  DigestGate,
  DigestVulnerabilities,
  ExploitedRow,
  VulnerabilitySeverity,
} from './messages';

const Z = '\u200B';
/** Names longer than this are clipped in every message (fits Slack's and Teams' limits). */
export const MAX_NAME = 80;

/** One line, at most `max` characters, as plain text (Slack `plain_text`, never parsed). */
export function plainText(s: string, max: number): string {
  return clip(oneLine(s), max);
}

/**
 * R13: text for Slack mrkdwn (and the top-level `text`): `&`, `<`, `>` escaped as Slack asks,
 * so `<!channel>` or `<@U1>` never mention anyone, and `* _ ~ \`` between zero-width spaces, so
 * they render as themselves instead of opening bold, italics, strike or code.
 */
export function slackText(s: string, max = MAX_NAME): string {
  return plainText(s, max)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[*_~`]/g, (c) => `${Z}${c}${Z}`)
    .replace(/[@#]/g, (c) => `${c}${Z}`);
}

/**
 * R13: text for an Adaptive Card TextBlock or Fact (Teams' markdown subset): emphasis and link
 * brackets between zero-width spaces, and a leading list or heading marker made inert. Teams
 * ignores HTML, so `<`, `>` stay.
 */
export function teamsText(s: string, max = MAX_NAME): string {
  const text = teamsInline(s, max);
  return /^([-+#>]|\d+\.)/.test(text) ? `${Z}${text}` : text;
}

/** `teamsText` for text that never starts a line (after a bullet, a label or other text). */
export function teamsInline(s: string, max = MAX_NAME): string {
  return plainText(s, max).replace(/[*_~`[\]]/g, (c) => `${Z}${c}${Z}`);
}

/** `Quality gate failed — <project> · <branch>` (spec §4), raw: each formatter escapes it. */
export function gateTitle(m: ChatGateMessage, esc: (s: string, max?: number) => string): string {
  const what = m.event === 'gate.failed' ? 'Quality gate failed' : 'Quality gate passes again';
  return `${what} — ${esc(m.project.name, 60)} · ${esc(m.branch.name, 40)}`;
}

/** R6: the email's wording, "Coverage on new code: 61.5% (fails when less than 80%)". */
export function conditionText(
  c: ChatGateMessage['failed'][number],
  esc: (s: string, max?: number) => string,
): string {
  // An unknown metric key is shown as it is: it comes from the sender, so it is escaped.
  const label = esc(metricLabel(c.metric), 100);
  return `${label}: ${metricValue(c.metric, c.value)} (fails when ${failsWhen(c)})`;
}

/** The short commit id, only for a hex revision (anything else could carry markup): else null. */
export function shortRevision(revision: string | null): string | null {
  return revision !== null && /^[0-9a-f]{7,64}$/i.test(revision)
    ? [...revision].slice(0, 7).join('')
    : null;
}

function validZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

/** The zone as written in a message: a valid IANA name (no markup possible), else UTC. */
export function displayZone(zone: string): string {
  return validZone(zone) ? zone : 'UTC';
}

/** "Security 2 · Reliability 0 · Maintainability 0"; null when no count is known. */
export function newCodeText(m: ChatGateMessage): string | null {
  const parts = (
    [
      ['Security', m.newIssues.security],
      ['Reliability', m.newIssues.reliability],
      ['Maintainability', m.newIssues.maintainability],
    ] as const
  ).flatMap(([label, n]) => (n === null ? [] : [`${label} ${n}`]));
  return parts.length === 0 ? null : parts.join(' · ');
}

/** `2026-10-19 07:05 UTC`. */
export function utcTime(iso: string): string {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/** The calendar date of an instant in a zone, `2026-10-19`. */
export function localDate(iso: string, zone: string): string {
  // en-CA writes dates as YYYY-MM-DD.
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: displayZone(zone),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date(iso));
}

const GATE_LABELS: Record<DigestGate, string> = {
  passed: 'gate passed',
  failed: 'gate failed',
  error: 'gate error',
  none: 'no gate',
  never: 'not analysed yet',
};

export function digestGateLabel(g: DigestGate): string {
  return GATE_LABELS[g];
}

const SEVERITY_LABELS: Record<Severity, string> = {
  blocker: 'Blocker',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function severityLabel(s: Severity): string {
  return SEVERITY_LABELS[s];
}

const VULNERABILITY_SEVERITY_LABELS: Record<VulnerabilitySeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
};

/** A vulnerability's severity (not an issue severity). */
export function vulnerabilitySeverityLabel(s: VulnerabilitySeverity): string {
  return VULNERABILITY_SEVERITY_LABELS[s];
}

/** `YYYY-MM-DD` of a stored date (the schema already guarantees the shape). */
export function kevDate(s: string): string {
  return s.slice(0, 10);
}

type Esc = (s: string, max?: number) => string;

/** C5 title, raw: each formatter escapes the project name. `more` rows count too. */
export function exploitedTitle(m: ChatExploitedMessage, esc: Esc): string {
  const [first] = m.projects;
  if (m.projects.length === 1 && first !== undefined && m.moreProjects === 0) {
    const n = first.rows.length + first.more;
    const where = esc(first.name, MAX_PROJECT_NAME);
    return n === 1
      ? `Exploited vulnerability in ${where}`
      : `${n} exploited vulnerabilities in ${where}`;
  }
  return `Exploited vulnerabilities in ${m.projects.length + m.moreProjects} projects`;
}

/** C8 exploited row, without its bullet. `bold` wraps the id (Slack); `esc` escapes the parts. */
export function exploitedRowText(r: ExploitedRow, esc: Esc, bold: (s: string) => string): string {
  const fix = r.fixedVersion === null ? 'no fix yet' : `fixed in ${esc(r.fixedVersion, 40)}`;
  return (
    `${bold(esc(r.vulnerabilityId, 60))} (${vulnerabilitySeverityLabel(r.severity)}) in ` +
    `${esc(r.packageName, MAX_PACKAGE_NAME)} ${esc(r.installedVersions.join(', '), MAX_INSTALLED_VERSIONS)}` +
    ` — ${fix} · ${esc(r.targets.join(', '), MAX_TARGETS)} · in KEV since ${kevDate(r.kevDateAdded)}`
  );
}

/** C8 digest summary: counts, with the exploited one only when it is known. */
export function vulnerabilitySummary(
  v: DigestVulnerabilities,
  bold: (s: string) => string,
): string {
  const x = v.exploited === null ? '' : ` · ${bold(String(v.exploited))} exploited`;
  return `${bold(String(v.critical))} critical · ${bold(String(v.high))} high new vulnerabilities${x}`;
}

/** C8 digest project line, without bullet and name. */
export function vulnerabilityProjectCounts(
  p: DigestVulnerabilities['projects'][number],
  esc: Esc,
): string {
  const x = p.exploited === null ? '' : `, ${p.exploited} exploited`;
  const more = p.moreTargets > 0 ? ` +${p.moreTargets} more` : '';
  const targets = p.targets.map((t) => esc(t, 40)).join(', ');
  return `${p.critical} critical, ${p.high} high${x} · ${targets}${more}`;
}

/** "High 2 · Medium 1": only the severities that have issues; "none" when none has. */
export function severityCounts(c: Record<Severity, number>): string {
  const parts = SEVERITIES.filter((s) => c[s] > 0).map((s) => `${SEVERITY_LABELS[s]} ${c[s]}`);
  return parts.length === 0 ? 'none' : parts.join(' · ');
}
