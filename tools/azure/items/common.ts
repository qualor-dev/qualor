/**
 * What the probe items share: the context `probe.ts` hands each item, shape checks, recordings,
 * clean-up, and the Azure DevOps calls more than one item makes (branch, pull request, thread,
 * build definition, the webhook recorder).
 */
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import { z } from 'zod';
import type { AzureAuth, AzureClient, AzureResponse } from '../client.js';
import { LISTED_KINDS, redact, type RedactionTable } from '../record.js';

/** The policy type id of a Build validation branch policy. */
export const BUILD_POLICY = '0609b952-1397-4640-95ec-e00a01b2c241';

export type TargetName = 'services' | 'server';
/** An item's answer; `interrupted`: stopped by Ctrl+C before it could answer. */
export type Answer =
  'yes' | 'no' | 'partly' | 'manual' | 'per-collection' | 'per-pull-request' | 'interrupted';
/** `links` (pull request URLs for a visual check) go to the console and the local results only. */
export type ProbeResult = {
  answer: Answer;
  detail: string;
  recordings: string[];
  links?: string[];
};

/** A branch (and its pull request) a manual item leaves open; `--cleanup-manual` closes it. */
export type ManualPr = { branch: string; id?: number };

/** A check that runs after the item's clean-up; `ok: false` turns the item's answer into no. */
export type Verification = () => Promise<{ ok: boolean; text: string }>;

export type ProbeContext = {
  target: TargetName;
  baseUrl: string;
  caPem?: string;
  /**
   * auth: qualor-bot on server (Project Administrator of the probe project); on services the
   * `--auth` credential (the PAT owner, or the Entra service principal).
   */
  bot: AzureClient;
  /** probe-user (Contributor). */
  user: AzureClient;
  userAuth: AzureAuth;
  /** probe-reader (Reader); server only. */
  reader?: AzureClient;
  /** bench-admin (Project Collection Administrator); server only, for collection-level rights. */
  admin?: AzureClient;
  /** A client with the target's main PAT (`AZURE_PROBE_<TARGET>_PAT`), whatever `--auth` chose. */
  pat: AzureClient;
  /** A client signed in with an Entra credential kind; undefined where there is no Entra (server). */
  entra?: (kind: 'secret' | 'certificate') => AzureClient;
  hookBase: string;
  recorderSecret: string;
  project: string;
  repo: string;
  /** UTC time of the run, `YYYYMMDDHHmmss`, in every branch and object name. */
  stamp: string;
  item: number;
  redaction: RedactionTable;
  recordings: string[];
  cleanup: Cleanup;
  /** Set by pushFiles/createPr with `keep`: written to the results for `--cleanup-manual`. */
  manualPr?: ManualPr;
  /** Checks run after the clean-up (shared state restored); their verdicts join the detail. */
  verifications: { label: string; check: Verification }[];
  /** Saves `value`, redacted, as `server/test/azure-shapes/<target>/<item>-<call>.json`. */
  record(call: string, value: unknown): Promise<string>;
  log(line: string): void;
};

export type ProbeItem = { id: number; title: string; run(ctx: ProbeContext): Promise<ProbeResult> };

export const result = (
  ctx: ProbeContext,
  answer: Answer,
  detail: string,
  links?: string[],
): ProbeResult => ({
  answer,
  detail,
  recordings: [...ctx.recordings],
  ...(links ? { links } : {}),
});

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** The thread id inside a comment event's `_links.threads.href` (`…/pullRequests/1/threads/5`). */
export function threadIdFromHref(href: string): number | undefined {
  const m = /\/threads\/(\d+)(?:[/?#]|$)/i.exec(href);
  return m ? Number(m[1]) : undefined;
}

/** `YYYYMMDDHHmmss` in UTC. */
export function stampOf(date: Date): string {
  return date.toISOString().replace(/\D/g, '').slice(0, 14);
}

/** What kind of name a value is, without saying the name: for results that must hold none. */
export function nameKind(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return 'absent';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))
    return 'a GUID';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) return 'an e-mail address';
  if (/^[^\\\s]+\\[^\\]+$/.test(value)) return 'DOMAIN\\account';
  return `a plain name (${value.length} characters)`;
}

const SECRET_KEY = /(?:PAT|PASSWORD|SECRET|TOKEN|API_KEY|LLM_KEY)$/;

function hostsOf(url: string | undefined): string[] {
  if (!url) return [];
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return [];
  }
  const out = [host];
  // An AWS public name (ec2-1-2-3-4.region.compute.amazonaws.com) and an sslip.io name carry an IP.
  const ec2 = /^ec2-(\d+)-(\d+)-(\d+)-(\d+)\./.exec(host);
  if (ec2) out.push(ec2.slice(1, 5).join('.'));
  const sslip = /^(\d+\.\d+\.\d+\.\d+)\.sslip\.io$/.exec(host);
  if (sslip?.[1]) out.push(sslip[1]);
  return out;
}

/** A value as it is, in lower and upper case, and URL-encoded (a name in a link). */
function withCases(values: string[]): string[] {
  const cased = values.flatMap((v) => [v, v.toLowerCase(), v.toUpperCase()]);
  return [...new Set([...cased, ...cased.map((v) => encodeURIComponent(v))])].filter(
    (v) => v.length > 0,
  );
}

/**
 * The redaction table of a run, from the environment: every PAT, password and secret (also as the
 * Basic credentials that carry them), the tenant id, the hosts of the targets and the recorder, the
 * Services organisation's name (from its URL), the probe's project (`AZURE_PROBE_PROJECT`), and the
 * salt of the synthetic ids (`AZURE_PROBE_ID_SALT`). People's names are added once the run has
 * asked who each credential is ({@link addIdentity}).
 */
export function buildRedactionTable(env: Record<string, string | undefined>): RedactionTable {
  const secrets: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (!value || !key.startsWith('AZURE_PROBE_') || !SECRET_KEY.test(key)) continue;
    secrets.push(value, Buffer.from(`:${value}`).toString('base64'));
  }
  const recorder = env['AZURE_PROBE_RECORDER_SECRET'];
  if (recorder) secrets.push(Buffer.from(`qualor:${recorder}`).toString('base64'));
  const servicesUrl = env['AZURE_PROBE_SERVICES_URL'];
  const orgs: string[] = [];
  if (servicesUrl) {
    try {
      const org = new URL(servicesUrl).pathname.split('/').filter(Boolean)[0];
      if (org) orgs.push(org);
    } catch {
      // not a URL: loadTarget's client refuses it before any request
    }
  }
  // The project's name is the operator's choice (on a bench often the organisation's name).
  const project = env['AZURE_PROBE_PROJECT'];
  if (project) orgs.push(project);
  const servicesHosts = hostsOf(servicesUrl).filter((h) => h !== 'dev.azure.com');
  const salt = env['AZURE_PROBE_ID_SALT'];
  return {
    ...(salt ? { idSalt: salt } : {}),
    secrets,
    emails: [],
    names: [],
    tenantIds: env['AZURE_PROBE_TENANT_ID'] ? [env['AZURE_PROBE_TENANT_ID']] : [],
    hosts: withCases([
      ...hostsOf(env['AZURE_PROBE_SERVER_URL']),
      ...hostsOf(env['AZURE_PROBE_HOOK_BASE']),
      ...hostsOf(env['AZURE_PROBE_QUALOR_URL']),
      ...servicesHosts,
    ]),
    orgs: withCases(orgs),
  };
}

/** Adds host or machine names (a Windows domain, a build agent) to the table. */
export function addHosts(table: RedactionTable, values: string[]): void {
  table.hosts.push(...withCases(values.filter((v) => v.length >= 3)));
}

/** Adds what an identity (connectionData's `authenticatedUser`, an identities entry) says. */
export function addIdentity(table: RedactionTable, identity: unknown): void {
  const parsed = IdentitySchema.safeParse(identity);
  if (!parsed.success) return;
  const id = parsed.data;
  // The identities API names the Windows machine (or domain) of a Server account.
  const domain = id.properties?.Domain?.$value;
  if (domain) addHosts(table, [domain]);
  const values = [
    id.providerDisplayName,
    id.customDisplayName,
    id.properties?.Account?.$value,
    id.properties?.Mail?.$value,
    id.properties?.DirectoryAlias?.$value,
  ].filter((v): v is string => typeof v === 'string' && v.length > 0);
  for (const v of values) {
    if (v.includes('@')) {
      table.emails.push(...withCases([v]));
      continue;
    }
    const slash = v.indexOf('\\');
    if (slash > 0) {
      // DOMAIN\account: the domain is a machine or tenant name, the account a person's.
      table.hosts.push(...withCases([v.slice(0, slash)]));
      table.names.push(...withCases([v.slice(slash + 1)]));
      continue;
    }
    table.names.push(...withCases([v]));
  }
}

const PLACEHOLDERS = [
  '<secret>',
  'user@example.invalid',
  'ado.example.invalid',
  '00000000-0000-0000-0000-00000000000t',
  'Probe User',
  'probe-org',
];

/** The listed values a redacted text still holds (case-insensitive); empty when it is clean. */
export function leaks(text: string, table: RedactionTable): string[] {
  let rest = text;
  for (const p of PLACEHOLDERS) rest = rest.split(p).join(' ');
  const lower = rest.toLowerCase();
  const found: string[] = [];
  for (const kind of LISTED_KINDS) {
    for (const v of table[kind]) {
      if (v.length >= 3 && lower.includes(v.toLowerCase())) found.push(kind);
    }
  }
  return [...new Set(found)];
}

/**
 * The first `length` characters of `text` after redaction: cut first, a listed value split by the
 * cut (an organisation name in a URL, say) would keep its start.
 */
export function excerpt(text: string, table: RedactionTable, length = 200): string {
  return String(redact(text, table)).slice(0, length);
}

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;

/** Any e-mail address left (a commit author in a build log, say) becomes the placeholder. */
export function scrubEmails(text: string): string {
  return text.replace(EMAIL, (m) => (m === 'user@example.invalid' ? m : 'user@example.invalid'));
}

export type AuthKind = 'pat' | 'secret' | 'certificate';

/**
 * The target, the items a `--items 1,3,4` list names (all known items when absent) and the main
 * identity's credential kind `--auth pat|secret|certificate` (pat when absent; Entra kinds on
 * services only).
 */
export function parseArgs(argv: string[]): {
  target: TargetName;
  items?: number[];
  cleanupManual?: true;
  auth?: AuthKind;
  verifyApply?: number;
} {
  let target: string | undefined;
  let items: number[] | undefined;
  let cleanupManual = false;
  let auth: AuthKind | undefined;
  let verifyApply: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const [flag, inline] = (arg ?? '').split('=', 2);
    const value = (): string => {
      const v = inline ?? argv[++i];
      if (v === undefined) throw new Error(`${flag} needs a value`);
      return v;
    };
    if (flag === '--target') target = value();
    else if (flag === '--auth') {
      const kind = value();
      if (kind !== 'pat' && kind !== 'secret' && kind !== 'certificate') {
        throw new Error(`--auth pat|secret|certificate, not ${kind}`);
      }
      auth = kind;
    } else if (flag === '--verify-apply') {
      const raw = value();
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0) throw new Error(`not a pull request id: ${raw}`);
      verifyApply = n;
    } else if (flag === '--cleanup-manual' && inline === undefined) cleanupManual = true;
    else if (flag === '--items') {
      items = value()
        .split(',')
        .filter((s) => s.trim().length > 0)
        .map((s) => {
          const n = Number(s.trim());
          if (!Number.isInteger(n) || n <= 0) throw new Error(`not an item number: ${s}`);
          return n;
        });
    } else if (arg !== '--') throw new Error(`unknown argument: ${arg}`);
  }
  if (target !== 'services' && target !== 'server') {
    throw new Error('--target services|server is required');
  }
  if (cleanupManual && items) throw new Error('--cleanup-manual takes no --items');
  if (target === 'server' && auth && auth !== 'pat') {
    throw new Error(`--auth ${auth}: server has no Entra (pat only)`);
  }
  if (verifyApply !== undefined && !(items?.length === 1 && items[0] === 23)) {
    throw new Error('--verify-apply <prId> goes with --items 23 only');
  }
  const withAuth = {
    ...(auth ? { auth } : {}),
    ...(verifyApply !== undefined ? { verifyApply } : {}),
  };
  if (cleanupManual) return { target, cleanupManual: true, ...withAuth };
  return items ? { target, items, ...withAuth } : { target, ...withAuth };
}

/**
 * The branches and pull requests the manual items of `target` left open, from the results file's
 * `Manual PR: <id> (<branch>)` and `Manual branch: <branch>` lines under that target's item headings.
 */
export function manualPrsFrom(text: string, target: TargetName): ManualPr[] {
  const out: ManualPr[] = [];
  let inTarget = false;
  for (const line of text.split(/\r?\n/)) {
    const heading = /^## (\S+) — item \d+:/.exec(line);
    if (heading) inTarget = heading[1] === target;
    else if (line.startsWith('## ')) inTarget = false;
    if (!inTarget) continue;
    const pr = /^Manual PR: (\d+) \((refs\/heads\/probe\/[^)\s]+)\)$/.exec(line);
    const branch = /^Manual branch: (refs\/heads\/probe\/\S+)$/.exec(line);
    if (pr?.[1] && pr[2]) out.push({ id: Number(pr[1]), branch: pr[2] });
    else if (branch?.[1]) out.push({ branch: branch[1] });
  }
  return out;
}

/** What `--cleanup-manual` does with one listed branch and its pull request. */
export type ManualStep = {
  /** Abandon the pull request (it is active and from the listed branch). */
  abandon: boolean;
  /** Delete the listed branch. */
  deleteBranch: boolean;
  /** What was found or is done about the pull request; none when no pull request is listed. */
  note?: string;
};

/**
 * The decision of `--cleanup-manual` for `m`, given its pull request as it reads now (`null`: the
 * id answers 404; `undefined`: no id is listed). The branch goes only when its pull request is
 * abandoned (now or before) or there is none; a pull request from another branch leaves both
 * alone, and a completed one leaves its branch alone.
 */
export function manualStep(
  m: ManualPr,
  found: { sourceRefName: string; status: string } | null | undefined,
): ManualStep {
  if (m.id === undefined) return { abandon: false, deleteBranch: true };
  if (!found) return { abandon: false, deleteBranch: true, note: `PR ${m.id} not found` };
  if (found.sourceRefName !== m.branch) {
    return {
      abandon: false,
      deleteBranch: false,
      note: `PR ${m.id} is from ${found.sourceRefName}, not ${m.branch}: both left alone`,
    };
  }
  if (found.status === 'active') {
    return { abandon: true, deleteBranch: true, note: `PR ${m.id} abandoned` };
  }
  if (found.status === 'abandoned') {
    return { abandon: false, deleteBranch: true, note: `PR ${m.id} already abandoned` };
  }
  return {
    abandon: false,
    deleteBranch: false,
    note: `PR ${m.id} is ${found.status}: its branch is left alone`,
  };
}

/** The lines of a build log as the Build logs API answers it in JSON (`{count, value: [...]}`). */
export function logLines(json: unknown): string[] {
  const parsed = z.object({ value: z.array(z.string()) }).safeParse(json);
  if (parsed.success) return parsed.data.value;
  return typeof json === 'string' ? json.split(/\r?\n/) : [];
}

/** A log line without the agent's leading ISO timestamp. */
export const logText = (line: string): string => line.replace(/^\d{4}-\d{2}-\d{2}T\S+\s/, '');

/**
 * The lines of a step log a recording keeps: the `name=value` lines the probe printed and, when
 * given, the lines from one marker line to the next (a `git cat-file` block), markers included. A
 * start marker without an end keeps nothing after it (the item reads such a block as absent too):
 * the rest of the log names the agent and its machine.
 */
export function keptLogLines(lines: string[], names: string[], block?: [string, string]): string[] {
  const texts = lines.map((line) => logText(line).trim());
  const inBlock = new Set<number>();
  if (block) {
    let start = texts.indexOf(block[0]);
    while (start >= 0) {
      const end = texts.indexOf(block[1], start + 1);
      if (end < 0) break;
      for (let i = start; i <= end; i++) inBlock.add(i);
      start = texts.indexOf(block[0], end + 1);
    }
  }
  return lines.filter(
    (_line, i) => inBlock.has(i) || names.some((n) => (texts[i] ?? '').startsWith(`${n}=`)),
  );
}

/** `name=value` lines the probe pipelines print, as a map (the first value of each name wins). */
export function printedValues(lines: string[], names: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of lines) {
    // Agent log lines start with an ISO timestamp and a space.
    const text = line.replace(/^\d{4}-\d{2}-\d{2}T\S+\s/, '');
    for (const name of names) {
      if (out[name] === undefined && text.startsWith(`${name}=`)) {
        out[name] = text.slice(name.length + 1).trim();
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Shapes, errors, recordings

export class ShapeError extends Error {
  override readonly name = 'ShapeError';
}

/** `schema`'s parse of `value`, or a ShapeError naming `what` and the issues (the item answers no). */
export function shape<T extends z.ZodType>(schema: T, value: unknown, what: string): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (parsed.success) return parsed.data;
  const issues = parsed.error.issues
    .slice(0, 5)
    .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('; ');
  throw new ShapeError(`${what} has an unexpected shape: ${issues}`);
}

/** The `message` of an Azure DevOps error body, else the start of the body. */
export function messageOf(json: unknown): string {
  if (json && typeof json === 'object' && 'message' in json) {
    const m = (json as { message: unknown }).message;
    if (typeof m === 'string') return m.slice(0, 300);
  }
  if (typeof json === 'string') return json.slice(0, 200);
  return JSON.stringify(json ?? null).slice(0, 200);
}

export class CallError extends Error {
  override readonly name = 'CallError';
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** `res` when it is a 2xx; a CallError with the status and Azure DevOps's message otherwise. */
export function ok(res: AzureResponse, what: string): AzureResponse {
  if (res.status >= 200 && res.status < 300) return res;
  throw new CallError(`${what}: HTTP ${res.status} ${messageOf(res.json)}`, res.status);
}

function createdField(res: AzureResponse, key: string): unknown {
  return res.json && typeof res.json === 'object'
    ? (res.json as Record<string, unknown>)[key]
    : undefined;
}

/**
 * The numeric id a 2xx create answered, read loosely: enough to register the object's clean-up
 * before anything that can throw (a recording's leak check, the full shape check) runs.
 */
export function createdNumber(res: AzureResponse, key: string, what: string): number {
  const v = createdField(res, key);
  if (typeof v === 'number') return v;
  throw new ShapeError(`${what} answered HTTP ${res.status} without a numeric ${key}`);
}

/** {@link createdNumber} for a string id (a service hook subscription's GUID). */
export function createdString(res: AzureResponse, key: string, what: string): string {
  const v = createdField(res, key);
  if (typeof v === 'string' && v.length > 0) return v;
  throw new ShapeError(`${what} answered HTTP ${res.status} without a ${key}`);
}

/** What a recording keeps of a response: the status, the content type and the body. */
export function answerOf(res: AzureResponse): {
  status: number;
  contentType: string | null;
  body: unknown;
} {
  return { status: res.status, contentType: res.headers['content-type'] ?? null, body: res.json };
}

export const SHAPES_ROOT = fileURLToPath(
  new URL('../../../server/test/azure-shapes', import.meta.url),
);

/**
 * Writes `value` redacted under `root` (the committed shapes by default); refuses (throws, writes
 * nothing) without the synthetic-id salt or when anything listed survives redaction.
 */
export async function writeRecording(
  table: RedactionTable,
  target: TargetName,
  item: number,
  call: string,
  value: unknown,
  root: string = SHAPES_ROOT,
): Promise<string> {
  if (!/^[a-z0-9-]+$/.test(call)) throw new Error(`recording name ${call} is not kebab-case`);
  if (!table.idSalt) {
    throw new Error(`recording ${item}-${call}: AZURE_PROBE_ID_SALT is not set; not written`);
  }
  const text = scrubEmails(JSON.stringify(redact(value, table), null, 2));
  const leaked = leaks(text, table);
  if (leaked.length > 0) {
    throw new Error(
      `recording ${item}-${call} would still hold: ${leaked.join(', ')}; not written`,
    );
  }
  const dir = path.join(root, target);
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, `${item}-${call}.json`);
  const options = (await resolveConfig(file)) ?? {};
  await writeFile(file, await format(text, { ...options, filepath: file }), 'utf8');
  return `server/test/azure-shapes/${target}/${item}-${call}.json`;
}

// ---------------------------------------------------------------------------------------------
// Clean-up

export class Cleanup {
  private steps: { label: string; fn: () => Promise<unknown> }[] = [];
  private running: { label: string; fn: () => Promise<unknown> }[] = [];

  add(label: string, fn: () => Promise<unknown>): void {
    this.steps.push({ label, fn });
  }

  /**
   * Runs every step once, newest first; returns the steps that failed, with why. The steps are
   * taken before the first one runs, so a second `run()` meanwhile finds none to repeat.
   */
  async run(): Promise<string[]> {
    const steps = [...this.steps].reverse();
    this.steps = [];
    this.running.push(...steps);
    const failed: string[] = [];
    for (const step of steps) {
      try {
        await step.fn();
      } catch (err) {
        failed.push(`${step.label}: ${(err as Error).message}`);
      } finally {
        this.running.splice(this.running.indexOf(step), 1);
      }
    }
    return failed;
  }

  /** The steps not finished yet, queued or running (what an immediate exit would leave behind). */
  pending(): string[] {
    return [...this.running, ...this.steps].map((s) => s.label);
  }
}

/** A DELETE that counts 404 (already gone) as done. */
export async function remove(client: AzureClient, p: string, what: string, apiVersion?: string) {
  const res = await client.request('DELETE', p, undefined, apiVersion ? { apiVersion } : {});
  if (res.status === 404) return;
  ok(res, `delete ${what}`);
}

/** Set by the probe's Ctrl+C handler: the items' waits end, so the item aborts and cleans up. */
export const stop = { requested: false };

export class InterruptedError extends Error {
  override readonly name = 'InterruptedError';
}

/** A pause of the probe's waits; throws InterruptedError once a stop is requested. */
export async function sleep(ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (stop.requested) throw new InterruptedError('interrupted (Ctrl+C)');
    await new Promise((r) => setTimeout(r, Math.min(500, end - Date.now())));
  }
  if (stop.requested) throw new InterruptedError('interrupted (Ctrl+C)');
}

/** Polls `fn` until it gives a value or `timeoutMs` passes; undefined then. */
export async function waitFor<T>(
  fn: () => Promise<T | undefined>,
  opts: { timeoutMs: number; intervalMs?: number },
): Promise<T | undefined> {
  const end = Date.now() + opts.timeoutMs;
  for (;;) {
    const value = await fn();
    if (value !== undefined) return value;
    if (Date.now() >= end) return undefined;
    await sleep(opts.intervalMs ?? 3000);
  }
}

// ---------------------------------------------------------------------------------------------
// Shapes the items read

export const IdentitySchema = z.object({
  id: z.string(),
  descriptor: z.string().optional(),
  subjectDescriptor: z.string().optional(),
  providerDisplayName: z.string().optional(),
  customDisplayName: z.string().optional(),
  isActive: z.boolean().optional(),
  properties: z
    .object({
      Account: z.object({ $value: z.string() }).optional(),
      Mail: z.object({ $value: z.string() }).optional(),
      Domain: z.object({ $value: z.string() }).optional(),
      DirectoryAlias: z.object({ $value: z.string() }).optional(),
    })
    .loose()
    .optional(),
});

export const ConnectionDataSchema = z.object({
  authenticatedUser: IdentitySchema,
  authorizedUser: IdentitySchema.optional(),
  instanceId: z.string(),
  deploymentType: z.string().optional(),
});

const RepoSchema = z.object({
  id: z.string(),
  name: z.string(),
  defaultBranch: z.string(),
  webUrl: z.string(),
  project: z.object({ id: z.string(), name: z.string() }),
});
export type Repo = z.infer<typeof RepoSchema>;

const RefsSchema = z.object({
  value: z.array(z.object({ name: z.string(), objectId: z.string() })),
});

const PushSchema = z.object({
  commits: z.array(z.object({ commitId: z.string() })).min(1),
  refUpdates: z.array(z.object({ name: z.string(), newObjectId: z.string() })).min(1),
});

export const PrSchema = z.object({
  pullRequestId: z.number(),
  status: z.string(),
  sourceRefName: z.string(),
  targetRefName: z.string(),
  codeReviewId: z.number().optional(),
  artifactId: z.string().optional(),
  lastMergeSourceCommit: z.object({ commitId: z.string() }).optional(),
  lastMergeTargetCommit: z.object({ commitId: z.string() }).optional(),
  lastMergeCommit: z.object({ commitId: z.string() }).optional(),
  repository: z.object({ id: z.string() }),
});
export type Pr = z.infer<typeof PrSchema>;

export const ThreadSchema = z.object({
  id: z.number(),
  status: z.union([z.string(), z.number()]).optional(),
  isDeleted: z.boolean().optional(),
  properties: z.record(z.string(), z.unknown()).nullish(),
  threadContext: z.unknown().optional(),
  pullRequestThreadContext: z.unknown().optional(),
  comments: z.array(
    z.object({
      id: z.number(),
      parentCommentId: z.number().optional(),
      content: z.string().optional(),
      commentType: z.union([z.string(), z.number()]).optional(),
      isDeleted: z.boolean().optional(),
      author: z.object({ id: z.string() }).loose(),
    }),
  ),
});
export type Thread = z.infer<typeof ThreadSchema>;

export const ThreadListSchema = z.object({ value: z.array(ThreadSchema) });

// ---------------------------------------------------------------------------------------------
// Git: repository, branches, pull requests, threads

const repoCache = new WeakMap<ProbeContext, Repo>();

export async function repoInfo(ctx: ProbeContext): Promise<Repo> {
  const cached = repoCache.get(ctx);
  if (cached) return cached;
  const res = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/git/repositories/${ctx.repo}`),
    'repository',
  );
  const repo = shape(RepoSchema, res.json, 'repository');
  repoCache.set(ctx, repo);
  return repo;
}

export const gitPath = (ctx: ProbeContext, repo: Repo, rest: string): string =>
  `/${ctx.project}/_apis/git/repositories/${repo.id}${rest}`;

export async function refHead(
  ctx: ProbeContext,
  refName: string,
  client: AzureClient = ctx.bot,
): Promise<string | undefined> {
  const repo = await repoInfo(ctx);
  const filter = encodeURIComponent(refName.replace(/^refs\//, ''));
  const res = ok(await client.request('GET', gitPath(ctx, repo, `/refs?filter=${filter}`)), 'refs');
  return shape(RefsSchema, res.json, 'refs').value.find((r) => r.name === refName)?.objectId;
}

export type NewFile = { path: string; content: string };

/**
 * Pushes one commit adding `files` onto `branch` (a new branch from `base`, the default branch's
 * head when absent; or the branch's own head when it exists). A new branch is deleted at clean-up
 * unless `keep` (a manual item's, left open for a visual check; `--cleanup-manual` deletes it).
 */
export async function pushFiles(
  ctx: ProbeContext,
  branch: string,
  files: NewFile[],
  opts: { client?: AzureClient; base?: string; comment?: string; keep?: boolean } = {},
): Promise<{ refName: string; commitId: string }> {
  const client = opts.client ?? ctx.bot;
  const repo = await repoInfo(ctx);
  const refName = `refs/heads/${branch}`;
  const existing = await refHead(ctx, refName, client);
  let parent = existing;
  if (!parent) {
    parent = opts.base ?? (await refHead(ctx, repo.defaultBranch, client));
    if (!parent) throw new Error(`no head for ${repo.defaultBranch}`);
  }
  const body = {
    refUpdates: [{ name: refName, oldObjectId: existing ?? '0'.repeat(40) }],
    commits: [
      {
        comment: opts.comment ?? `Qualor probe item ${ctx.item}`,
        parents: [parent],
        changes: files.map((f) => ({
          changeType: 'add',
          item: { path: f.path },
          newContent: { content: f.content, contentType: 'rawtext' },
        })),
      },
    ],
  };
  if (!existing && opts.keep) ctx.manualPr = { branch: refName };
  if (!existing && !opts.keep) {
    ctx.cleanup.add(`delete branch ${branch}`, () => deleteBranch(ctx, refName));
  }
  const res = ok(await client.request('POST', gitPath(ctx, repo, '/pushes'), body), 'push');
  const push = shape(PushSchema, res.json, 'push');
  const commitId = push.commits[push.commits.length - 1]?.commitId ?? '';
  return { refName, commitId };
}

/** A new branch at `commitId` with no commit of its own (a pull request target). */
export async function createBranchAt(
  ctx: ProbeContext,
  branch: string,
  commitId: string,
): Promise<string> {
  const repo = await repoInfo(ctx);
  const refName = `refs/heads/${branch}`;
  const res = ok(
    await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: refName, oldObjectId: '0'.repeat(40), newObjectId: commitId },
    ]),
    'create branch',
  );
  const updates = shape(
    z.object({ value: z.array(z.object({ success: z.boolean(), updateStatus: z.string() })) }),
    res.json,
    'ref update',
  );
  if (!updates.value.every((u) => u.success)) {
    throw new Error(`create branch ${branch}: ${updates.value.map((u) => u.updateStatus).join()}`);
  }
  // Only a branch this call created is deleted: a failed create may have met someone else's.
  ctx.cleanup.add(`delete branch ${branch}`, () => deleteBranch(ctx, refName));
  return refName;
}

export async function deleteBranch(ctx: ProbeContext, refName: string): Promise<void> {
  const repo = await repoInfo(ctx);
  const head = await refHead(ctx, refName);
  if (!head) return;
  ok(
    await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: refName, oldObjectId: head, newObjectId: '0'.repeat(40) },
    ]),
    `delete ${refName}`,
  );
}

/** Opens a pull request; abandons it at clean-up unless `keep` (a manual item's, left open). */
export async function createPr(
  ctx: ProbeContext,
  sourceRefName: string,
  opts: { targetRefName?: string; title?: string; client?: AzureClient; keep?: boolean } = {},
): Promise<{ pr: Pr; res: AzureResponse; webUrl: string }> {
  const client = opts.client ?? ctx.bot;
  const repo = await repoInfo(ctx);
  const res = ok(
    await client.request('POST', gitPath(ctx, repo, '/pullrequests'), {
      sourceRefName,
      targetRefName: opts.targetRefName ?? repo.defaultBranch,
      title: opts.title ?? `Qualor probe item ${ctx.item} (${ctx.stamp})`,
      description: `Opened by the Qualor Azure DevOps probe, item ${ctx.item}.`,
    }),
    'create pull request',
  );
  const id = createdNumber(res, 'pullRequestId', 'create pull request');
  if (opts.keep) ctx.manualPr = { branch: sourceRefName, id };
  else ctx.cleanup.add(`abandon pull request ${id}`, () => abandonPr(ctx, id));
  const pr = shape(PrSchema, res.json, 'pull request');
  return { pr, res, webUrl: `${repo.webUrl}/pullrequest/${id}` };
}

export async function abandonPr(ctx: ProbeContext, id: number): Promise<void> {
  const repo = await repoInfo(ctx);
  ok(
    await ctx.bot.request('PATCH', gitPath(ctx, repo, `/pullrequests/${id}`), {
      status: 'abandoned',
    }),
    `abandon pull request ${id}`,
  );
}

export async function getPr(
  ctx: ProbeContext,
  id: number,
): Promise<{ pr: Pr; res: AzureResponse }> {
  const repo = await repoInfo(ctx);
  const res = ok(await ctx.bot.request('GET', gitPath(ctx, repo, `/pullrequests/${id}`)), 'pr');
  return { pr: shape(PrSchema, res.json, 'pull request'), res };
}

/** The pull request once Azure DevOps has computed its merge commit (or after `timeoutMs`). */
export async function prWithMerge(ctx: ProbeContext, id: number, timeoutMs = 60_000) {
  const merged = await waitFor(
    async () => {
      const got = await getPr(ctx, id);
      return got.pr.lastMergeCommit && got.pr.lastMergeSourceCommit ? got : undefined;
    },
    { timeoutMs, intervalMs: 2000 },
  );
  return merged ?? (await getPr(ctx, id));
}

export const threadsPath = (ctx: ProbeContext, repo: Repo, prId: number, rest = ''): string =>
  gitPath(ctx, repo, `/pullRequests/${prId}/threads${rest}`);

/** The latest iteration of a pull request and the change tracking id of `filePath` in it. */
export async function changeTracking(
  ctx: ProbeContext,
  prId: number,
  filePath: string,
): Promise<{ iterationId: number; changeTrackingId: number; changes: AzureResponse }> {
  const repo = await repoInfo(ctx);
  const iterations = shape(
    z.object({ value: z.array(z.object({ id: z.number() })).min(1) }),
    ok(
      await ctx.bot.request('GET', gitPath(ctx, repo, `/pullRequests/${prId}/iterations`)),
      'iterations',
    ).json,
    'iterations',
  );
  const iterationId = Math.max(...iterations.value.map((i) => i.id));
  const changes = ok(
    await ctx.bot.request(
      'GET',
      gitPath(ctx, repo, `/pullRequests/${prId}/iterations/${iterationId}/changes`),
    ),
    'iteration changes',
  );
  const entries = shape(
    z.object({
      changeEntries: z.array(
        z.object({ changeTrackingId: z.number(), item: z.object({ path: z.string() }) }),
      ),
    }),
    changes.json,
    'iteration changes',
  );
  const entry = entries.changeEntries.find((e) => e.item.path === filePath);
  if (!entry) throw new ShapeError(`iteration ${iterationId} has no change for ${filePath}`);
  return { iterationId, changeTrackingId: entry.changeTrackingId, changes };
}

/** A small TypeScript file for right-side line threads (10 lines). */
export function probeSource(ctx: ProbeContext): NewFile {
  const lines = [
    `// Qualor probe item ${ctx.item} (${ctx.stamp})`,
    'export function probeValue(input: number): number {',
    '  const doubled = input * 2;',
    '  const unused = doubled + 1;',
    '  return doubled;',
    '}',
    '',
    'export const probeName = "qualor";',
    'export const probeList = [1, 2, 3];',
    'export default probeValue;',
  ];
  return { path: `/probe/item-${ctx.item}-${ctx.stamp}.ts`, content: `${lines.join('\n')}\n` };
}

/** The body of a thread on right-side line `line` of `filePath`. */
export function lineThread(
  filePath: string,
  line: number,
  content: string,
  tracking?: { iterationId: number; changeTrackingId: number },
): Record<string, unknown> {
  return {
    comments: [{ parentCommentId: 0, content, commentType: 1 }],
    status: 1,
    threadContext: {
      filePath,
      rightFileStart: { line, offset: 1 },
      rightFileEnd: { line, offset: 6 },
    },
    ...(tracking
      ? {
          pullRequestThreadContext: {
            changeTrackingId: tracking.changeTrackingId,
            iterationContext: {
              firstComparingIteration: tracking.iterationId,
              secondComparingIteration: tracking.iterationId,
            },
          },
        }
      : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Builds (items 8 and 17)

export async function defaultQueueId(ctx: ProbeContext): Promise<number> {
  const res = ok(
    await ctx.bot.request(
      'GET',
      `/${ctx.project}/_apis/distributedtask/queues?queueName=Default`,
      undefined,
      { apiVersion: '7.0-preview.1' },
    ),
    'agent queues (7.0-preview.1)',
  );
  const queues = shape(
    z.object({ value: z.array(z.object({ id: z.number(), name: z.string() })) }),
    res.json,
    'agent queues',
  );
  const q = queues.value.find((x) => x.name === 'Default');
  if (!q) throw new ShapeError('the project has no Default agent queue');
  return q.id;
}

export const BuildSchema = z.object({
  id: z.number(),
  status: z.string(),
  result: z.string().optional(),
  sourceBranch: z.string().optional(),
  sourceVersion: z.string().optional(),
  reason: z.string().optional(),
  queue: z.object({ id: z.number() }).optional(),
});

/** The YAML of a probe pipeline on the agent pool `Default`, steps as given. */
export function pipelineYaml(steps: string): string {
  return ['trigger: none', 'pool:', '  name: Default', 'steps:', steps].join('\n') + '\n';
}

/** Creates a YAML build definition; deletes it (after cancelling its builds) at clean-up. */
export async function createDefinition(
  ctx: ProbeContext,
  body: Record<string, unknown>,
): Promise<{ id: number; res: AzureResponse }> {
  const res = await ctx.bot.request('POST', `/${ctx.project}/_apis/build/definitions`, body);
  ok(res, 'create build definition');
  const id = createdNumber(res, 'id', 'create build definition');
  trackDefinition(ctx, id);
  shape(z.object({ id: z.number(), revision: z.number() }), res.json, 'definition');
  return { id, res };
}

/** Deletes definition `id` at clean-up, after cancelling its builds. */
export function trackDefinition(ctx: ProbeContext, id: number): void {
  ctx.cleanup.add(`delete build definition ${id}`, async () => {
    await cancelBuilds(ctx, id);
    await remove(ctx.bot, `/${ctx.project}/_apis/build/definitions/${id}`, 'definition');
  });
}

/** Queues definition `definitionId` on `sourceBranch`. */
export async function queueBuild(
  ctx: ProbeContext,
  definitionId: number,
  sourceBranch: string,
): Promise<{ id: number; res: AzureResponse }> {
  const res = ok(
    await ctx.bot.request('POST', `/${ctx.project}/_apis/build/builds`, {
      definition: { id: definitionId },
      sourceBranch,
    }),
    'queue build',
  );
  return { id: shape(BuildSchema, res.json, 'queued build').id, res };
}

const PermissionsSchema = z.object({
  allPipelines: z.object({ authorized: z.boolean() }).nullish(),
  pipelines: z.array(z.object({ id: z.number(), authorized: z.boolean() })).nullish(),
});

/**
 * A queue's pipeline permissions as one comparable line: allPipelines and the sorted list, without
 * pipeline `ignoreId` when given (the probe's own definition, deleted at clean-up).
 */
export function permissionsKey(
  perms: z.infer<typeof PermissionsSchema>,
  ignoreId?: number,
): string {
  const list = (perms.pipelines ?? [])
    .filter((p) => p.id !== ignoreId)
    .map((p) => `${p.id}:${String(p.authorized)}`)
    .sort();
  const all = perms.allPipelines ? String(perms.allPipelines.authorized) : 'none';
  return `allPipelines ${all}; pipelines [${list.join(', ')}]`;
}

/** The pipeline permissions of agent queue `queueId` (`7.0-preview.1`). */
export async function queuePermissions(ctx: ProbeContext, queueId: number) {
  const res = ok(
    await ctx.bot.request(
      'GET',
      `/${ctx.project}/_apis/pipelines/pipelinePermissions/queue/${queueId}`,
      undefined,
      { apiVersion: '7.0-preview.1' },
    ),
    'pipeline permissions (7.0-preview.1)',
  );
  const perms = shape(PermissionsSchema, res.json, 'pipeline permissions');
  return {
    res,
    perms,
    key: permissionsKey(perms),
    open: perms.allPipelines?.authorized === true,
    authorized: (id: number) => perms.pipelines?.some((p) => p.id === id && p.authorized) ?? false,
  };
}

/**
 * Authorizes definition `id` (the probe's own) on the shared agent queue `queueId`. The queue's
 * permissions are read first. Before the PATCH, clean-up is told to take the authorization back
 * (when it reads as given), and a check after clean-up to compare the queue's permissions with that
 * first reading, the probe's own definition left out (a difference makes the item answer no). Both
 * come first so that a PATCH that takes effect but answers late, or not at all, is undone too.
 */
export async function authorizeQueue(ctx: ProbeContext, queueId: number, id: number) {
  const before = await queuePermissions(ctx, queueId);
  const p = `/${ctx.project}/_apis/pipelines/pipelinePermissions/queue/${queueId}`;
  const opts = { apiVersion: '7.0-preview.1' };
  ctx.cleanup.add(`restore the pipeline permissions of queue ${queueId}`, async () => {
    if (!(await queuePermissions(ctx, queueId)).authorized(id)) return;
    ok(
      await ctx.bot.request('PATCH', p, { pipelines: [{ id, authorized: false }] }, opts),
      'take back the authorization',
    );
  });
  ctx.verifications.push({
    label: `queue ${queueId} permissions`,
    check: async () => {
      const after = await queuePermissions(ctx, queueId);
      const was = permissionsKey(before.perms, id);
      const now = permissionsKey(after.perms, id);
      return now === was
        ? {
            ok: true,
            text: `queue ${queueId} pipeline permissions equal the original (${was}; the probe's definition left out)`,
          }
        : {
            ok: false,
            text: `queue ${queueId} pipeline permissions differ from the original: before ${was}, after ${now} (the probe's definition left out)`,
          };
    },
  });
  return ctx.bot.request('PATCH', p, { pipelines: [{ id, authorized: true }] }, opts);
}

export async function cancelBuilds(ctx: ProbeContext, definitionId: number): Promise<void> {
  const res = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds?definitions=${definitionId}`),
    'builds',
  );
  const builds = shape(z.object({ value: z.array(BuildSchema) }), res.json, 'builds');
  for (const b of builds.value.filter((x) => x.status !== 'completed')) {
    await ctx.bot.request('PATCH', `/${ctx.project}/_apis/build/builds/${b.id}`, {
      status: 'cancelling',
    });
  }
}

export async function getBuild(ctx: ProbeContext, id: number) {
  const res = ok(await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds/${id}`), 'build');
  return { build: shape(BuildSchema, res.json, 'build'), res };
}

/** Waits for a build to complete; `onWaiting` runs once when it has not started after `stuckMs`. */
export async function waitBuild(
  ctx: ProbeContext,
  id: number,
  opts: { timeoutMs: number; stuckMs?: number; onWaiting?: () => Promise<void> },
) {
  const started = Date.now();
  let nudged = false;
  for (;;) {
    const got = await getBuild(ctx, id);
    if (got.build.status === 'completed') return got;
    if (Date.now() - started > opts.timeoutMs) return got;
    if (
      !nudged &&
      opts.onWaiting &&
      got.build.status === 'notStarted' &&
      Date.now() - started > (opts.stuckMs ?? 90_000)
    ) {
      nudged = true;
      await opts.onWaiting();
    }
    await sleep(10_000);
  }
}

/**
 * Every log of a build as lines, by log id. The names of the agents that ran it (the timeline's
 * `workerName`) join the redaction table first, as the logs and the build may name them.
 */
export async function buildLogs(ctx: ProbeContext, id: number): Promise<Map<number, string[]>> {
  const timeline = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds/${id}/timeline`),
    'build timeline',
  );
  const records = z
    .object({ records: z.array(z.object({ workerName: z.string().nullish() }).loose()) })
    .safeParse(timeline.json);
  if (records.success) {
    // An agent named like a project, repository, branch or pool the probe uses (`probe`, `main`,
    // `Default`) is not added: replacing that word everywhere would mangle paths, refs and names
    // in the recordings, and such a name says nothing about a machine.
    const reserved = new Set(
      [ctx.project, ctx.repo, 'probe-basic', 'probe-scrum', 'main', 'Default'].map((n) =>
        n.toLowerCase(),
      ),
    );
    addHosts(
      ctx.redaction,
      records.data.records
        .map((r) => r.workerName ?? '')
        .filter((w) => w.length > 0 && !reserved.has(w.toLowerCase())),
    );
  }
  const res = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds/${id}/logs`),
    'build logs',
  );
  const list = shape(z.object({ value: z.array(z.object({ id: z.number() })) }), res.json, 'logs');
  const out = new Map<number, string[]>();
  for (const log of list.value) {
    const one = ok(
      await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds/${id}/logs/${log.id}`),
      `build log ${log.id}`,
    );
    out.set(log.id, logLines(one.json));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Policies (items 7 and 17)

export async function createPolicy(
  ctx: ProbeContext,
  body: Record<string, unknown>,
): Promise<{ id: number; res: AzureResponse }> {
  const res = ok(
    await ctx.bot.request('POST', `/${ctx.project}/_apis/policy/configurations`, body),
    'create policy',
  );
  const id = createdNumber(res, 'id', 'create policy');
  ctx.cleanup.add(`delete policy ${id}`, () =>
    remove(ctx.bot, `/${ctx.project}/_apis/policy/configurations/${id}`, 'policy'),
  );
  return { id, res };
}

export const EvaluationsSchema = z.object({
  value: z.array(
    z.object({
      evaluationId: z.string(),
      status: z.string(),
      configuration: z
        .object({ id: z.number(), type: z.object({ id: z.string() }).loose() })
        .loose(),
      context: z.unknown().optional(),
    }),
  ),
});

/** The policy evaluations of a pull request (`7.0-preview.1`). */
export async function evaluations(ctx: ProbeContext, pr: Pr) {
  const repo = await repoInfo(ctx);
  const artifactId = `vstfs:///CodeReview/CodeReviewId/${repo.project.id}/${pr.codeReviewId ?? pr.pullRequestId}`;
  const res = ok(
    await ctx.bot.request(
      'GET',
      `/${ctx.project}/_apis/policy/evaluations?artifactId=${encodeURIComponent(artifactId)}`,
      undefined,
      { apiVersion: '7.0-preview.1' },
    ),
    'policy evaluations (7.0-preview.1)',
  );
  return { list: shape(EvaluationsSchema, res.json, 'policy evaluations'), res };
}

// ---------------------------------------------------------------------------------------------
// The webhook recorder (item 9)

function recorderAuth(ctx: ProbeContext): string {
  return `Basic ${Buffer.from(`qualor:${ctx.recorderSecret}`).toString('base64')}`;
}

export async function recorderList(ctx: ProbeContext): Promise<string[]> {
  const res = await fetch(`${ctx.hookBase.replace(/\/+$/, '')}/hooks/_list`, {
    headers: { authorization: recorderAuth(ctx) },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`recorder list: HTTP ${res.status}`);
  return shape(z.array(z.string()), await res.json(), 'recorder list');
}

export const RecordedHookSchema = z.object({
  time: z.string(),
  method: z.string(),
  path: z.string(),
  headers: z.record(z.string(), z.unknown()),
  authorization: z.object({ scheme: z.string().nullable(), passwordMatches: z.boolean() }),
  body: z.string(),
});

export async function recorderGet(ctx: ProbeContext, file: string) {
  const res = await fetch(
    `${ctx.hookBase.replace(/\/+$/, '')}/hooks/_get/${encodeURIComponent(file)}`,
    { headers: { authorization: recorderAuth(ctx) }, signal: AbortSignal.timeout(30_000) },
  );
  if (!res.ok) throw new Error(`recorder get: HTTP ${res.status}`);
  return shape(RecordedHookSchema, await res.json(), 'recorded hook');
}
