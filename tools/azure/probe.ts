/**
 * The Azure DevOps probe:
 * `pnpm azure:probe --target services|server [--items 1,3] [--auth pat|secret|certificate]`
 * (`--auth`: the main identity's credential, pat by default; the Entra kinds on services only).
 * Each item exercises one REST behaviour the design depends on, records the redacted answers under
 * server/test/azure-shapes/<target>/ and appends its answer to the results file
 * (`AZURE_PROBE_RESULTS_FILE`, kept out of the repository).
 * `--items 23 --verify-apply <prId>` reads item 23's file after the Apply clicks and judges each thread.
 * `--cleanup-manual` closes the pull requests and branches the manual items left open.
 * `--qualor-identity contributor|minimal-pat`: the bench Qualor's connection holds that weaker
 * identity (seed-qualor.mjs --identity); items 19, 21, 24, 27 and 31 then record each step's
 * outcome, refusals included, and answer `recorded` (items/identity.ts).
 */
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { appendFile, writeFile } from 'node:fs/promises';
import { z } from 'zod';
import { AzureClient, type AzureAuth } from './client.js';
import { redact, type RedactionTable } from './record.js';
import { loadEnvFiles, loadTarget, qualorIdentityAuth, type Target } from './targets.js';
import {
  abandonPr,
  addIdentity,
  buildRedactionTable,
  CallError,
  Cleanup,
  ConnectionDataSchema,
  deleteBranch,
  getPr,
  IdentitySchema,
  InterruptedError,
  manualPrsFrom,
  manualStep,
  ok,
  parseArgs,
  shape,
  stampOf,
  stop,
  writeRecording,
  type ManualPr,
  type ProbeContext,
  type ProbeResult,
  type TargetName,
  type WeakerIdentity,
} from './items/common.js';
import { ITEMS } from './items/index.js';
import { verifyApply } from './items/23-suggestion-ranges.js';

/** The keys the probe needs besides the targets' (loadTarget names those). */
function requiredEnv(key: 'AZURE_PROBE_RESULTS_FILE' | 'AZURE_PROBE_ID_SALT'): string {
  const v = process.env[key];
  if (!v) throw new Error(`${key} is not set`);
  return v;
}

const RESULTS_HEADER = [
  '# Azure DevOps probe results',
  '',
  'Written by `pnpm azure:probe` (tools/azure/probe.ts), one section per item and run.',
  'Local only: never committed. Recordings are under `server/test/azure-shapes/<target>/`.',
  '',
].join('\n');

async function ensureResultsFile(file: string): Promise<void> {
  if (existsSync(file)) return;
  await writeFile(file, RESULTS_HEADER, 'utf8');
}

/** The line `--cleanup-manual` reads back (manualPrsFrom). */
const manualLine = (m: ManualPr): string =>
  m.id === undefined ? `Manual branch: ${m.branch}` : `Manual PR: ${m.id} (${m.branch})`;

async function appendResult(
  file: string,
  target: string,
  item: { id: number; title: string },
  res: ProbeResult,
  stamp: string,
  cleanupFailures: string[],
  manual: ManualPr | undefined,
  identity?: WeakerIdentity,
): Promise<void> {
  await ensureResultsFile(file);
  const lines = [
    '',
    `## ${target} — item ${item.id}: ${item.title}`,
    '',
    `Date: ${new Date().toISOString().slice(0, 10)} (run ${stamp})`,
    '',
    ...(identity ? [`Qualor's identity: ${identity}`, ''] : []),
    `Answer: **${res.answer}**`,
    '',
    res.detail,
    '',
  ];
  if (res.links?.length) lines.push(`Open: ${res.links.join(' ')}`, '');
  if (manual) lines.push(manualLine(manual), '');
  lines.push(
    `Recordings: ${res.recordings.length ? res.recordings.map((r) => `\`${r}\``).join(', ') : 'none'}`,
    '',
    `Clean-up: ${cleanupFailures.length ? `FAILED — ${cleanupFailures.join('; ')}` : 'done'}`,
    '',
  );
  await appendFile(file, lines.join('\n'), 'utf8');
}

/**
 * The section a second Ctrl+C leaves, written synchronously before the exit: the item's heading
 * and its manual pull request line, so that `--cleanup-manual` still finds what it left open.
 */
function appendQuitSync(
  file: string,
  target: string,
  item: { id: number; title: string },
  stamp: string,
  left: string[],
  manual: ManualPr | undefined,
): void {
  if (!existsSync(file)) writeFileSync(file, RESULTS_HEADER, 'utf8');
  const lines = [
    '',
    `## ${target} — item ${item.id}: ${item.title}`,
    '',
    `Date: ${new Date().toISOString().slice(0, 10)} (run ${stamp})`,
    '',
    'Answer: **interrupted**',
    '',
    `Quit at once by a second Ctrl+C; clean-up not finished: ${left.length ? left.join('; ') : 'nothing known'}`,
    '',
  ];
  if (manual) lines.push(manualLine(manual), '');
  appendFileSync(file, lines.join('\n'), 'utf8');
}

type Clients = {
  target: Target;
  client: (auth: AzureAuth) => AzureClient;
  bot: AzureClient;
  user: AzureClient;
  reader?: AzureClient;
  admin?: AzureClient;
  /** `--qualor-identity`: the weaker identity the bench Qualor's connection holds, and its client. */
  qualorAs?: { identity: WeakerIdentity; client: AzureClient };
};

/**
 * Who each credential is, so that their names are redacted from every recording: connectionData,
 * then the identities API, which also names a Server account's Windows machine (`Domain`).
 */
async function learnIdentities(c: Clients, redaction: RedactionTable): Promise<void> {
  for (const [who, client] of [
    ['auth', c.bot],
    ['user', c.user],
    ['reader', c.reader],
    ['admin', c.admin],
  ] as const) {
    if (!client) continue;
    const res = ok(
      await client.request('GET', '/_apis/connectionData', undefined, {
        apiVersion: '7.0-preview',
      }),
      `connectionData for ${who}`,
    );
    const data = shape(ConnectionDataSchema, res.json, `connectionData for ${who}`);
    addIdentity(redaction, data.authenticatedUser);
    const ids = await client.request(
      'GET',
      `/_apis/identities?identityIds=${data.authenticatedUser.id}`,
    );
    const parsed = z.object({ value: z.array(IdentitySchema) }).safeParse(ids.json);
    if (ids.status < 300 && parsed.success) {
      for (const identity of parsed.data.value) addIdentity(redaction, identity);
    } else {
      // Services serves identities from another host; its accounts are e-mail addresses anyway.
      console.log(`  (identities API for ${who}: HTTP ${ids.status}; connectionData only)`);
    }
  }
}

function contextFor(
  c: Clients,
  args: { target: TargetName },
  redaction: RedactionTable,
  stamp: string,
  item: number,
  say: (line: string) => string,
): ProbeContext {
  const entra =
    args.target === 'services'
      ? (kind: 'secret' | 'certificate') => c.client(loadTarget('services', { auth: kind }).auth)
      : undefined;
  const ctx: ProbeContext = {
    target: args.target,
    baseUrl: c.target.baseUrl,
    ...(c.target.caPem ? { caPem: c.target.caPem } : {}),
    bot: c.bot,
    pat:
      c.target.auth.kind === 'pat'
        ? c.bot
        : c.client(loadTarget(args.target, { auth: 'pat' }).auth),
    user: c.user,
    userAuth: c.target.userAuth,
    ...(c.reader ? { reader: c.reader } : {}),
    ...(c.admin ? { admin: c.admin } : {}),
    ...(entra ? { entra } : {}),
    ...(c.qualorAs ? { qualorAs: c.qualorAs } : {}),
    hookBase: c.target.hookBase,
    recorderSecret: c.target.recorderSecret,
    project: c.target.project,
    repo: 'probe',
    stamp,
    item,
    redaction,
    recordings: [],
    cleanup: new Cleanup(),
    verifications: [],
    record: async (call, value) => {
      const saved = await writeRecording(redaction, args.target, item, call, value);
      ctx.recordings.push(saved);
      return saved;
    },
    log: (line) => console.log(`  [${item}] ${say(line)}`),
  };
  return ctx;
}

/** Abandons the manual items' pull requests (by id, from the results file) and deletes their branches. */
async function cleanupManual(ctx: ProbeContext, file: string, say: (s: string) => string) {
  const listed = existsSync(file) ? manualPrsFrom(readFileSync(file, 'utf8'), ctx.target) : [];
  const lines: string[] = [];
  for (const m of listed) {
    const parts: string[] = [];
    try {
      const found =
        m.id === undefined
          ? undefined
          : await getPr(ctx, m.id).then(
              (got) => got.pr,
              (err: unknown) => {
                if (err instanceof CallError && err.status === 404) return null;
                throw err;
              },
            );
      const step = manualStep(m, found);
      if (step.abandon && m.id !== undefined) await abandonPr(ctx, m.id);
      if (step.note) parts.push(step.note);
      if (step.deleteBranch) {
        await deleteBranch(ctx, m.branch);
        parts.push(`${m.branch} deleted (or already gone)`);
      }
    } catch (err) {
      parts.push(`FAILED: ${(err as Error).message}`);
    }
    lines.push(say(parts.join('; ')));
  }
  for (const l of lines) console.log(`  ${l}`);
  console.log(`${listed.length} manual pull request(s) or branch(es) listed for ${ctx.target}`);
  await ensureResultsFile(file);
  await appendFile(
    file,
    [
      '',
      `## ${ctx.target} — manual clean-up`,
      '',
      `Date: ${new Date().toISOString().slice(0, 10)}`,
      '',
      ...(lines.length ? lines.map((l) => `- ${l}`) : ['- nothing listed']),
      '',
    ].join('\n'),
    'utf8',
  );
  return lines.some((l) => l.includes('FAILED'));
}

async function main(): Promise<void> {
  loadEnvFiles();
  const args = parseArgs(process.argv.slice(2));
  const file = requiredEnv('AZURE_PROBE_RESULTS_FILE');
  requiredEnv('AZURE_PROBE_ID_SALT');
  const target = loadTarget(args.target, args.auth ? { auth: args.auth } : {});
  const items = args.items
    ? args.items.map((id) => {
        const found = ITEMS.find((i) => i.id === id);
        if (!found) throw new Error(`no probe item ${id}`);
        return found;
      })
    : ITEMS;
  const caOpts = target.caPem ? { caPem: target.caPem } : {};
  const client = (auth: AzureAuth): AzureClient => new AzureClient(target.baseUrl, auth, caOpts);
  const stamp = stampOf(new Date());

  // Before the first write: which organisation this run acts on.
  console.log(`Target ${args.target}: ${target.baseUrl} (main identity: ${target.auth.kind})`);

  const redaction = buildRedactionTable(process.env);
  const clients: Clients = {
    target,
    client,
    bot: client(target.auth),
    user: client(target.userAuth),
    ...(target.readerAuth ? { reader: client(target.readerAuth) } : {}),
    ...(target.adminAuth ? { admin: client(target.adminAuth) } : {}),
  };
  await learnIdentities(clients, redaction);
  if (args.qualorIdentity) {
    const qualorClient = client(qualorIdentityAuth(args.target, args.qualorIdentity));
    clients.qualorAs = { identity: args.qualorIdentity, client: qualorClient };
    console.log(
      `Qualor's connection identity: ${args.qualorIdentity} (the items record its refusals)`,
    );
    // Its names join the redaction table; a minimal PAT may not read connectionData (its owner is the
    // main PAT's, whose names are in the table already).
    const who = await qualorClient.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: '7.0-preview',
    });
    const data = ConnectionDataSchema.safeParse(who.json);
    if (who.status < 300 && data.success) addIdentity(redaction, data.data.authenticatedUser);
    else
      console.log(`  (connectionData for the ${args.qualorIdentity} identity: HTTP ${who.status})`);
  }
  const say = (line: string): string => String(redact(line, redaction));

  if (args.cleanupManual) {
    const ctx = contextFor(clients, args, redaction, stamp, 0, say);
    if (await cleanupManual(ctx, file, say)) process.exitCode = 1;
    return;
  }

  // Ctrl+C only asks to stop: the current item's waits end (InterruptedError), the loop below runs
  // its clean-up once, writes its results, and starts no further item. A second Ctrl+C quits at
  // once, after saying (and writing) what that leaves behind.
  let current: { ctx: ProbeContext; item: { id: number; title: string } } | undefined;
  process.on('SIGINT', () => {
    if (stop.requested) {
      const left = current ? current.ctx.cleanup.pending().map(say) : [];
      console.log(
        `\nquitting now; left behind: ${left.length ? left.join('; ') : 'nothing known'}`,
      );
      if (current) {
        const manual = current.ctx.manualPr;
        if (manual) console.log(`  also left open: ${manualLine(manual)}`);
        try {
          appendQuitSync(file, args.target, current.item, stamp, left, manual);
        } catch (err) {
          console.log(`  could not write the results file: ${(err as Error).message}`);
        }
      }
      process.exit(130);
    }
    stop.requested = true;
    console.log(
      '\ninterrupted: the current item stops and cleans up (Ctrl+C again to quit at once)',
    );
  });

  let failures = 0;
  for (const item of items) {
    if (stop.requested) break;
    const ctx = contextFor(clients, args, redaction, stamp, item.id, say);
    current = { ctx, item };
    console.log(`item ${item.id}: ${item.title} …`);
    let res: ProbeResult;
    try {
      res =
        args.verifyApply === undefined
          ? await item.run(ctx)
          : await verifyApply(ctx, args.verifyApply);
    } catch (err) {
      const e = err as Error;
      if (err instanceof InterruptedError) {
        // Stopped by Ctrl+C: no answer, and not a failure of the item.
        res = { answer: 'interrupted', detail: e.message, recordings: [...ctx.recordings] };
      } else {
        // A failed call or an unexpected shape: the item answers no, with the issue.
        res = { answer: 'no', detail: `${e.name}: ${e.message}`, recordings: [...ctx.recordings] };
        failures++;
      }
    }
    const cleanupFailures = (await ctx.cleanup.run()).map(say);
    // Shared state the item changed must read as before once its clean-up has run.
    const verdicts: string[] = [];
    const fail = (r: ProbeResult): ProbeResult =>
      r.answer === 'interrupted' ? r : { ...r, answer: 'no' };
    for (const v of ctx.verifications) {
      try {
        const verdict = await v.check();
        verdicts.push(`after clean-up, ${verdict.text}`);
        if (!verdict.ok) res = fail(res);
      } catch (err) {
        verdicts.push(`after clean-up, ${v.label} could not be checked: ${(err as Error).message}`);
        res = fail(res);
      }
    }
    current = undefined;
    const detail = [res.detail, ...verdicts].join('\n\n');
    res = { ...res, detail: say(detail) };
    if (cleanupFailures.length) failures++;
    console.log(`item ${item.id}: ${item.title}\n  answer: ${res.answer}\n  ${res.detail}`);
    for (const link of res.links ?? []) console.log(`  open: ${link}`);
    if (ctx.manualPr) console.log(`  left open for a visual check: ${manualLine(ctx.manualPr)}`);
    if (cleanupFailures.length) console.log(`  clean-up FAILED: ${cleanupFailures.join('; ')}`);
    await appendResult(
      file,
      args.target,
      item,
      res,
      stamp,
      cleanupFailures,
      ctx.manualPr,
      args.qualorIdentity,
    );
  }
  console.log(`results appended to ${file}`);
  if (stop.requested) {
    console.log('stopped by Ctrl+C: no further item was started');
    process.exitCode = 130;
  } else if (failures > 0) process.exitCode = 1;
}

main().catch((err: unknown) => {
  const message = String(redact((err as Error).message, buildRedactionTable(process.env)));
  console.error(`probe failed: ${message}`);
  process.exitCode = 2;
});
