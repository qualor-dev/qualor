import { z } from 'zod';
import {
  answerOf,
  createdNumber,
  InterruptedError,
  ok,
  result,
  shape,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const PATCH_JSON = 'application/json-patch+json';
const LINK = 'https://qualor.example.invalid/issues/probe-13';
const REPRO = 'Microsoft.VSTS.TCM.ReproSteps';
/** Fields a recording of the type list keeps besides the always-required ones. */
const USED_FIELDS = ['System.Title', 'System.Description', REPRO, 'System.Tags', 'System.History'];

const TypesSchema = z.object({
  count: z.number().optional(),
  value: z.array(
    z
      .object({
        name: z.string(),
        referenceName: z.string(),
        xmlForm: z.string().optional(),
        fields: z.array(
          z
            .object({ referenceName: z.string(), name: z.string(), alwaysRequired: z.boolean() })
            .loose(),
        ),
        states: z
          .array(z.object({ name: z.string(), category: z.string().optional() }).loose())
          .optional(),
      })
      .loose(),
  ),
});

const WorkItemSchema = z.object({
  id: z.number(),
  rev: z.number(),
  fields: z.record(z.string(), z.unknown()),
  relations: z.array(z.object({ rel: z.string(), url: z.string() }).loose()).nullish(),
});

type Process = { label: string; project: string; type: string };

/** A type's `fieldInstances`: its fields with their help texts (about 70 entries per type). */
const FieldInstancesSchema = z.array(
  z.object({ referenceName: z.string(), alwaysRequired: z.boolean().optional() }).loose(),
);

const used = (f: { referenceName: string; alwaysRequired?: boolean | undefined }): boolean =>
  f.alwaysRequired === true || USED_FIELDS.includes(f.referenceName);

/** The used entries of a `fieldInstances` answer, each as it came. */
function usedInstances(value: unknown): unknown[] {
  const list = FieldInstancesSchema.parse(value);
  return (value as unknown[]).filter((_entry, i) => {
    const entry = list[i];
    return entry !== undefined && used(entry);
  });
}

/**
 * The type list without the parts a fake never needs (form XML, transitions, unused fields and
 * field instances). A list trimmed before comes back trimmed the same way.
 */
export function trimTypes(json: unknown): unknown {
  const parsed = TypesSchema.parse(json);
  const dropped = new Set(['xmlForm', 'transitions', '_links', 'fields']);
  return {
    count: parsed.count ?? parsed.value.length,
    value: parsed.value.map((type) => ({
      ...Object.fromEntries(
        Object.entries(type)
          .filter(([k]) => !dropped.has(k))
          .map(([k, v]) => (k === 'fieldInstances' ? [k, usedInstances(v)] : [k, v])),
      ),
      fields: type.fields.filter(used),
    })),
    _probeNote:
      'trimmed by the probe: xmlForm, transitions, _links, and unused fields and fieldInstances left out',
  };
}

async function oneProcess(ctx: ProbeContext, p: Process): Promise<{ ok: boolean; text: string }> {
  const base = `/${p.project}/_apis/wit`;
  const typesRes = ok(await ctx.bot.request('GET', `${base}/workitemtypes`), `${p.label} types`);
  const types = shape(TypesSchema, typesRes.json, `${p.label} work item types`);
  await ctx.record(`${p.label}-types`, { ...answerOf(typesRes), body: trimTypes(typesRes.json) });
  const type = types.value.find((t) => t.name === p.type);
  if (!type) return { ok: false, text: `${p.label}: no type ${p.type}` };
  const required = type.fields.filter((f) => f.alwaysRequired).map((f) => f.referenceName);
  const hasRepro = type.fields.some((f) => f.referenceName === REPRO);
  const form = type.xmlForm;
  let descriptionOnForm = 'unknown (no xmlForm)';
  if (form !== undefined) descriptionOnForm = form.includes('System.Description') ? 'yes' : 'no';

  const patch = [
    { op: 'add', path: '/fields/System.Title', value: `Qualor probe item 13 (${ctx.stamp})` },
    { op: 'add', path: '/fields/System.Description', value: '<p>Qualor probe: description.</p>' },
    ...(hasRepro
      ? [{ op: 'add', path: `/fields/${REPRO}`, value: '<p>Qualor probe: repro steps.</p>' }]
      : []),
    { op: 'add', path: '/fields/System.Tags', value: 'qualor; probe13' },
    { op: 'add', path: '/relations/-', value: { rel: 'Hyperlink', url: LINK } },
  ];
  const createRes = await ctx.bot.request(
    'POST',
    `${base}/workitems/$${encodeURIComponent(p.type)}`,
    patch,
    { contentType: PATCH_JSON },
  );
  if (createRes.status < 300) {
    // Tracked for clean-up before the recording and the shape check, which can throw.
    const id = createdNumber(createRes, 'id', `${p.label} create ${p.type}`);
    const removable = type.states?.some((s) => s.name === 'Removed') ?? false;
    ctx.cleanup.add(`delete work item ${id}`, async () => {
      const del = await ctx.bot.request('DELETE', `${base}/workitems/${id}`);
      if (del.status < 300 || del.status === 404) return;
      if (!removable)
        throw new Error(`delete answered HTTP ${del.status}; the type has no Removed`);
      ok(
        await ctx.bot.request(
          'PATCH',
          `${base}/workitems/${id}`,
          [{ op: 'add', path: '/fields/System.State', value: 'Removed' }],
          { contentType: PATCH_JSON },
        ),
        'move to Removed',
      );
    });
  }
  await ctx.record(`${p.label}-create`, answerOf(createRes));
  ok(createRes, `${p.label} create ${p.type}`);
  const created = shape(WorkItemSchema, createRes.json, `${p.label} work item`);

  const historyRes = ok(
    await ctx.bot.request(
      'PATCH',
      `${base}/workitems/${created.id}`,
      [{ op: 'add', path: '/fields/System.History', value: '<p>Qualor probe: a note.</p>' }],
      { contentType: PATCH_JSON },
    ),
    `${p.label} history`,
  );
  await ctx.record(`${p.label}-history`, answerOf(historyRes));
  const commentsRes = await ctx.bot.request(
    'GET',
    `${base}/workItems/${created.id}/comments`,
    undefined,
    { apiVersion: '7.0-preview.3' },
  );
  await ctx.record(`${p.label}-comments`, answerOf(commentsRes));
  const comments = z
    .object({ comments: z.array(z.object({ text: z.string() }).loose()) })
    .safeParse(commentsRes.json);
  const noteAsComment =
    comments.success && comments.data.comments.some((c) => c.text.includes('a note'));

  const wiqlRes = ok(
    await ctx.bot.request('POST', `${base}/wiql`, {
      query:
        "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS 'qualor' ORDER BY [System.Id] DESC",
    }),
    `${p.label} wiql`,
  );
  await ctx.record(`${p.label}-wiql`, answerOf(wiqlRes));
  const wiql = shape(
    z.object({ workItems: z.array(z.object({ id: z.number() })) }),
    wiqlRes.json,
    `${p.label} wiql`,
  );
  const found = wiql.workItems.some((w) => w.id === created.id);

  const batchRes = ok(
    await ctx.bot.request('POST', `${base}/workitemsbatch`, {
      ids: [created.id],
      $expand: 'relations',
    }),
    `${p.label} workitemsbatch`,
  );
  await ctx.record(`${p.label}-batch`, answerOf(batchRes));
  const batch = shape(z.object({ value: z.array(WorkItemSchema) }), batchRes.json, 'batch');
  const read = batch.value.find((w) => w.id === created.id);
  const f = read?.fields ?? {};
  const tags = typeof f['System.Tags'] === 'string' ? f['System.Tags'] : '';
  const checks = {
    title: typeof f['System.Title'] === 'string',
    description: String(f['System.Description'] ?? '').includes('description'),
    repro: !hasRepro || String(f[REPRO] ?? '').includes('repro steps'),
    tag: tags.split(';').some((t) => t.trim() === 'qualor'),
    link: read?.relations?.some((r) => r.rel === 'Hyperlink' && r.url === LINK) ?? false,
  };
  const all = Object.values(checks).every(Boolean) && found;
  const failedChecks = Object.entries(checks)
    .filter(([, v]) => !v)
    .map(([k]) => k);
  const noteText = noteAsComment
    ? 'reads back as a comment (7.0-preview.3)'
    : `not among the comments (HTTP ${commentsRes.status})`;
  const batchText = failedChecks.length
    ? `misses ${failedChecks.join(', ')}`
    : 'reads back title, description, repro steps, tag and link';
  return {
    ok: all,
    text:
      `${p.label} (${p.project}, ${p.type} ${created.id}): always required ${required.join(', ') || 'none'}; ` +
      `Repro Steps ${hasRepro ? 'on the type' : 'not on the type'}; System.Description on the form: ${descriptionOnForm}; ` +
      `History note ${noteText}; ` +
      `WIQL ${found ? 'finds it' : 'does not find it'}; workitemsbatch ${batchText}`,
  };
}

export const item: ProbeItem = {
  id: 13,
  title: 'work items on Basic, Agile and Scrum: create, History note, WIQL by tag, batch read',
  async run(ctx) {
    const processes: Process[] = [
      { label: 'basic', project: 'probe-basic', type: 'Issue' },
      { label: 'agile', project: ctx.project, type: 'Bug' },
      { label: 'scrum', project: 'probe-scrum', type: 'Bug' },
    ];
    const lines: string[] = [];
    let passed = 0;
    for (const p of processes) {
      try {
        const r = await oneProcess(ctx, p);
        if (r.ok) passed++;
        lines.push(r.text);
      } catch (err) {
        if (err instanceof InterruptedError) throw err;
        lines.push(`${p.label}: ${(err as Error).name}: ${(err as Error).message}`);
      }
    }
    let answer: 'yes' | 'partly' | 'no' = 'no';
    if (passed === processes.length) answer = 'yes';
    else if (passed > 0) answer = 'partly';
    return result(ctx, answer, lines.join('\n\n'));
  },
};
