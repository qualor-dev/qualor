import { z } from 'zod';
import { AzureClient, type AzureAuth } from '../client.js';
import { loadTarget } from '../targets.js';
import { CONNECTION_DATA_VERSION } from './01-identity.js';
import {
  addIdentity,
  answerOf,
  ConnectionDataSchema,
  createPr,
  IdentitySchema,
  ok,
  prWithMerge,
  pushFiles,
  repoInfo,
  result,
  shape,
  threadsPath,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** The Git Repositories security namespace and its Contribute bit (as item 16). */
const GIT_NAMESPACE = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87';
const CONTRIBUTE = 4;
const IDENTITIES_VERSION = '7.0';

const AclSchema = z.object({
  value: z.array(
    z.object({
      token: z.string(),
      acesDictionary: z.record(
        z.string(),
        z.object({
          descriptor: z.string(),
          allow: z.number(),
          deny: z.number(),
          extendedInfo: z
            .object({ effectiveAllow: z.number().optional(), effectiveDeny: z.number().optional() })
            .loose()
            .optional(),
        }),
      ),
    }),
  ),
});

const ReplyThread = z
  .object({
    id: z.number(),
    publishedDate: z.string().optional(),
    comments: z.array(
      z
        .object({
          id: z.number(),
          parentCommentId: z.number().optional(),
          content: z.string().optional(),
          publishedDate: z.string().optional(),
          author: z.object({ id: z.string(), displayName: z.string().optional() }).loose(),
        })
        .loose(),
    ),
  })
  .loose();

/**
 * The identities host of an Azure DevOps Services organisation URL: `vssps.dev.azure.com/<org>` for
 * `dev.azure.com/<org>`, `<org>.vssps.visualstudio.com` for `<org>.visualstudio.com`. Test tooling:
 * the one other host this probe derives from the configured organisation.
 */
export function identitiesBase(servicesUrl: string): string {
  const url = new URL(servicesUrl);
  const host = url.hostname.toLowerCase();
  if (host === 'dev.azure.com') {
    const org = url.pathname.split('/').find(Boolean);
    if (!org) throw new Error('the Services URL has no organisation');
    return `https://vssps.dev.azure.com/${org}`;
  }
  const m = /^([^.]+)\.visualstudio\.com$/.exec(host);
  if (m?.[1]) return `https://${m[1]}.vssps.visualstudio.com`;
  throw new Error('the Services URL is neither dev.azure.com/<org> nor <org>.visualstudio.com');
}

/** The identity descriptor forms the ACL `descriptors=` parameter takes (not a `aad.` subject descriptor). */
export function isIdentityDescriptor(d: string): boolean {
  return /^Microsoft\.(IdentityModel\.Claims\.ClaimsIdentity|VisualStudio\.Services\.Claims\.AadServicePrincipal|TeamFoundation\.[A-Za-z]+);/.test(
    d,
  );
}

/**
 * Adds every identity an identities answer holds to the redaction table, before anything is
 * recorded: names, alias, account, mail, domain (addIdentity), plus DN, Description and the
 * objectidentifier claim. The recording then fails closed (writeRecording's leaks check) if one survives.
 */
export function learnIdentities(table: ProbeContext['redaction'], json: unknown): void {
  const parsed = z.object({ value: z.array(IdentitySchema) }).safeParse(json);
  if (!parsed.success) return;
  for (const identity of parsed.data.value) {
    addIdentity(table, identity);
    const props = (identity.properties ?? {}) as Record<string, { $value?: unknown } | undefined>;
    for (const key of ['DN', 'Description']) {
      const v = props[key]?.$value;
      if (typeof v === 'string' && v.length >= 3) table.names.push(v);
    }
    const oid = props['http://schemas.microsoft.com/identity/claims/objectidentifier']?.$value;
    if (typeof oid === 'string' && oid.length >= 3) table.names.push(oid, oid.toLowerCase());
  }
}

async function who(client: AzureClient, label: string) {
  const res = ok(
    await client.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: CONNECTION_DATA_VERSION,
    }),
    `connectionData (${label})`,
  );
  return shape(ConnectionDataSchema, res.json, `connectionData (${label})`).authenticatedUser;
}

async function aclOf(ctx: ProbeContext, descriptor: string, label: string) {
  const repo = await repoInfo(ctx);
  const token = `repoV2/${repo.project.id}/${repo.id}`;
  const res = ok(
    await ctx.bot.request(
      'GET',
      `/_apis/accesscontrollists/${GIT_NAMESPACE}?token=${encodeURIComponent(token)}` +
        `&descriptors=${encodeURIComponent(descriptor)}&includeExtendedInfo=true`,
    ),
    `access control list (${label})`,
  );
  await ctx.record(`acl-${label}`, answerOf(res));
  const acl = shape(AclSchema, res.json, `access control list (${label})`);
  const ace = acl.value
    .flatMap((a) => Object.values(a.acesDictionary))
    .find((e) => e.descriptor.toLowerCase() === descriptor.toLowerCase());
  return {
    entry: ace !== undefined,
    allow: ace?.allow,
    effective: ace?.extendedInfo?.effectiveAllow,
  };
}

export const item: ProbeItem = {
  id: 20,
  title:
    'the commenter-rights check and thread replies: identities, ACL bit 4, reply and thread reads',
  async run(ctx) {
    if (ctx.target !== 'services') {
      return result(ctx, 'no', 'item 20 runs on the Services target only');
    }
    if (!ctx.entra) throw new Error('no Entra client on this target');
    const servicesUrl = process.env['AZURE_PROBE_SERVICES_URL'] ?? '';
    const idBase = identitiesBase(servicesUrl);
    const lines: string[] = [];
    const checks: { what: string; pass: boolean }[] = [];
    const add = (what: string, pass: boolean, got: string) => {
      checks.push({ what, pass });
      lines.push(`${pass ? 'yes' : 'NO'} - ${what}: ${got}`);
    };

    // Who is who: the PAT user (the reply author) and the service principal (Qualor).
    const userMe = await who(ctx.user, 'PAT user');
    const spClient = ctx.entra('secret');
    const spMe = await who(spClient, 'service principal');
    addIdentity(ctx.redaction, userMe);
    addIdentity(ctx.redaction, spMe);
    const spAuth: AzureAuth = loadTarget('services', { auth: 'secret' }).auth;

    // A probe pull request; Qualor's thread by the service principal; the PAT user's reply.
    const repo = await repoInfo(ctx);
    const file = { path: `/probe/item-20-${ctx.stamp}.txt`, content: `Qualor probe item 20\n` };
    const pushed = await pushFiles(ctx, `probe/20-${ctx.stamp}`, [file]);
    const created = await createPr(ctx, pushed.refName);
    const prId = created.pr.pullRequestId;
    await prWithMerge(ctx, prId);
    const opened = ok(
      await spClient.request('POST', threadsPath(ctx, repo, prId), {
        comments: [
          { parentCommentId: 0, content: 'Qualor probe item 20: a root comment', commentType: 1 },
        ],
        status: 1,
      }),
      'create thread (service principal)',
    );
    const thread = shape(ReplyThread, opened.json, 'created thread');
    const rootId = thread.comments[0]?.id ?? 1;
    const replyRes = ok(
      await ctx.user.request('POST', threadsPath(ctx, repo, prId, `/${thread.id}/comments`), {
        parentCommentId: rootId,
        content: 'Qualor probe item 20: a reply from the PAT user',
        commentType: 1,
      }),
      'reply (PAT user)',
    );
    await ctx.record('reply-post', answerOf(replyRes));
    const reply = shape(
      z.object({ id: z.number(), parentCommentId: z.number().optional() }).loose(),
      replyRes.json,
      'reply',
    );
    add(
      'the reply answers with its id and parentCommentId',
      reply.id > rootId && reply.parentCommentId === rootId,
      `HTTP ${replyRes.status}, id ${reply.id} (root ${rootId}), parentCommentId ${String(reply.parentCommentId)}`,
    );

    const threadRes = ok(
      await ctx.bot.request('GET', threadsPath(ctx, repo, prId, `/${thread.id}`)),
      'thread',
    );
    await ctx.record('thread-get', answerOf(threadRes));
    const got = shape(ReplyThread, threadRes.json, 'thread');
    const replyIn = got.comments.find((c) => c.id === reply.id);
    add(
      'GET thread has publishedDate, parentCommentId and author.displayName on the reply',
      got.publishedDate !== undefined &&
        replyIn?.parentCommentId === rootId &&
        typeof replyIn.author.displayName === 'string' &&
        got.comments.length === 2,
      `HTTP ${threadRes.status}, ${got.comments.length} comments, thread publishedDate ${got.publishedDate ? 'present' : 'absent'}, reply parentCommentId ${String(replyIn?.parentCommentId)}, author.displayName ${replyIn?.author.displayName ? 'present' : 'absent'}`,
    );

    // The identities lookups on the identities host, with the PAT and with the service principal's token.
    const patIds = new AzureClient(idBase, ctx.userAuth);
    const spIds = new AzureClient(idBase, spAuth);
    const lookups: [string, string, AzureClient, string, string][] = [
      ['pat-user', 'PAT user by PAT', patIds, userMe.id, 'user'],
      ['service-principal', 'service principal by PAT', patIds, spMe.id, 'sp'],
      ['service-principal-self', 'service principal by its own token', spIds, spMe.id, 'sp-self'],
    ];
    const descriptors: Record<string, string> = {};
    for (const [call, label, client, id, key] of lookups) {
      const res = await client.request('GET', `/_apis/identities?identityIds=${id}`, undefined, {
        apiVersion: IDENTITIES_VERSION,
      });
      learnIdentities(ctx.redaction, res.json);
      await ctx.record(`identities-${call}`, answerOf(res));
      const parsed = z.object({ value: z.array(IdentitySchema) }).safeParse(res.json);
      const d = parsed.success ? parsed.data.value[0]?.descriptor : undefined;
      add(
        `identities lookup (${label}) answers 200 with an identity descriptor in the ACL form`,
        res.status === 200 && d !== undefined && isIdentityDescriptor(d),
        `HTTP ${res.status}, descriptor form ${d ? `${d.split(';')[0]};…` : 'absent'}`,
      );
      if (d) descriptors[key] = d;
    }

    // The ACL with each looked-up descriptor: bit 4 (Contribute) of effectiveAllow.
    for (const [label, key] of [
      ['pat-user', 'user'],
      ['service-principal', 'sp'],
    ] as const) {
      const d = descriptors[key];
      if (!d) {
        add(`the ACL with the ${label}'s looked-up descriptor has bit 4`, false, 'no descriptor');
        continue;
      }
      const acl = await aclOf(ctx, d, label);
      add(
        `the ACL with the ${label}'s looked-up descriptor has bit 4 in effectiveAllow`,
        acl.effective !== undefined && (acl.effective & CONTRIBUTE) !== 0,
        `entry ${acl.entry ? 'found' : 'missing'}, allow ${String(acl.allow)}, effectiveAllow ${String(acl.effective)}`,
      );
    }

    // Service hooks subscriptions: GET only.
    const subs = ok(
      await ctx.bot.request(
        'GET',
        '/_apis/hooks/subscriptions?consumerId=webHooks&consumerActionId=httpRequest&publisherId=tfs',
      ),
      'service hook subscriptions',
    );
    await ctx.record('hooks-subscriptions', answerOf(subs));
    const count = (subs.json as { count?: unknown } | null)?.count;
    lines.push(`note: hooks subscriptions GET: HTTP ${subs.status}, count ${String(count)}`);
    lines.push(`note: identities base called: ${idBase.replace(/\/[^/]+$/, '/<org>')}`);

    for (const l of lines) ctx.log(l);
    return result(ctx, checks.every((c) => c.pass) ? 'yes' : 'no', lines.join('\n\n'));
  },
};
