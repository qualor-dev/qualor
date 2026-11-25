import { rawRequest, type RawResponse } from '../client.js';
import { whoAmI } from './01-identity.js';
import {
  createPr,
  excerpt,
  InterruptedError,
  probeSource,
  pushFiles,
  result,
  type ProbeContext,
  type ProbeItem,
} from './common.js';
import type { RedactionTable } from '../record.js';

/**
 * Whether a GET of a pull request's web page opened that pull request: 200 HTML, no redirect (to a
 * sign-in page), and the page carries the pull request's title. The title matters: Server answers
 * an unknown pull request id with the same 200 application shell, without the title.
 */
export function prPageOpens(raw: RawResponse, title: string): boolean {
  if (raw.status !== 200 || raw.headers['location']) return false;
  if (!/text\/html/i.test(raw.headers['content-type'] ?? '')) return false;
  const escaped = title.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return raw.text.includes(title) || raw.text.includes(escaped);
}

const recorded = (raw: RawResponse, method: string, title: string, table: RedactionTable) => ({
  method,
  status: raw.status,
  contentType: raw.headers['content-type'] ?? null,
  location: raw.headers['location'] ?? null,
  ...(method === 'GET'
    ? { first200: excerpt(raw.text, table), carriesTitle: prPageOpens(raw, title) }
    : {}),
});

/**
 * The web page with the second user's PAT, following no redirect. The URL comes from an answer
 * (`repository.webUrl`): the PAT goes only to the target's own origin.
 */
async function open(ctx: ProbeContext, url: string, method: 'HEAD' | 'GET', pat: string) {
  const page = new URL(url);
  if (page.origin !== new URL(ctx.baseUrl).origin) {
    throw new Error(
      "repository.webUrl is not on the target URL's origin: no credential sent to it",
    );
  }
  const credential = Buffer.from(`:${pat}`).toString('base64');
  return rawRequest(
    method,
    page,
    { authorization: `Basic ${credential}`, accept: 'text/html' },
    undefined,
    ctx.caPem ? { caPem: ctx.caPem } : {},
  );
}

/** Item 12, part one: the Entra scope string with a secret and with a certificate. */
async function checkScope(ctx: ProbeContext): Promise<{ lines: string[]; scopeOk: boolean }> {
  const lines: string[] = [];
  let scopeOk = true;
  if (!ctx.entra) {
    lines.push('scope: skipped (server has no Entra)');
    return { lines, scopeOk };
  }
  for (const kind of ['secret', 'certificate'] as const) {
    try {
      await whoAmI(ctx, ctx.entra(kind), kind, false);
      lines.push(`scope 499b84ac-1321-427f-aa17-267ca6975798/.default with ${kind}: accepted`);
    } catch (err) {
      if (err instanceof InterruptedError) throw err;
      scopeOk = false;
      lines.push(`scope with ${kind}: failed: ${(err as Error).message}`);
    }
  }
  return { lines, scopeOk };
}

export const item: ProbeItem = {
  id: 12,
  title: 'the Entra scope string is accepted, and repository.webUrl + /pullrequest/{id} opens',
  async run(ctx) {
    const { lines, scopeOk } = await checkScope(ctx);

    const title = `Qualor probe item ${ctx.item} (${ctx.stamp})`;
    const { refName } = await pushFiles(ctx, `probe/12-${ctx.stamp}`, [probeSource(ctx)]);
    const { webUrl } = await createPr(ctx, refName, { title });
    if (ctx.userAuth.kind !== 'pat') throw new Error('the second user has no PAT on this target');
    const pat = ctx.userAuth.pat;
    // HEAD is recorded as an observation only: on Server a scoped PAT (vso.code_write) gets 401 for
    // any HEAD, even of a REST route whose GET it may read, so HEAD says nothing about the link.
    const head = await open(ctx, webUrl, 'HEAD', pat);
    await ctx.record('pr-web-head', recorded(head, 'HEAD', title, ctx.redaction));
    const get = await open(ctx, webUrl, 'GET', pat);
    await ctx.record('pr-web-get', recorded(get, 'GET', title, ctx.redaction));
    const linkOk = prPageOpens(get, title);
    const describe = (raw: RawResponse) =>
      `HTTP ${raw.status} ${raw.headers['content-type'] ?? 'no content type'}${raw.headers['location'] ? ', with a redirect' : ''}`;
    lines.push(
      `GET repository.webUrl + "/pullrequest/" + id with the second user's PAT: ${describe(get)}; ` +
        `${linkOk ? 'the page carries the pull request title (it opened the pull request)' : 'the page does not open the pull request'}`,
      `HEAD of the same URL with the same PAT: ${describe(head)} (observation only)`,
    );
    let answer: 'yes' | 'partly' | 'no' = linkOk ? 'yes' : 'no';
    if (ctx.entra && linkOk !== scopeOk) answer = 'partly';
    else if (ctx.entra && !scopeOk) answer = 'no';
    return result(ctx, answer, lines.join('\n\n'));
  },
};
