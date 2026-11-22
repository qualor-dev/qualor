import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { redact } from '../record.js';
import { trimTypes } from './13-boards.js';
import { parentsOf } from './17-head-checkout.js';
import { threadIdScope } from './15-thread-ids.js';
import { commentKind, pickResourceVersion } from './09-service-hooks.js';
import { prPageOpens } from './12-scope-and-link.js';
import { aclAnswer, contributeSource } from './16-acl.js';
import {
  addIdentity,
  buildRedactionTable,
  excerpt,
  Cleanup,
  InterruptedError,
  keptLogLines,
  leaks,
  logLines,
  manualPrsFrom,
  manualStep,
  nameKind,
  parseArgs,
  permissionsKey,
  printedValues,
  scrubEmails,
  sleep,
  stampOf,
  stop,
  threadIdFromHref,
  writeRecording,
} from './common.js';

describe('threadIdFromHref', () => {
  it('reads the thread id out of a comment event link', () => {
    expect(
      threadIdFromHref(
        'https://dev.example.invalid/org/_apis/git/repositories/r/pullRequests/1/threads/5',
      ),
    ).toBe(5);
    expect(
      threadIdFromHref('https://h/c/_apis/git/repositories/r/pullRequests/7/threads/12/comments/1'),
    ).toBe(12);
    expect(threadIdFromHref('https://h/c/pullRequests/7/threads/33?api-version=7.0')).toBe(33);
    expect(threadIdFromHref('https://h/c/pullRequests/7/threadsX/3')).toBeUndefined();
    expect(threadIdFromHref('https://h/c/pullRequests/7')).toBeUndefined();
  });
});

describe('buildRedactionTable', () => {
  const env = {
    AZURE_PROBE_SERVER_URL:
      'https://ec2-16-1-2-3.eu-north-1.compute.amazonaws.com/DefaultCollection',
    AZURE_PROBE_SERVER_PAT: 'pat-one',
    AZURE_PROBE_SERVER_USER_PASSWORD: 'pw-two',
    AZURE_PROBE_CLIENT_SECRET: 'secret-three',
    AZURE_PROBE_RECORDER_SECRET: 'rec-four',
    AZURE_PROBE_CLIENT_KEY_FILE: 'E:/bench/out/probe-client.key',
    AZURE_PROBE_HOOK_BASE: 'https://16.9.8.7.sslip.io',
    AZURE_PROBE_TENANT_ID: '11111111-2222-3333-4444-555555555555',
    OTHER_PAT: 'not ours',
  };

  it('lists every secret, also as Basic credentials, but not file paths or other keys', () => {
    const t = buildRedactionTable(env);
    for (const s of ['pat-one', 'pw-two', 'secret-three', 'rec-four'])
      expect(t.secrets).toContain(s);
    expect(t.secrets).toContain(Buffer.from(':pat-one').toString('base64'));
    expect(t.secrets).toContain(Buffer.from('qualor:rec-four').toString('base64'));
    expect(t.secrets).not.toContain('E:/bench/out/probe-client.key');
    expect(t.secrets).not.toContain('not ours');
    expect(t.tenantIds).toEqual(['11111111-2222-3333-4444-555555555555']);
  });

  it('lists the hosts with the IPs their names carry, the organisation and the project', () => {
    const t = buildRedactionTable(env);
    expect(t.hosts).toContain('ec2-16-1-2-3.eu-north-1.compute.amazonaws.com');
    expect(t.hosts).toContain('16.1.2.3');
    expect(t.hosts).toContain('16.9.8.7.sslip.io');
    expect(t.hosts).toContain('16.9.8.7');
    // No organisation is named without AZURE_PROBE_SERVICES_URL: there is no built-in name.
    expect(t.orgs).toEqual([]);
    const services = buildRedactionTable({
      AZURE_PROBE_SERVICES_URL: 'https://dev.azure.com/some-org',
      AZURE_PROBE_PROJECT: 'Demo-Project',
    });
    expect(services.orgs).toEqual(
      expect.arrayContaining(['some-org', 'Demo-Project', 'demo-project', 'DEMO-PROJECT']),
    );
    expect(services.hosts).not.toContain('dev.azure.com');
  });

  it('takes the synthetic-id salt from AZURE_PROBE_ID_SALT, and has none without it', () => {
    expect(buildRedactionTable({ AZURE_PROBE_ID_SALT: 'test-salt' }).idSalt).toBe('test-salt');
    expect(buildRedactionTable(env).idSalt).toBeUndefined();
  });

  it('takes names, e-mails and machine names from identities', () => {
    const t = buildRedactionTable({});
    addIdentity(t, {
      id: 'a',
      providerDisplayName: 'Qualor Bot',
      properties: { Account: { $type: 'System.String', $value: 'MACHINE-1\\qualor-bot' } },
    });
    addIdentity(t, {
      id: 'b',
      providerDisplayName: 'Jane Doe',
      properties: {
        Account: { $value: 'jane@corp.example' },
        Mail: { $value: 'Jane@Corp.example' },
      },
    });
    addIdentity(t, { no: 'identity' });
    // The identities API: the Windows machine of a Server account.
    addIdentity(t, {
      id: 'c',
      properties: { Domain: { $value: 'WINHOST-7' }, DirectoryAlias: { $value: 'probe-x' } },
    });
    expect(t.hosts).toEqual(expect.arrayContaining(['WINHOST-7', 'winhost-7']));
    expect(t.names).toContain('probe-x');
    expect(t.names).toEqual(expect.arrayContaining(['Qualor Bot', 'qualor-bot', 'Jane Doe']));
    expect(t.hosts).toEqual(expect.arrayContaining(['MACHINE-1', 'machine-1']));
    expect(t.emails).toEqual(expect.arrayContaining(['jane@corp.example', 'Jane@Corp.example']));
  });
});

describe('leaks', () => {
  it('finds listed values that survived, in any case, and ignores the placeholders', () => {
    const t = buildRedactionTable({
      AZURE_PROBE_SERVER_PAT: 'pat-one',
      AZURE_PROBE_SERVICES_URL: 'https://dev.azure.com/acme-org',
      AZURE_PROBE_ID_SALT: 'test-salt',
    });
    addIdentity(t, {
      id: 'x',
      providerDisplayName: 'Probe User',
      properties: { Account: { $value: 'probe-user' } },
    });
    const clean = JSON.stringify(
      redact({ by: 'Probe User', who: 'probe-user', key: 'pat-one' }, t),
    );
    expect(leaks(clean, t)).toEqual([]);
    expect(leaks('owner ACME-ORG', t)).toEqual(['orgs']);
    expect(leaks('token PAT-ONE', t)).toEqual(['secrets']);
  });
});

describe('scrubEmails', () => {
  it('replaces any e-mail address and keeps what only looks like one', () => {
    expect(scrubEmails('author A <a.b+c@mail.example.org> 1700000000')).toBe(
      'author A <user@example.invalid> 1700000000',
    );
    expect(scrubEmails('zod@4.6.7 @types/node user@example.invalid')).toBe(
      'zod@4.6.7 @types/node user@example.invalid',
    );
  });
});

describe('parseArgs', () => {
  it('reads the target and the item list', () => {
    expect(parseArgs(['--target', 'server', '--items', '1,10'])).toEqual({
      target: 'server',
      items: [1, 10],
    });
    expect(parseArgs(['--target=services'])).toEqual({ target: 'services' });
    expect(() => parseArgs([])).toThrow(/--target/);
    expect(() => parseArgs(['--target', 'prod'])).toThrow(/--target/);
    expect(() => parseArgs(['--target', 'server', '--items', '1,x'])).toThrow(/x/);
    expect(() => parseArgs(['--target', 'server', '--force'])).toThrow(/--force/);
    expect(parseArgs(['--cleanup-manual', '--target', 'server'])).toEqual({
      target: 'server',
      cleanupManual: true,
    });
    expect(() => parseArgs(['--cleanup-manual', '--target', 'server', '--items', '2'])).toThrow();
  });

  it('reads the main identity credential kind, Entra kinds on services only', () => {
    expect(parseArgs(['--target', 'services', '--auth', 'secret', '--items', '7'])).toEqual({
      target: 'services',
      items: [7],
      auth: 'secret',
    });
    expect(parseArgs(['--target=services', '--auth=certificate'])).toEqual({
      target: 'services',
      auth: 'certificate',
    });
    expect(parseArgs(['--target', 'server', '--auth', 'pat'])).toEqual({
      target: 'server',
      auth: 'pat',
    });
    expect(() => parseArgs(['--target', 'server', '--auth', 'secret'])).toThrow(/no Entra/);
    expect(() => parseArgs(['--target', 'services', '--auth', 'oauth'])).toThrow(/oauth/);
    expect(() => parseArgs(['--target', 'services', '--auth'])).toThrow(/needs a value/);
  });
});

describe('build log helpers', () => {
  const lines = [
    '2026-11-21T10:00:00.0000000Z ##[section]Starting: Qualor probe item 17',
    '2026-11-21T10:00:01.0000000Z BUILD_SOURCEVERSION=' + 'a'.repeat(40),
    '2026-11-21T10:00:01.0000000Z SYSTEM_PULLREQUEST_SOURCECOMMITID=unset',
    '2026-11-21T10:00:01.0000000Z --- git cat-file -p HEAD',
    '2026-11-21T10:00:01.0000000Z tree ' + 'f'.repeat(40),
    '2026-11-21T10:00:01.0000000Z parent ' + 'b'.repeat(40),
    '2026-11-21T10:00:01.0000000Z parent ' + 'c'.repeat(40),
    '2026-11-21T10:00:01.0000000Z author Probe User <user@example.invalid> 1700000000 +0000',
    '2026-11-21T10:00:01.0000000Z --- end',
    '2026-11-21T10:00:02.0000000Z HEAD2=' + 'c'.repeat(40),
  ];

  it('keeps only the printed lines and the cat-file block of a step log', () => {
    const withAgent = [
      '2026-11-21T10:00:00.0000000Z Agent machine name: some-machine',
      ...lines,
      '2026-11-21T10:00:03.0000000Z Finishing: Qualor probe item 17',
    ];
    const kept = keptLogLines(
      withAgent,
      ['BUILD_SOURCEVERSION', 'HEAD2'],
      ['--- git cat-file -p HEAD', '--- end'],
    );
    expect(kept.join('\n')).not.toContain('some-machine');
    expect(kept.join('\n')).not.toContain('Starting');
    expect(kept).toHaveLength(8);
    expect(keptLogLines(withAgent, ['HEAD2'])).toEqual([lines[9]]);
  });

  it('keeps no block whose end marker is missing', () => {
    const noEnd = [
      ...lines.slice(0, 8),
      '2026-11-21T10:00:02.0000000Z Agent machine name: some-machine',
      lines[9] ?? '',
    ];
    const kept = keptLogLines(
      noEnd,
      ['BUILD_SOURCEVERSION', 'HEAD2'],
      ['--- git cat-file -p HEAD', '--- end'],
    );
    expect(kept).toEqual([lines[1], lines[9]]);
    expect(parentsOf(noEnd)).toEqual([]);
  });

  it('reads printed name=value lines and the parents of HEAD', () => {
    expect(
      printedValues(lines, [
        'BUILD_SOURCEVERSION',
        'SYSTEM_PULLREQUEST_SOURCECOMMITID',
        'HEAD2',
        'NONE',
      ]),
    ).toEqual({
      BUILD_SOURCEVERSION: 'a'.repeat(40),
      SYSTEM_PULLREQUEST_SOURCECOMMITID: 'unset',
      HEAD2: 'c'.repeat(40),
    });
    expect(parentsOf(lines)).toEqual(['b'.repeat(40), 'c'.repeat(40)]);
    expect(parentsOf(lines.slice(0, 5))).toEqual([]);
  });

  it('takes the lines of a JSON log answer, or splits text', () => {
    expect(logLines({ count: 2, value: ['a', 'b'] })).toEqual(['a', 'b']);
    expect(logLines('a\r\nb')).toEqual(['a', 'b']);
    expect(logLines(null)).toEqual([]);
  });
});

describe('small helpers', () => {
  it('tells thread id numbering apart by whether the two pull requests share ids', () => {
    expect(threadIdScope(10, 11, 12, [10, 12], [11])).toBe('per-collection');
    // System threads interleave: A1 < B1 < A2 still, but both pull requests count from 1.
    expect(threadIdScope(1, 2, 3, [1, 3], [1, 2])).toBe('per-pull-request');
    expect(threadIdScope(3, 2, 4, [1, 2, 3, 4], [1, 2])).toBe('per-pull-request');
    expect(threadIdScope(5, 9, 7, [5, 7], [9])).toBeUndefined();
  });

  it('reads the manual pull requests of one target from the results file', () => {
    const text = [
      '## server — item 2: markers',
      'Manual PR: 12 (refs/heads/probe/2-20261121000000)',
      '## services — item 2: markers',
      'Manual PR: 7 (refs/heads/probe/2-20261121000000)',
      '## server — item 11: corpus',
      'Manual branch: refs/heads/probe/11-20261121000000',
      'Manual PR: 99 (refs/heads/main)',
      '## server — manual clean-up',
      'Manual PR: 13 (refs/heads/probe/x)',
    ].join('\n');
    expect(manualPrsFrom(text, 'server')).toEqual([
      { id: 12, branch: 'refs/heads/probe/2-20261121000000' },
      { branch: 'refs/heads/probe/11-20261121000000' },
    ]);
    expect(manualPrsFrom(text, 'services')).toEqual([
      { id: 7, branch: 'refs/heads/probe/2-20261121000000' },
    ]);
  });

  it('compares queue permissions as one line', () => {
    expect(
      permissionsKey({
        allPipelines: null,
        pipelines: [
          { id: 9, authorized: true },
          { id: 3, authorized: false },
        ],
      }),
    ).toBe('allPipelines none; pipelines [3:false, 9:true]');
    expect(permissionsKey({ allPipelines: { authorized: true } })).toBe(
      'allPipelines true; pipelines []',
    );
    // The probe's own definition (id 9) is left out of the comparison.
    expect(
      permissionsKey(
        {
          pipelines: [
            { id: 9, authorized: false },
            { id: 3, authorized: true },
          ],
        },
        9,
      ),
    ).toBe('allPipelines none; pipelines [3:true]');
  });

  it('decides what --cleanup-manual does with a listed branch and its pull request', () => {
    const branch = 'refs/heads/probe/2-20261121000000';
    const pr = (status: string, sourceRefName = branch) => ({ status, sourceRefName });
    // A branch without a pull request: deleted.
    expect(manualStep({ branch }, undefined)).toEqual({ abandon: false, deleteBranch: true });
    // The pull request is gone (404): the branch is deleted.
    expect(manualStep({ id: 4, branch }, null)).toEqual({
      abandon: false,
      deleteBranch: true,
      note: 'PR 4 not found',
    });
    // Active and from the listed branch: abandoned, then the branch deleted.
    expect(manualStep({ id: 4, branch }, pr('active'))).toEqual({
      abandon: true,
      deleteBranch: true,
      note: 'PR 4 abandoned',
    });
    expect(manualStep({ id: 4, branch }, pr('abandoned'))).toEqual({
      abandon: false,
      deleteBranch: true,
      note: 'PR 4 already abandoned',
    });
    // Completed: the branch is left alone.
    expect(manualStep({ id: 4, branch }, pr('completed'))).toEqual({
      abandon: false,
      deleteBranch: false,
      note: 'PR 4 is completed: its branch is left alone',
    });
    // The id now names someone else's pull request: neither is touched, whatever its status.
    for (const status of ['active', 'abandoned']) {
      expect(manualStep({ id: 4, branch }, pr(status, 'refs/heads/feature/x'))).toEqual({
        abandon: false,
        deleteBranch: false,
        note: `PR 4 is from refs/heads/feature/x, not ${branch}: both left alone`,
      });
    }
  });

  it('names the kind of a name without the name', () => {
    expect(nameKind('Qualor Bot')).toBe('a plain name (10 characters)');
    expect(nameKind('a@b.example')).toBe('an e-mail address');
    expect(nameKind('HOST\\user')).toBe('DOMAIN\\account');
    expect(nameKind('0f0f0f0f-1111-4222-8333-444444444444')).toBe('a GUID');
    expect(nameKind(undefined)).toBe('absent');
  });

  it('stamps in UTC', () => {
    expect(stampOf(new Date('2026-11-21T09:08:07.123Z'))).toBe('20261121090807');
  });
});

describe('commentKind (item 9)', () => {
  const event = (over: {
    pr?: number;
    thread?: number;
    id?: number;
    parent?: number;
    content: string;
  }) => ({
    eventType: 'ms.vss-code.git-pullrequest-comment-event',
    message: { text: 'x' },
    resource: {
      comment: {
        id: over.id ?? 1,
        ...(over.parent === undefined ? {} : { parentCommentId: over.parent }),
        content: over.content,
        author: { id: 'u' },
        _links: {
          threads: {
            href: `https://h/c/_apis/git/repositories/r/pullRequests/${over.pr ?? 5}/threads/${over.thread ?? 3}`,
          },
        },
      },
      pullRequest: { pullRequestId: over.pr ?? 5 },
    },
  });
  const expectIds = { prId: 5, threadId: 3, commentId: 1 };

  it('tells created, edited and reply apart, only on this pull request and thread', () => {
    expect(commentKind(event({ content: 'Qualor probe item 9: a comment' }), expectIds)).toBe(
      'created',
    );
    expect(
      commentKind(event({ content: 'Qualor probe item 9: a comment, edited' }), expectIds),
    ).toBe('edited');
    expect(
      commentKind(event({ id: 2, parent: 1, content: 'Qualor probe item 9: a reply' }), expectIds),
    ).toBe('reply');
    expect(
      commentKind(event({ pr: 6, content: 'Qualor probe item 9: a comment' }), expectIds),
    ).toBeUndefined();
    expect(
      commentKind(event({ thread: 4, content: 'Qualor probe item 9: a comment' }), expectIds),
    ).toBeUndefined();
    expect(
      commentKind(event({ id: 2, parent: 7, content: 'Qualor probe item 9: a reply' }), expectIds),
    ).toBeUndefined();
    expect(commentKind(event({ content: 'someone else' }), expectIds)).toBeUndefined();
  });
});

describe('Cleanup.run', () => {
  it('takes its steps once: two concurrent runs execute each step exactly once, newest first', async () => {
    const order: string[] = [];
    const c = new Cleanup();
    for (const label of ['branch', 'definition', 'policy']) {
      c.add(label, async () => {
        await new Promise((r) => setTimeout(r, 5));
        order.push(label);
      });
    }
    expect(c.pending()).toEqual(['branch', 'definition', 'policy']);
    const runs = Promise.all([c.run(), c.run()]);
    // While the first step runs, all three are still unfinished.
    expect(c.pending()).toEqual(['policy', 'definition', 'branch']);
    const [a, b] = await runs;
    expect(order).toEqual(['policy', 'definition', 'branch']);
    expect(a).toEqual([]);
    expect(b).toEqual([]);
    expect(c.pending()).toEqual([]);
  });

  it('runs the remaining steps after one fails and names the failure', async () => {
    const c = new Cleanup();
    const ran: string[] = [];
    c.add('first', async () => ran.push('first'));
    c.add('second', async () => {
      throw new Error('gone wrong');
    });
    expect(await c.run()).toEqual(['second: gone wrong']);
    expect(ran).toEqual(['first']);
  });
});

describe('sleep after a stop request', () => {
  it('ends with InterruptedError', async () => {
    stop.requested = true;
    try {
      await expect(sleep(10_000)).rejects.toBeInstanceOf(InterruptedError);
    } finally {
      stop.requested = false;
    }
    await expect(sleep(1)).resolves.toBeUndefined();
  });
});

describe('prPageOpens (item 12)', () => {
  const page = (status: number, text: string, headers: Record<string, string> = {}) => ({
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', ...headers },
    text,
  });
  const title = 'Qualor probe item 12 (20261121080000)';

  it('accepts a 200 HTML page that carries the pull request title', () => {
    expect(prPageOpens(page(200, `<html>${title}</html>`), title)).toBe(true);
    expect(prPageOpens(page(200, '<html>Qualor &lt;b&gt; probe</html>'), 'Qualor <b> probe')).toBe(
      true,
    );
  });

  it('refuses the application shell an unknown id gets, a redirect, a non-HTML answer and a 401', () => {
    expect(prPageOpens(page(200, '<html><title>Pull requests</title></html>'), title)).toBe(false);
    expect(prPageOpens(page(200, title, { location: 'https://h/_signin' }), title)).toBe(false);
    expect(prPageOpens(page(200, title, { 'content-type': 'application/json' }), title)).toBe(
      false,
    );
    expect(prPageOpens(page(401, title), title)).toBe(false);
  });
});

describe('pickResourceVersion (item 9)', () => {
  it('takes 2.0 where offered, else the newest released version, else none', () => {
    expect(pickResourceVersion(['2.0', '1.0', '1.0-preview.1'])).toBe('2.0');
    expect(pickResourceVersion(['1.0', '1.0-preview.1'])).toBe('1.0');
    expect(pickResourceVersion(['1.0-preview.1'])).toBe('1.0-preview.1');
    expect(pickResourceVersion(['1.0', '1.1', '1.0-preview.1'])).toBe('1.1');
    expect(pickResourceVersion([])).toBeUndefined();
    expect(pickResourceVersion(undefined)).toBeUndefined();
  });
});

describe('contributeSource (item 16)', () => {
  it('credits groups only when the entry itself lacks Contribute', () => {
    // Server's probe-user: no allow of its own, Contribute through the Contributors group.
    expect(contributeSource(0, 82038)).toBe('groups');
    // Services' repository creator: Contribute in its own entry, so groups are not shown.
    expect(contributeSource(228990, 491390)).toBe('explicit');
    // Server's probe-reader: no Contribute at all.
    expect(contributeSource(0, 81922)).toBe('none');
    expect(contributeSource(4, 0)).toBe('none');
  });
});

describe('aclAnswer (item 16)', () => {
  it('says yes only when a group-derived Contribute is shown', () => {
    // Server: probe-user through Contributors, probe-reader without Contribute.
    expect(aclAnswer('groups', true)).toBe('yes');
    expect(aclAnswer('groups', undefined)).toBe('partly');
    expect(aclAnswer('groups', false)).toBe('no');
    // Services: the maintainer's own entry allows Contribute; the service principal's group does.
    expect(aclAnswer('explicit', 'skipped', 'groups')).toBe('yes');
    expect(aclAnswer('explicit', 'skipped', 'explicit')).toBe('partly');
    expect(aclAnswer('explicit', 'skipped')).toBe('partly');
    expect(aclAnswer('explicit', true)).toBe('partly');
    // No effective Contribute read for another identity.
    expect(aclAnswer('none', 'skipped', 'groups')).toBe('no');
    expect(aclAnswer(undefined, 'skipped', 'groups')).toBe('no');
  });
});

describe('excerpt (item 10)', () => {
  it('redacts before it cuts, so a value split by the cut leaves no start behind', () => {
    const table = buildRedactionTable({
      AZURE_PROBE_SERVICES_URL: 'https://dev.azure.com/acme-org',
    });
    const text = `${'a/'.repeat(97)}a%2Facme-org%2F_apis`; // 195 characters before %2F
    // Cut first, the slice would end in "%2Fac".
    expect(text.slice(0, 200).endsWith('%2Fac')).toBe(true);
    const cut = excerpt(text, table);
    expect(cut).toHaveLength(200);
    expect(cut.toLowerCase()).not.toContain('%2fac');
    expect(cut.endsWith('%2Fpr')).toBe(true); // the start of probe-org
    expect(excerpt('short', table)).toBe('short');
  });
});

describe('writeRecording', () => {
  const withRoot = async (fn: (root: string) => Promise<void>) => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'azure-shapes-'));
    try {
      await fn(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
  const table = () =>
    buildRedactionTable({ AZURE_PROBE_SERVER_PAT: 'pat-one', AZURE_PROBE_ID_SALT: 'test-salt' });

  it('writes the redacted value under the given root', async () => {
    await withRoot(async (root) => {
      const saved = await writeRecording(table(), 'server', 1, 'sample', { key: 'pat-one' }, root);
      expect(saved).toBe('server/test/azure-shapes/server/1-sample.json');
      const text = readFileSync(path.join(root, 'server', '1-sample.json'), 'utf8');
      expect(JSON.parse(text)).toEqual({ key: '<secret>' });
    });
  });

  it('refuses, writing nothing, when a listed value survives redaction', async () => {
    await withRoot(async (root) => {
      // Redaction replaces the listed spelling; the leak check finds any case.
      await expect(
        writeRecording(table(), 'server', 1, 'leaky', { key: 'PAT-ONE' }, root),
      ).rejects.toThrow(/would still hold: secrets; not written/);
      expect(existsSync(path.join(root, 'server'))).toBe(false);
    });
  });

  it('refuses, writing nothing, without the synthetic-id salt', async () => {
    await withRoot(async (root) => {
      const unsalted = buildRedactionTable({ AZURE_PROBE_SERVER_PAT: 'pat-one' });
      await expect(
        writeRecording(unsalted, 'server', 1, 'sample', { id: 'x' }, root),
      ).rejects.toThrow(/AZURE_PROBE_ID_SALT/);
      expect(existsSync(path.join(root, 'server'))).toBe(false);
    });
  });
});

describe('trimTypes (item 13)', () => {
  const field = (referenceName: string, alwaysRequired: boolean) => ({
    referenceName,
    name: referenceName,
    alwaysRequired,
  });
  const answer = {
    count: 1,
    value: [
      {
        name: 'Bug',
        referenceName: 'Microsoft.VSTS.WorkItemTypes.Bug',
        xmlForm: '<FORM/>',
        transitions: {},
        fieldInstances: [
          { ...field('System.Title', false), helpText: 'the title' },
          { ...field('System.AreaId', true), helpText: 'the area' },
          { ...field('Custom.Unused', false), helpText: 'unused' },
        ],
        url: 'https://ado.example.invalid/x',
        fields: [
          field('System.Title', false),
          field('System.AreaId', true),
          field('Custom.Unused', false),
        ],
      },
    ],
  };

  it('keeps only required and used fields and field instances, in place', () => {
    const trimmed = trimTypes(answer) as { value: Record<string, unknown>[] };
    const type = trimmed.value[0] ?? {};
    expect(Object.keys(type)).toEqual(['name', 'referenceName', 'fieldInstances', 'url', 'fields']);
    const names = (list: unknown) =>
      (list as { referenceName: string }[]).map((f) => f.referenceName);
    expect(names(type['fieldInstances'])).toEqual(['System.Title', 'System.AreaId']);
    expect(names(type['fields'])).toEqual(['System.Title', 'System.AreaId']);
    expect(trimTypes(trimmed)).toEqual(trimmed);
  });
});
