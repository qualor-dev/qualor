import { docLink, normalizePath, parseDocPage, REPOSITORY, slugger } from './markdown';

describe('docLink: the guide links as qualor.dev rewrites them, in the app', () => {
  it.each([
    ['./gitlab.md', { kind: 'page', route: ['/docs', 'gitlab'], fragment: null }],
    ['./gitlab.md#merge-request-comments', { kind: 'page', route: ['/docs', 'gitlab'], fragment: 'merge-request-comments' }],
    ['README.md', { kind: 'page', route: ['/docs'], fragment: null }],
    ['#tokens', { kind: 'page', route: ['/docs', 'cli'], fragment: 'tokens' }],
    ['../../deploy/README.md', { kind: 'external', href: `${REPOSITORY}/blob/main/deploy/README.md` }],
    ['../../templates/', { kind: 'external', href: `${REPOSITORY}/tree/main/templates` }],
    ['../../../elsewhere.md', { kind: 'external', href: '../../../elsewhere.md' }],
    ['https://qualor.dev/docs', { kind: 'external', href: 'https://qualor.dev/docs' }],
    ['mailto:security@qualor.dev', { kind: 'external', href: 'mailto:security@qualor.dev' }],
  ])('%s', (href, expected) => {
    expect(docLink(href, 'cli')).toEqual(expected);
  });

  it('normalizes paths', () => {
    expect(normalizePath('docs/guide/../../deploy/./README.md')).toBe('deploy/README.md');
    expect(normalizePath('docs/guide/../../../x')).toBe('../x');
  });
});

describe('slugger: GitHub heading anchors', () => {
  it('lowers, drops punctuation, dashes spaces and numbers repeats', () => {
    const slug = slugger();
    expect(slug('Upgrade the server')).toBe('upgrade-the-server');
    expect(slug('`qualor.yml` & env: precedence!')).toBe('qualoryml--env-precedence');
    expect(slug('Upgrade the server')).toBe('upgrade-the-server-1');
    expect(slug('Upgrade the server')).toBe('upgrade-the-server-2');
  });
});

describe('parseDocPage', () => {
  const page = parseDocPage(
    [
      '# Quick start',
      '',
      'Run **the** [server](./install-server.md#tls) with `docker`.',
      '',
      '## Install',
      '',
      '1. One',
      '2. Two',
      '   - nested',
      '',
      '```prompt',
      'Set up <Qualor>.',
      '```',
      '',
      '| Name | Value |',
      '| :--- | ---: |',
      '| a | `1` |',
      '',
      '> Note <b>raw</b>',
      '',
      '## Install',
    ].join('\r\n'),
    'quick-start',
  );

  it('takes the title from the H1 and lists the headings below it with anchors', () => {
    expect(page.title).toBe('Quick start');
    expect(page.headings).toEqual([
      { depth: 2, id: 'install', text: 'Install' },
      { depth: 2, id: 'install-1', text: 'Install' },
    ]);
  });

  it('keeps inline structure and rewrites links', () => {
    expect(page.blocks[0]).toEqual({
      kind: 'paragraph',
      children: [
        { kind: 'text', text: 'Run ' },
        { kind: 'strong', children: [{ kind: 'text', text: 'the' }] },
        { kind: 'text', text: ' ' },
        {
          kind: 'link',
          link: { kind: 'page', route: ['/docs', 'install-server'], fragment: 'tls' },
          children: [{ kind: 'text', text: 'server' }],
        },
        { kind: 'text', text: ' with ' },
        { kind: 'code', text: 'docker' },
        { kind: 'text', text: '.' },
      ],
    });
  });

  it('turns lists, code, tables and quotes into blocks, and raw HTML into text', () => {
    const kinds = page.blocks.map((b) => b.kind);
    expect(kinds).toEqual(['paragraph', 'heading', 'list', 'code', 'table', 'blockquote', 'heading']);
    const list = page.blocks[2];
    expect(list?.kind === 'list' && list.ordered && list.items.length).toBe(2);
    expect(page.blocks[3]).toEqual({ kind: 'code', lang: 'prompt', text: 'Set up <Qualor>.' });
    const table = page.blocks[4];
    expect(table?.kind === 'table' && table.align).toEqual(['left', 'right']);
    expect(JSON.stringify(page.blocks[5])).toContain('<b>');
  });
});
