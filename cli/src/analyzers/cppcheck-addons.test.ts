import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { CPPCHECK_VERSION, parseConfig, type QualorConfigInput } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { cFamilyContext } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { cppcheckAnalyzer } from './cppcheck';
import { cppcheckXmlToSarif } from './cppcheck-xml';
import type { AnalyzerCommand } from './types';

const tmp = useTempDirs();
const PYTHON = '/usr/bin/python3';

type Settings = NonNullable<NonNullable<QualorConfigInput['analyzers']>['cppcheck']>;

function setup(
  files: Record<string, string>,
  o: {
    settings?: Settings;
    installed?: readonly string[];
    python?: boolean;
    lines?: string[];
  } = {},
) {
  const prefix = tmp();
  writeTree(
    prefix,
    Object.fromEntries(
      (o.installed ?? ['misra']).map((a) => [`share/cppcheck/addons/${a}.py`, 'x']),
    ),
  );
  const { ctx, root, work } = cFamilyContext(tmp, files, {
    binaries: {
      cppcheck: path.join(prefix, 'bin', 'cppcheck'),
      ...(o.python !== false && { python3: PYTHON }),
    },
    versionStdout: `Cppcheck ${CPPCHECK_VERSION}\n`,
    config: { analyzers: { cppcheck: { addons: ['misra'], ...o.settings } } },
    ...(o.lines !== undefined && { lines: o.lines }),
  });
  return { ctx, root, work, addons: path.join(prefix, 'share', 'cppcheck', 'addons') };
}

async function run(ctx: ReturnType<typeof setup>['ctx']): Promise<AnalyzerCommand> {
  const p = await cppcheckAnalyzer.prepare(ctx);
  if (!('run' in p)) throw new Error(JSON.stringify(p));
  return p.run;
}

const addonArgs = (cmd: AnalyzerCommand) => cmd.args.filter((a) => a.startsWith('--addon'));

describe('cppcheck addons: the command (issue #33)', () => {
  it('runs a chosen addon by its absolute path in the install, with a pinned python', async () => {
    const { ctx, addons } = setup({ 'src/a.c': 'int a;\n' });
    const cmd = await run(ctx);
    expect(addonArgs(cmd)).toEqual([
      `--addon-python=${PYTHON}`,
      `--addon=${path.join(addons, 'misra.py')}`,
    ]);
    expect(cmd.env).toMatchObject({ PYTHONDONTWRITEBYTECODE: '1' });
  });

  it('turns on style and warning, which cppcheck needs to keep addon results', async () => {
    const { ctx } = setup({ 'src/a.c': 'int a;\n' }, { settings: { enable: ['performance'] } });
    expect((await run(ctx)).args).toContain('--enable=performance,warning,style');
  });

  it('does not repeat a group the project already enabled', async () => {
    const { ctx } = setup(
      { 'src/a.c': 'int a;\n' },
      { settings: { enable: ['style', 'warning'] } },
    );
    expect((await run(ctx)).args).toContain('--enable=style,warning');
  });

  it('never names or copies an addon file of the checkout', async () => {
    const { ctx, root, work } = setup({
      'src/a.c': 'int a;\n',
      'misra.py': 'evil',
      'runaddon.py': 'evil',
      'misra.json': '{"script":"evil.py"}',
      'src/runaddon.py': 'evil',
    });
    const cmd = await run(ctx);
    for (const a of addonArgs(cmd)) expect(a).not.toContain(root);
    expect(readdirSync(path.join(work, 'src', 'src'))).toEqual(['a.c']);
    expect(readdirSync(path.join(work, 'src'))).toEqual(['src']);
  });

  it('is a skip when python3 cannot be found', async () => {
    const { ctx } = setup({ 'src/a.c': 'int a;\n' }, { python: false });
    expect(await cppcheckAnalyzer.prepare(ctx)).toEqual({
      skip: expect.stringContaining('python3') as string,
    });
  });

  it('is a skip when the addon is not installed beside cppcheck', async () => {
    const { ctx } = setup(
      { 'src/a.c': 'int a;\n' },
      { installed: ['misra'], settings: { addons: ['misra', 'y2038'] } },
    );
    expect(await cppcheckAnalyzer.prepare(ctx)).toEqual({
      skip: expect.stringContaining('y2038') as string,
    });
  });

  it('adds no addon option and keeps the groups when no addon is chosen', async () => {
    const { ctx } = setup({ 'src/a.c': 'int a;\n' }, { settings: { addons: [] } });
    const cmd = await run(ctx);
    expect(addonArgs(cmd)).toEqual([]);
    expect(cmd.args).toContain('--enable=warning,performance,portability');
    expect(cmd.env).not.toHaveProperty('PYTHONDONTWRITEBYTECODE');
  });
});

describe('cppcheck addons: the MISRA rule texts (issue #33)', () => {
  it('copies the file out of the checkout and names it in an addon file of its own', async () => {
    const { ctx, work, addons } = setup(
      { 'src/a.c': 'int a;\n', 'misra/rules.txt': 'Rule 1.1\nText\n' },
      { settings: { misraRuleTexts: 'misra/rules.txt' } },
    );
    const cmd = await run(ctx);
    const addonFile = path.join(work, 'cppcheck-addon-misra.json');
    const texts = path.join(work, 'misra-rule-texts.txt');
    expect(addonArgs(cmd)).toEqual([`--addon-python=${PYTHON}`, `--addon=${addonFile}`]);
    expect(JSON.parse(readFileSync(addonFile, 'utf8'))).toEqual({
      script: path.join(addons, 'misra.py'),
      args: [`--rule-texts=${texts}`],
    });
    expect(readFileSync(texts, 'utf8')).toBe('Rule 1.1\nText\n');
  });

  it('is a skip when the file does not exist', async () => {
    const { ctx } = setup(
      { 'src/a.c': 'int a;\n' },
      { settings: { misraRuleTexts: 'missing.txt' } },
    );
    expect(await cppcheckAnalyzer.prepare(ctx)).toEqual({
      skip: expect.stringContaining('missing.txt') as string,
    });
  });

  it('is a skip when the file is larger than 1 MiB', async () => {
    const { ctx, work } = setup(
      { 'src/a.c': 'int a;\n', 'rules.txt': 'x'.repeat(1024 * 1024 + 1) },
      { settings: { misraRuleTexts: 'rules.txt' } },
    );
    expect(await cppcheckAnalyzer.prepare(ctx)).toEqual({
      skip: expect.stringContaining('1 MiB') as string,
    });
    expect(existsSync(path.join(work, 'misra-rule-texts.txt'))).toBe(false);
  });

  const check = (cppcheck: Settings) =>
    cppcheckAnalyzer.checkConfig?.(tmp(), parseConfig({ version: 1, analyzers: { cppcheck } })) ??
    null;

  it('accepts a repository file with the misra addon', () => {
    expect(check({ addons: ['misra'], misraRuleTexts: 'rules.txt' })).toBeNull();
  });

  it('refuses a URL or a path outside the repository', () => {
    expect(check({ addons: ['misra'], misraRuleTexts: 'https://x/rules.txt' })).toContain('URL');
    expect(check({ addons: ['misra'], misraRuleTexts: '../rules.txt' })).toContain('outside');
  });

  it('refuses rule texts without the misra addon', () => {
    expect(check({ addons: ['y2038'], misraRuleTexts: 'rules.txt' })).toContain('misra');
  });
});

describe('cppcheck addons: paths a shell would interpret (issue #33)', () => {
  const files = {
    'src/ok.c': 'int a;\n',
    'src/with space.c': 'int a;\n',
    'src/äö.c': 'int a;\n',
    'c++/x.c': 'int a;\n',
    'src/$(touch x).c': 'int a;\n',
    'src/`touch x`.c': 'int a;\n',
    'src/a;b.c': 'int a;\n',
    "src/q'x.c": 'int a;\n',
    'd$(x)/y.c': 'int a;\n',
    '-x.c': 'int a;\n',
  };
  const listed = (work: string) =>
    readFileSync(path.join(work, 'cppcheck-files.txt'), 'utf8').trim().split('\n').sort();

  it('leaves such a file out with a warning when an addon runs', async () => {
    const lines: string[] = [];
    const { ctx, work } = setup(files, { lines });
    await run(ctx);
    expect(listed(work)).toEqual(['c++/x.c', 'src/ok.c', 'src/with space.c', 'src/äö.c']);
    expect(lines.join('\n')).toContain('6 C/C++ file(s) left out');
  });

  it('keeps such a file when no addon runs', async () => {
    const lines: string[] = [];
    const { ctx, work } = setup(files, { lines, settings: { addons: [] } });
    await run(ctx);
    expect(listed(work)).toHaveLength(Object.keys(files).length);
    expect(lines.join('\n')).not.toContain('left out');
  });

  it('is a skip when no file is left', async () => {
    const { ctx } = setup({ 'src/$(x).c': 'int a;\n' });
    expect(await cppcheckAnalyzer.prepare(ctx)).toHaveProperty('skip');
  });

  it.runIf(process.platform !== 'win32')(
    'is a skip when the work directory holds such a character',
    async () => {
      const { ctx } = setup({ 'src/a.c': 'int a;\n' });
      expect(await cppcheckAnalyzer.prepare({ ...ctx, workDir: `${ctx.workDir}/$(x)` })).toEqual({
        skip: expect.stringContaining('work directory') as string,
      });
    },
  );
});

describe('cppcheck addons: the results (issue #33)', () => {
  const base = path.resolve('/w/src');
  const error = (id: string, severity: string, msg = 'm') =>
    `<error id="${id}" severity="${severity}" msg="${msg}"><location file="a.c" line="1" column="1"/></error>`;
  const convert = (errors: string, projectGroups?: ReadonlySet<string>) =>
    cppcheckXmlToSarif(
      `<?xml version="1.0"?><results version="2"><cppcheck version="2.22.0"/><errors>${errors}</errors></results>`,
      { version: '2.22.0', base, ...(projectGroups !== undefined && { projectGroups }) },
    );
  const ids = (c: ReturnType<typeof convert>) => c.log.runs[0]?.results?.map((r) => r.ruleId);

  it("keeps addon results and only the groups the project enabled of cppcheck's own", () => {
    const c = convert(
      error('misra-c2012-10.3', 'style') +
        error('y2038-unsafe-call', 'warning') +
        error('shadowVariable', 'style') +
        error('uninitvar', 'warning') +
        error('passedByValue', 'performance') +
        error('nullPointer', 'error'),
      new Set(['performance']),
    );
    expect(ids(c)).toEqual([
      'misra-c2012-10.3',
      'y2038-unsafe-call',
      'passedByValue',
      'nullPointer',
    ]);
  });

  it('keeps every result without addons', () => {
    expect(ids(convert(error('shadowVariable', 'style')))).toEqual(['shadowVariable']);
  });

  it('counts misra-config as no finding', () => {
    const c = convert(error('misra-config', 'error'), new Set());
    expect(ids(c)).toEqual([]);
    expect(c.notAnalysed.get('misra-config')).toBe(1);
  });

  it('names the MISRA rule when there is no rule text', () => {
    const c = convert(
      error(
        'misra-c2012-10.3',
        'style',
        'misra violation (use --rule-texts=&lt;file&gt; to get proper output)',
      ),
      new Set(),
    );
    expect(c.log.runs[0]?.results?.[0]?.message?.text).toBe(
      'Violation of MISRA C 2012 rule 10.3. Set analyzers.cppcheck.misraRuleTexts for its text.',
    );
  });

  it('counts the addon runs that failed', () => {
    const c = convert(
      error('internalError', 'error', "Bailing out: Failed to execute addon 'misra'") +
        error('internalError', 'error', 'something else'),
      new Set(),
    );
    expect(c.addonFailures).toBe(1);
  });
});
