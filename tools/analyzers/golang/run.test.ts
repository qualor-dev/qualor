import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { GOSEC_RULE_ID } from '@qualor/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GO_RUNNER_MAX_WARNINGS } from '../../../cli/src/analyzers/golang';
import { useTempDirs } from '../../../cli/test/tmp';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import * as runner from './run.mjs';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('run.mjs helpers (plan 9C)', () => {
  it('reads the top-level objects of go list and go vet output, strings with braces included', () => {
    const text = '{}\n{\n\t"a": "x}{",\n\t"b": {"c": 1}\n}\n{\n\t"d": "\\"}"\n}\n';
    expect(runner.splitJsonObjects(text)).toEqual([{}, { a: 'x}{', b: { c: 1 } }, { d: '"}' }]);
    expect(() => runner.splitJsonObjects('{"a": 1')).toThrow(/truncated/);
    expect(() => runner.splitJsonObjects('}')).toThrow(/unbalanced/);
  });

  it('keeps one bounded line of tool text, never a # header or a control character', () => {
    expect(runner.detail('# example.com/e\n./main.go:22:20: undefined: x\n')).toBe(
      './main.go:22:20: undefined: x',
    );
    expect(runner.detail('a\u001b[31mb')).toBe('a [31mb');
    expect(runner.detail('x'.repeat(400))).toHaveLength(300);
    expect(runner.detail(undefined)).toBe('');
  });

  it('plans the packages that load and hold in-scope files, and lists those that cannot load', () => {
    const mod = tmp();
    for (const d of ['store', 'cmd/app', 'gen', 'onlytests'])
      mkdirSync(path.join(mod, d), { recursive: true });
    const listed = [
      { ImportPath: 'ex/store', Dir: path.join(mod, 'store') },
      {
        ImportPath: 'ex/cmd/app',
        Dir: path.join(mod, 'cmd/app'),
        DepsErrors: [{ Err: 'module lookup disabled by GOPROXY=off' }],
      },
      { ImportPath: 'ex/gen', Dir: path.join(mod, 'gen') },
      {
        ImportPath: 'ex/onlytests',
        Dir: path.join(mod, 'onlytests'),
        Error: { Err: 'no non-test Go files in …' },
      },
      { ImportPath: 'ex/root', Dir: mod },
    ];
    const scope = new Set(
      ['store', 'cmd/app', 'onlytests', ''].map((d) => runner.realOr(path.join(mod, d))),
    );
    expect(runner.plannedPackages(listed, mod, scope)).toEqual({
      packages: [
        { importPath: 'ex/store', dir: './store' },
        { importPath: 'ex/onlytests', dir: './onlytests' },
        { importPath: 'ex/root', dir: '.' },
      ],
      failed: [{ importPath: 'ex/cmd/app', error: 'module lookup disabled by GOPROXY=off' }],
    });
  });

  it('turns staticcheck JSON into results and compile problems, at repository paths', () => {
    const toRepo = (f: string) => (f.startsWith('/repo/') ? f.slice('/repo/'.length) : null);
    const text = [
      JSON.stringify({
        code: 'SA5009',
        severity: 'warning',
        location: { file: '/repo/a b/x.go', line: 45, column: 21 },
        end: { file: '/repo/a b/x.go', line: 45, column: 31 },
        message: 'Printf format %d has arg #1 of wrong type string',
      }),
      JSON.stringify({
        code: 'U1000',
        severity: 'warning',
        location: { file: '/repo/y.go', line: 3, column: 6 },
        end: { file: '', line: 0, column: 0 },
        message: 'func f is unused',
      }),
      JSON.stringify({
        code: 'compile',
        severity: 'error',
        location: { file: '', line: 0, column: 0 },
        end: { file: '', line: 0, column: 0 },
        message: '# ex/e\n./main.go:22:20: undefined: cgoValue',
      }),
      JSON.stringify({
        code: 'SA4006',
        location: { file: '/elsewhere/z.go', line: 1, column: 1 },
        message: 'outside',
      }),
      '',
    ].join('\n');
    const out = runner.staticcheckResults(text, toRepo);
    expect(out.problems).toEqual(['./main.go:22:20: undefined: cgoValue']);
    expect(out.results.map((r: { rel: string; sarif: unknown }) => [r.rel, r.sarif])).toEqual([
      [
        'a b/x.go',
        {
          ruleId: 'SA5009',
          level: 'warning',
          message: { text: 'Printf format %d has arg #1 of wrong type string' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'a%20b/x.go' },
                region: { startLine: 45, startColumn: 21, endLine: 45, endColumn: 31 },
              },
            },
          ],
        },
      ],
      [
        'y.go',
        {
          ruleId: 'U1000',
          level: 'warning',
          message: { text: 'func f is unused' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'y.go' },
                region: { startLine: 3, startColumn: 6 },
              },
            },
          ],
        },
      ],
    ]);
  });

  it('turns go vet JSON into results per analyzer, and analyzer errors into problems', () => {
    const toRepo = (f: string) => (f.startsWith('/repo/') ? f.slice('/repo/'.length) : null);
    const objects = [
      {},
      {
        'ex/store': {
          copylocks: [
            {
              posn: '/repo/store/store.go:39:17',
              end: '/repo/store/store.go:39:22',
              message: 'Snapshot passes lock by value',
            },
          ],
          printf: [
            {
              posn: '/repo/store/store.go:45:22',
              end: '/repo/store/store.go:45:24',
              message: 'fmt.Sprintf format %d has arg "many" of wrong type string',
            },
          ],
          nilness: { error: 'analysis failed: boom' },
        },
      },
    ];
    const out = runner.vetResults(objects, toRepo);
    expect(
      out.results.map((r: { rel: string; sarif: { ruleId: string } }) => [r.rel, r.sarif.ruleId]),
    ).toEqual([
      ['store/store.go', 'copylocks'],
      ['store/store.go', 'printf'],
    ]);
    expect(out.problems).toEqual(['analysis failed: boom']);
  });

  it("rebases gosec's SARIF, relative to the package directory it was given, onto repository paths and keeps its rules", () => {
    const mod = tmp();
    const pkg = path.join(mod, 'store');
    mkdirSync(pkg);
    writeFileSync(path.join(pkg, 'store.go'), 'package store\n');
    writeFileSync(path.join(pkg, 'abs.go'), 'package store\n');
    const toRepo = (f: string) => {
      const rel = path.relative(mod, f);
      return rel.startsWith('..') ? null : `svc/${rel.split(path.sep).join('/')}`;
    };
    const at = (uri: string, line: number) => [
      { physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } },
    ];
    const log = {
      runs: [
        {
          tool: {
            driver: {
              name: 'gosec',
              rules: [
                {
                  id: 'G401',
                  properties: { tags: ['security', 'MEDIUM'] },
                  relationships: [{ target: { id: '328', toolComponent: { name: 'CWE' } } }],
                },
              ],
            },
          },
          results: [
            // gosec 2.29.0 given ./store writes `store.go`, relative to the package directory (pre-flight).
            {
              ruleId: 'G401',
              level: 'error',
              message: { text: 'Use of weak cryptographic primitive' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'store.go' },
                    region: { startLine: 60, startColumn: 9 },
                  },
                },
              ],
            },
            {
              ruleId: 'G401',
              level: 'error',
              message: { text: 'file URI' },
              locations: at(pathToFileURL(path.join(pkg, 'abs.go')).href, 2),
            },
            {
              ruleId: 'G401',
              level: 'error',
              message: { text: 'absolute path' },
              locations: at(path.join(pkg, 'abs.go'), 3),
            },
            {
              ruleId: 'G101',
              level: 'error',
              message: { text: 'x' },
              locations: at('../../outside.go', 1),
            },
          ],
        },
      ],
    };
    const out = runner.gosecResults(log, pkg, toRepo);
    expect(out.rules.map((r: { id: string }) => r.id)).toEqual(['G401']);
    expect(
      out.results.map((r: { rel: string; sarif: { ruleId: string; level: string } }) => [
        r.rel,
        r.sarif.ruleId,
        r.sarif.level,
      ]),
    ).toEqual([
      ['svc/store/store.go', 'G401', 'error'],
      ['svc/store/abs.go', 'G401', 'error'],
      ['svc/store/abs.go', 'G401', 'error'],
    ]);
  });

  it("prints as many warnings as the CLI logs (golang.ts's GO_RUNNER_MAX_WARNINGS)", () => {
    expect(runner.MAX_WARNINGS).toBe(GO_RUNNER_MAX_WARNINGS);
  });

  it("checks gosec rule ids with the CLI's own pattern", () => {
    expect(runner.GOSEC_ID.source).toBe(GOSEC_RULE_ID.source);
  });

  it("links go vet analyzers to their package's page, under its own name when that differs", () => {
    const passes = 'https://pkg.go.dev/golang.org/x/tools/go/analysis/passes';
    expect(runner.HELP.govet('printf')).toBe(`${passes}/printf`);
    expect(runner.HELP.govet('copylocks')).toBe(`${passes}/copylock`);
    expect(runner.HELP.govet('composites')).toBe(`${passes}/composite`);
    expect(runner.HELP.staticcheck('SA4000')).toBe('https://staticcheck.dev/docs/checks#SA4000');
  });

  it('encodes each path segment, so the normaliser decodes it back exactly', () => {
    expect(runner.encodeUri('a b/c#d/100%/x:y.go')).toBe('a%20b/c%23d/100%25/x%3Ay.go');
  });

  it('refuses a spec that is not what the CLI writes', () => {
    const dir = tmp();
    const file = path.join(dir, 'spec.json');
    const good = {
      tool: 'staticcheck',
      toolPath: '/b/staticcheck',
      go: '/b/go',
      version: '2026.2.1',
      root: '/r',
      workDir: '/w',
      out: '/w/o.sarif',
      files: ['a.go'],
      modules: [{ dir: '/r', rel: '' }],
      gosecExclude: [],
    };
    for (const bad of [
      { tool: 'golangci-lint' },
      { go: 'go' },
      { files: 'a.go' },
      { modules: [{ dir: 'rel', rel: '' }] },
      { gosecExclude: ['--conf=x'] },
    ]) {
      writeFileSync(file, JSON.stringify({ ...good, ...bad }));
      expect(() => runner.readSpec(file), JSON.stringify(bad)).toThrow(/spec:/);
    }
    writeFileSync(file, JSON.stringify(good));
    expect(runner.readSpec(file)).toEqual(good);
  });

  it('exits 2 with one fatal line when there is no spec', () => {
    const err: string[] = [];
    expect(runner.main([], { out: () => {}, err: (s: string) => err.push(s) })).toBe(2);
    expect(err).toEqual(['go: fatal: missing --spec\n']);
  });
});

describe.runIf(posix)('run.mjs with stand-in tools (plan 9C)', () => {
  function fakeTools(dir: string) {
    const go = path.join(dir, 'go');
    writeFileSync(
      go,
      '#!/bin/sh\ncase "$1" in\n  list) cat "$FAKE_DIR/list.json" ;;\n  vet) cat "$FAKE_DIR/vet.json"; exit "${FAKE_VET_EXIT:-0}" ;;\nesac\n',
    );
    const sc = path.join(dir, 'staticcheck');
    writeFileSync(
      sc,
      '#!/bin/sh\necho "$@" > "$FAKE_DIR/staticcheck.args"\ncat "$FAKE_DIR/staticcheck.json"\nexit 1\n',
    );
    // Like gosec 2.29.0 given one package directory: one G401 on `a.go`, relative to that directory.
    const gs = path.join(dir, 'gosec');
    writeFileSync(
      gs,
      [
        '#!/bin/sh',
        'for a in "$@"; do case "$a" in -out=*) out="${a#-out=}" ;; esac; prev="$last"; last="$a"; done',
        'echo "$prev $last $out" >> "$FAKE_DIR/gosec.args"',
        `printf '%s' '${JSON.stringify({ runs: [{ tool: { driver: { name: 'gosec', rules: [{ id: 'G401', properties: { tags: ['security', 'MEDIUM'] } }] } }, results: [{ ruleId: 'G401', level: 'warning', message: { text: 'weak' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.go' }, region: { startLine: 3 } } }] }] }] })}' > "$out"`,
        '',
      ].join('\n'),
    );
    for (const f of [go, sc, gs]) chmodSync(f, 0o755);
    return { go, sc, gs };
  }

  it('runs gosec once per package and keeps the same file name of two packages apart', () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    for (const d of ['one', 'two']) mkdirSync(path.join(root, d));
    const { go, gs } = fakeTools(fake);
    writeFileSync(
      path.join(fake, 'list.json'),
      [
        { ImportPath: 'ex/one', Dir: path.join(root, 'one') },
        { ImportPath: 'ex/two', Dir: path.join(root, 'two') },
      ]
        .map((o) => JSON.stringify(o))
        .join('\n'),
    );
    vi.stubEnv('FAKE_DIR', fake);
    const out = path.join(work, 'gosec.sarif');
    const spec = path.join(work, 'spec.json');
    writeFileSync(
      spec,
      JSON.stringify({
        tool: 'gosec',
        toolPath: gs,
        go,
        version: '2.29.0',
        root,
        workDir: work,
        out,
        files: ['one/a.go', 'two/a.go'],
        modules: [{ dir: root, rel: '' }],
        gosecExclude: ['G104'],
      }),
    );
    const summary: string[] = [];
    expect(
      runner.main(['--spec', spec], { out: (s: string) => summary.push(s), err: () => {} }),
    ).toBe(0);
    // One run per package, each writing its own scratch file, never the spec's out.
    const scratch = path.join(work, 'gosec-package.sarif');
    expect(readFileSync(path.join(fake, 'gosec.args'), 'utf8')).toBe(
      `-- ./one ${scratch}\n-- ./two ${scratch}\n`,
    );
    const sarif = JSON.parse(readFileSync(out, 'utf8'));
    expect(
      sarif.runs[0].results.map(
        (r: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
          r.locations[0]!.physicalLocation.artifactLocation.uri,
      ),
    ).toEqual(['one/a.go', 'two/a.go']);
    expect(sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(['G401']);
    expect(JSON.parse(summary.join(''))).toMatchObject({ packages: 2, results: 2, outOfScope: 0 });
  });

  it('maps the real paths the tools print back to a root reached through a symbolic link', () => {
    const real = realpathSync(tmp());
    const root = path.join(tmp(), 'link');
    symlinkSync(real, root);
    const work = tmp();
    const fake = tmp();
    mkdirSync(path.join(real, 'store'));
    const { go, sc } = fakeTools(fake);
    // go list and staticcheck print real paths, as with a linked root (probe G3).
    writeFileSync(
      path.join(fake, 'list.json'),
      JSON.stringify({ ImportPath: 'ex/store', Dir: path.join(real, 'store') }),
    );
    writeFileSync(
      path.join(fake, 'staticcheck.json'),
      JSON.stringify({
        code: 'SA4000',
        location: { file: path.join(real, 'store', 'a.go'), line: 3, column: 1 },
        message: 'x',
      }),
    );
    vi.stubEnv('FAKE_DIR', fake);
    const spec = path.join(work, 'spec.json');
    writeFileSync(
      spec,
      JSON.stringify({
        tool: 'staticcheck',
        toolPath: sc,
        go,
        version: '2026.2.1',
        root,
        workDir: work,
        out: path.join(work, 'o.sarif'),
        files: ['store/a.go'],
        modules: [{ dir: root, rel: '' }],
        gosecExclude: [],
      }),
    );
    expect(runner.main(['--spec', spec], { out: () => {}, err: () => {} })).toBe(0);
    expect(readFileSync(path.join(fake, 'staticcheck.args'), 'utf8').trim()).toBe(
      '-f json -fail none -- ex/store',
    );
    const sarif = JSON.parse(readFileSync(path.join(work, 'o.sarif'), 'utf8'));
    expect(
      sarif.runs[0].results.map(
        (r: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
          r.locations[0]!.physicalLocation.artifactLocation.uri,
      ),
    ).toEqual(['store/a.go']);
  });

  it('analyses the loadable in-scope packages, drops out-of-scope results and duplicates, and warns once', () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    mkdirSync(path.join(root, 'store'));
    mkdirSync(path.join(root, 'gen'));
    mkdirSync(path.join(root, 'cmd'));
    const { go, sc } = fakeTools(fake);
    writeFileSync(
      path.join(fake, 'list.json'),
      [
        { ImportPath: 'ex/store', Dir: path.join(root, 'store') },
        { ImportPath: 'ex/gen', Dir: path.join(root, 'gen') },
        {
          ImportPath: 'ex/cmd',
          Dir: path.join(root, 'cmd'),
          DepsErrors: [{ Err: 'module lookup disabled by GOPROXY=off' }],
        },
      ]
        .map((o) => JSON.stringify(o, null, '\t'))
        .join('\n'),
    );
    const line = (file: string, code: string) =>
      JSON.stringify({
        code,
        location: { file: path.join(root, file), line: 3, column: 1 },
        message: code,
      });
    writeFileSync(
      path.join(fake, 'staticcheck.json'),
      [
        line('store/a.go', 'SA4000'),
        line('store/a.go', 'SA4000'),
        line('gen/g.go', 'S1002'),
        JSON.stringify({
          code: 'compile',
          location: { file: '' },
          message: './x.go:1:1: undefined: y',
        }),
      ].join('\n'),
    );
    vi.stubEnv('FAKE_DIR', fake);
    const spec = path.join(work, 'spec.json');
    writeFileSync(
      spec,
      JSON.stringify({
        tool: 'staticcheck',
        toolPath: sc,
        go,
        version: '2026.2.1',
        root,
        workDir: work,
        out: path.join(work, 'out.sarif'),
        files: ['store/a.go', 'cmd/main.go'],
        modules: [{ dir: root, rel: '' }],
        gosecExclude: [],
      }),
    );
    const out: string[] = [];
    const err: string[] = [];
    expect(
      runner.main(['--spec', spec], {
        out: (s: string) => out.push(s),
        err: (s: string) => err.push(s),
      }),
    ).toBe(0);
    // gen/ has no in-scope file: never passed; ex/cmd cannot load: not passed either.
    expect(readFileSync(path.join(fake, 'staticcheck.args'), 'utf8').trim()).toBe(
      '-f json -fail none -- ex/store',
    );
    const sarif = JSON.parse(readFileSync(path.join(work, 'out.sarif'), 'utf8'));
    expect(sarif.runs[0].tool.driver).toMatchObject({
      name: 'staticcheck',
      version: '2026.2.1',
      rules: [{ id: 'SA4000', helpUri: 'https://staticcheck.dev/docs/checks#SA4000' }],
    });
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(JSON.parse(out.join(''))).toEqual({
      tool: 'staticcheck',
      modules: 1,
      packages: 1,
      notLoaded: 1,
      results: 1,
      outOfScope: 1,
    });
    expect(err).toEqual([
      'go: warning: the root module: 1 package(s) not analysed, e.g. ex/cmd: module lookup disabled by GOPROXY=off; their dependencies are not on disk: run `go mod download` before `qualor scan`, vendor them, or set GOMODCACHE (config.md §6)\n',
      'go: warning: the root module: 1 package(s) could not be type-checked and were not analysed, e.g. ./x.go:1:1: undefined: y\n',
    ]);
  });

  function specFile(
    work: string,
    o: {
      tool: string;
      toolPath: string;
      go: string;
      root: string;
      files: string[];
      modules?: { dir: string; rel: string }[];
    },
  ) {
    const spec = path.join(work, 'spec.json');
    writeFileSync(
      spec,
      JSON.stringify({
        version: o.tool === 'govet' ? '1.27.1' : '2026.2.1',
        workDir: work,
        out: path.join(work, 'out.sarif'),
        modules: [{ dir: o.root, rel: '' }],
        gosecExclude: [],
        ...o,
      }),
    );
    return spec;
  }

  it("runs go and the tools with Qualor's Go settings over whatever it inherits (ruling G9-10)", () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    mkdirSync(path.join(root, 'store'));
    const { go, sc } = fakeTools(fake);
    writeFileSync(go, '#!/bin/sh\nenv > "$FAKE_DIR/go.env"\ncat "$FAKE_DIR/list.json"\n');
    writeFileSync(sc, '#!/bin/sh\nenv > "$FAKE_DIR/staticcheck.env"\n');
    writeFileSync(
      path.join(fake, 'list.json'),
      JSON.stringify({ ImportPath: 'ex/store', Dir: path.join(root, 'store') }),
    );
    vi.stubEnv('FAKE_DIR', fake);
    const hostile = {
      GOTOOLCHAIN: 'auto',
      GOPROXY: 'http://127.0.0.1:9',
      GOFLAGS: `-toolexec=${fake}/x`,
      CGO_ENABLED: '1',
      GOPACKAGESDRIVER: `${fake}/driver`,
      GOWORK: `${fake}/go.work`,
      GOENV: `${fake}/env`,
    };
    for (const [k, v] of Object.entries(hostile)) vi.stubEnv(k, v);
    const spec = specFile(work, {
      tool: 'staticcheck',
      toolPath: sc,
      go,
      root,
      files: ['store/a.go'],
    });
    expect(runner.main(['--spec', spec], { out: () => {}, err: () => {} })).toBe(0);
    for (const file of ['go.env', 'staticcheck.env']) {
      const env = Object.fromEntries(
        readFileSync(path.join(fake, file), 'utf8')
          .split('\n')
          .filter((l) => l.includes('='))
          .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
      );
      expect(env, file).toMatchObject({
        GOTOOLCHAIN: 'local',
        GOPROXY: 'off',
        GOFLAGS: '',
        CGO_ENABLED: '0',
        GOPACKAGESDRIVER: 'off',
        GOWORK: 'off',
        GOENV: 'off',
        FAKE_DIR: fake,
      });
    }
  });

  it('turns a tool that floods its stderr into a warning for that module, not a fatal error', () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    const { go, sc } = fakeTools(fake);
    // More stderr than the runner buffers: spawnSync stops the child with ENOBUFS.
    writeFileSync(go, '#!/bin/sh\nhead -c 20000000 /dev/zero | tr "\0" x >&2\n');
    const modules = ['a', 'b'].map((rel) => {
      mkdirSync(path.join(root, rel));
      return { dir: path.join(root, rel), rel };
    });
    const spec = specFile(work, {
      tool: 'staticcheck',
      toolPath: sc,
      go,
      root,
      files: [],
      modules,
    });
    const err: string[] = [];
    expect(runner.main(['--spec', spec], { out: () => {}, err: (s: string) => err.push(s) })).toBe(
      0,
    );
    expect(err).toEqual([
      'go: warning: a: go wrote more than 16 MiB to stderr and was stopped; the module was not analysed\n',
      'go: warning: b: go wrote more than 16 MiB to stderr and was stopped; the module was not analysed\n',
    ]);
    expect(JSON.parse(readFileSync(path.join(work, 'out.sarif'), 'utf8')).runs[0].results).toEqual(
      [],
    );
  });

  it('keeps the JSON findings of a go vet that exits non-zero, and names why (end to end through main)', () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    for (const d of ['good', 'bad']) mkdirSync(path.join(root, d));
    const { go } = fakeTools(fake);
    writeFileSync(
      path.join(fake, 'list.json'),
      [
        { ImportPath: 'ex/m/bad', Dir: path.join(root, 'bad') },
        { ImportPath: 'ex/m/good', Dir: path.join(root, 'good') },
      ]
        .map((o) => JSON.stringify(o, null, '\t'))
        .join('\n'),
    );
    // What go 1.27.1 prints for a package that does not type-check next to one with a finding
    // (toolbox probe, task 10 report): the JSON on stdout, the compile error on stderr, exit 1.
    writeFileSync(
      go,
      [
        '#!/bin/sh',
        'case "$1" in',
        '  list) echo "$@" > "$FAKE_DIR/list.args"; cat "$FAKE_DIR/list.json" ;;',
        '  vet) echo "$@" > "$FAKE_DIR/vet.args"; cat "$FAKE_DIR/vet.json"; printf "# ex/m/bad\nvet: bad/b.go:3:23: undefined: undefinedThing\n" >&2; exit 1 ;;',
        'esac',
        '',
      ].join('\n'),
    );
    writeFileSync(
      path.join(fake, 'vet.json'),
      JSON.stringify(
        {
          'ex/m/good': {
            printf: [
              {
                posn: `${path.join(root, 'good', 'a.go')}:5:39`,
                end: `${path.join(root, 'good', 'a.go')}:5:41`,
                message: 'fmt.Sprintf format %d has arg "s" of wrong type string',
              },
            ],
          },
        },
        null,
        '\t',
      ),
    );
    vi.stubEnv('FAKE_DIR', fake);
    const spec = specFile(work, {
      tool: 'govet',
      toolPath: go,
      go,
      root,
      files: ['good/a.go', 'bad/b.go'],
    });
    const out: string[] = [];
    const err: string[] = [];
    expect(
      runner.main(['--spec', spec], {
        out: (s: string) => out.push(s),
        err: (s: string) => err.push(s),
      }),
    ).toBe(0);
    expect(readFileSync(path.join(fake, 'vet.args'), 'utf8').trim()).toBe(
      'vet -json -- ex/m/bad ex/m/good',
    );
    expect(readFileSync(path.join(fake, 'list.args'), 'utf8').trim()).toBe(
      'list -e -json=ImportPath,Dir,Error,DepsErrors -- ./...',
    );
    expect(err).toEqual([
      'go: warning: the root module: go vet exited 1: vet: bad/b.go:3:23: undefined: undefinedThing\n',
    ]);
    const sarif = JSON.parse(readFileSync(path.join(work, 'out.sarif'), 'utf8'));
    expect(sarif.runs[0].tool.driver).toMatchObject({
      name: 'govet',
      version: '1.27.1',
      rules: [
        {
          id: 'printf',
          helpUri: 'https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/printf',
        },
      ],
    });
    expect(sarif.runs[0].results).toEqual([
      {
        ruleId: 'printf',
        level: 'warning',
        message: { text: 'fmt.Sprintf format %d has arg "s" of wrong type string' },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'good/a.go' },
              region: { startLine: 5, startColumn: 39, endLine: 5, endColumn: 41 },
            },
          },
        ],
      },
    ]);
    expect(JSON.parse(out.join(''))).toMatchObject({ tool: 'govet', packages: 2, results: 1 });
  });

  it('keeps at most MAX_WARNINGS warnings and says how many more there were', () => {
    const root = tmp();
    const work = tmp();
    const fake = tmp();
    const { go, sc } = fakeTools(fake);
    writeFileSync(path.join(fake, 'list.json'), '');
    writeFileSync(path.join(fake, 'staticcheck.json'), '');
    vi.stubEnv('FAKE_DIR', fake);
    const modules = Array.from({ length: runner.MAX_WARNINGS + 3 }, (_, i) => {
      const dir = path.join(root, `m${i}`);
      mkdirSync(dir);
      return { dir, rel: `m${i}` };
    });
    const spec = path.join(work, 'spec.json');
    // A go that exits 1 for go list: every module gives one warning.
    writeFileSync(go, '#!/bin/sh\necho "go: broken" >&2\nexit 1\n');
    writeFileSync(
      spec,
      JSON.stringify({
        tool: 'staticcheck',
        toolPath: sc,
        go,
        version: '2026.2.1',
        root,
        workDir: work,
        out: path.join(work, 'o.sarif'),
        files: [],
        modules,
        gosecExclude: [],
      }),
    );
    const err: string[] = [];
    expect(runner.main(['--spec', spec], { out: () => {}, err: (s: string) => err.push(s) })).toBe(
      0,
    );
    expect(err).toHaveLength(runner.MAX_WARNINGS + 1);
    expect(err.at(-1)).toBe('go: warning: 3 more warning(s) left out\n');
  });
});
