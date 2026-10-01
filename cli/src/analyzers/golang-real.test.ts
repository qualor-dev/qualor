import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import {
  GO_VERSION,
  GOSEC_VERSION,
  parseConfig,
  STATICCHECK_VERSION,
  type QualorConfigInput,
} from '@qualor/shared';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { describeWithGo } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { createLogger } from '../log';
import { Warnings } from '../warnings';
import { gosecAnalyzer, govetAnalyzer, staticcheckAnalyzer } from './golang';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();
/** False once the process is gone or a zombie nobody reaped yet (a container's sh as PID 1). */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3) !== 'Z';
  } catch {
    return false;
  }
}

async function gone(pid: number): Promise<boolean> {
  for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
  return !alive(pid);
}

const ALL = [staticcheckAnalyzer, govetAnalyzer, gosecAnalyzer];

type Result = {
  ruleId: string;
  locations: {
    physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } };
  }[];
};
const results = (sarif: unknown) =>
  (sarif as { runs: { results: Result[] }[] }).runs[0]?.results ?? [];
const where = (r: Result) =>
  `${decodeURIComponent(r.locations[0]!.physicalLocation.artifactLocation.uri)}:${r.locations[0]!.physicalLocation.region.startLine} ${r.ruleId}`;

async function scan(
  root: string,
  env: NodeJS.ProcessEnv = process.env,
  config: Omit<QualorConfigInput, 'version'> = {},
  analyzers = ALL,
) {
  const parsed = parseConfig({ version: 1, ...config });
  const lines: string[] = [];
  const files = discoverFiles({
    root,
    config: parsed,
    warnings: new Warnings(),
    log: createLogger('error', () => {}),
  });
  const captures = await runAnalyzers(analyzers, {
    root,
    config: parsed,
    files,
    log: createLogger('debug', (t) => lines.push(t)),
    env,
  });
  const by = (id: string) => captures.find((c) => c.engineId === id)!;
  return { by, log: lines.join('') };
}

// Type-checking the standard library with an empty GOCACHE takes a while per engine.
describeWithGo()('the Go engines with the real tools (plan 9C)', { timeout: 300_000 }, () => {
  let requests = 0;
  const server = createServer((_req, res) => {
    requests += 1;
    res.statusCode = 404;
    res.end();
  });
  let port = 0;
  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  // `auto` with the go.mod's toolchain line, and a CI that names a toolchain itself (ruling G9-15:
  // the version probes too run with GOTOOLCHAIN=local).
  it.each(['auto', 'go1.99.1'])(
    'never runs, fetches or switches what a checkout or a CI variable asks for (GOTOOLCHAIN=%s)',
    async (toolchain) => {
      const root = tmp();
      const outside = tmp();
      const marker = path.join(outside, 'exec.sh');
      writeFileSync(marker, `#!/bin/sh\ntouch ${outside}/exec-marker\nexec "$@"\n`);
      chmodSync(marker, 0o755);
      writeTree(outside, {
        'mod/go.mod': 'module ex/outside\n\ngo 1.24\n',
        'mod/bad.go': 'package outside\n\nfunc F(x int) bool { return x == x }\n',
      });
      writeTree(root, {
        'go.mod': 'module ex/hostile\n\ngo 1.24\n\ntoolchain go1.99.1\n',
        'go.work': `go 1.24\n\nuse (\n\t.\n\t${outside}/mod\n)\n`,
        '.golangci.yml': `linters-settings:\n  custom:\n    evil:\n      path: ${outside}/plugin.so\n`,
        'main.go': [
          'package main',
          '',
          `//go:generate sh -c "touch ${outside}/generate-marker"`,
          '',
          'import "fmt"',
          '',
          'func main() {',
          '\tx := 1',
          '\tif x == x {',
          '\t\tfmt.Printf("%d\\n", "s")',
          '\t}',
          '}',
          '',
        ].join('\n'),
        'cgo.go': `package main\n\n// #cgo LDFLAGS: -Wl,--version-script=${outside}/cgo-marker\n// int f() { return 1; }\nimport "C"\n\nfunc viaC() int { return int(C.f()) }\n`,
      });
      // An existing but empty GOROOT: the version probes (ctx.exec, which keeps the CI's environment)
      // still print a version, while a GOROOT that leaked into the runner's environment would make
      // package loading fail and the engines not `ok`. A missing directory would fail the probe itself
      // (`go version` exits 2: "cannot find GOROOT directory", pre-flight scan).
      const emptyGoroot = path.join(outside, 'empty-goroot');
      mkdirSync(emptyGoroot);
      const { by } = await scan(root, {
        ...process.env,
        GOTOOLCHAIN: toolchain,
        GOPROXY: `http://127.0.0.1:${port}`,
        GOFLAGS: `-toolexec=${marker}`,
        GOPACKAGESDRIVER: marker,
        GOSEC_AI_API_KEY: 'not-a-key',
        GOROOT: emptyGoroot,
      });
      for (const id of ['staticcheck', 'govet', 'gosec'])
        expect(by(id).status, `${id}: ${by(id).reason ?? ''}`).toBe('ok');
      expect(results(by('staticcheck').sarif).map(where).sort()).toEqual([
        'main.go:10 SA5009',
        'main.go:9 SA4000',
      ]);
      expect(results(by('govet').sarif).map(where)).toEqual(['main.go:10 printf']);
      expect(requests).toBe(0);
      expect([by('staticcheck').version, by('govet').version, by('gosec').version]).toEqual([
        STATICCHECK_VERSION,
        GO_VERSION,
        GOSEC_VERSION,
      ]);
      for (const m of ['exec-marker', 'generate-marker', 'cgo-marker'])
        expect(existsSync(path.join(outside, m)), m).toBe(false);
    },
  );

  it('leaves out a module that replaces a dependency with an outside directory or links out, and analyses the others', async () => {
    const root = tmp();
    const outside = tmp();
    writeFileSync(
      path.join(outside, 'secret.go'),
      'package c\n\nfunc S(x int) bool { return x == x }\n',
    );
    writeTree(root, {
      'a/go.mod': `module ex/a\n\ngo 1.24\n\nrequire ex/dep v0.0.0\n\nreplace ex/dep => ${outside}\n`,
      'a/a.go': 'package a\n\nfunc A(x int) bool { return x == x }\n',
      'b/go.mod': 'module ex/b\n\ngo 1.24\n',
      'b/b.go': 'package b\n\nfunc B(x int) bool { return x == x }\n',
      'c/go.mod': 'module ex/c\n\ngo 1.24\n',
      'c/c.go': 'package c\n',
    });
    symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'c', 'link.go'));
    const { by, log } = await scan(root);
    expect(by('staticcheck').status).toBe('ok');
    expect(results(by('staticcheck').sarif).map(where)).toEqual(['b/b.go:3 SA4000']);
    expect(log).toContain('a is not analysed: a/go.mod replaces ex/dep with');
    expect(log).toContain('c is not analysed: c/link.go is a symbolic link out of the repository');
  });

  it('analyses what loads without the module cache, names what does not, and reads vendor/', async () => {
    const root = tmp();
    const sum =
      'github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\ngithub.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n';
    writeTree(root, {
      'needs/go.mod': 'module ex/needs\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n',
      'needs/go.sum': sum,
      'needs/e/e.go': 'package e\n\nimport "github.com/pkg/errors"\n\nvar E = errors.New("x")\n',
      'needs/plain/p.go': 'package plain\n\nfunc P(x int) bool { return x == x }\n',
      'vendored/go.mod': 'module ex/vendored\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n',
      'vendored/go.sum': sum,
      'vendored/vendor/modules.txt':
        '# github.com/pkg/errors v0.9.1\n## explicit\ngithub.com/pkg/errors\n',
      'vendored/vendor/github.com/pkg/errors/errors.go':
        'package errors\n\nfunc New(s string) error { return nil }\n',
      'vendored/v/v.go':
        'package v\n\nimport "github.com/pkg/errors"\n\nfunc V(x int) error {\n\tif x == x {\n\t\treturn errors.New("x")\n\t}\n\treturn nil\n}\n',
    });
    const { by, log } = await scan(root, { ...process.env, GOMODCACHE: path.join(tmp(), 'empty') });
    expect(by('staticcheck').status).toBe('ok');
    expect(results(by('staticcheck').sarif).map(where).sort()).toEqual([
      'needs/plain/p.go:3 SA4000',
      'vendored/v/v.go:6 SA4000',
    ]);
    expect(log).toContain('needs: 1 package(s) not analysed, e.g. ex/needs/e');
    expect(log).toContain('run `go mod download` before `qualor scan`');
    expect(by('govet').status).toBe('ok');
  });

  it("follows the project's staticcheck.conf, and analyses awkward file names at their repository paths", async () => {
    const root = tmp();
    writeTree(root, {
      'go.mod': 'module ex/names\n\ngo 1.24\n',
      'staticcheck.conf': 'checks = ["all", "-SA4000"]\n',
      'pkg/a b#%.go':
        'package pkg\n\nimport (\n\t"crypto/md5"\n\t"fmt"\n)\n\nfunc A() string { return fmt.Sprintf("%d", "s") + string(md5.New().Sum(nil)) }\n',
      'pkg/ü.go':
        'package pkg\n\nfunc U(b bool) bool {\n\tif b == true {\n\t\treturn true\n\t}\n\treturn false\n}\n',
    });
    const { by } = await scan(root);
    const sc = results(by('staticcheck').sarif).map(where);
    expect(sc.some((w) => w.endsWith('SA4000'))).toBe(false);
    expect(sc).toContain('pkg/ü.go:4 S1002');
    expect(results(by('govet').sarif).map(where)).toContain('pkg/a b#%.go:8 printf');
    expect(results(by('gosec').sarif).map(where)).toContain('pkg/a b#%.go:4 G501');
  });

  it('reports exactly the findings of G4 on fixtures/go-basic (and can record them)', async () => {
    const root = path.resolve('fixtures/go-basic');
    const { by } = await scan(root);
    const got = (id: string) => results(by(id).sarif).map(where).sort();
    expect(got('staticcheck')).toEqual([
      'store/store.go:45 SA5009',
      'store/store.go:50 SA4000',
      'tools/next.go:5 S1002',
      'tools/next.go:5 S1008',
    ]);
    expect(got('govet')).toEqual([
      'store/store.go:39 copylocks',
      'store/store.go:40 copylocks',
      'store/store.go:45 printf',
      'store/store.go:50 bools',
    ]);
    expect(got('gosec')).toEqual(['store/store.go:4 G501', 'store/store.go:60 G401']);
    // Task 10 Step 6 records cli/test/analyzer-output/<engine>/basic.sarif through this hook.
    const record = process.env['QUALOR_RECORD_GO_SARIF'];
    if (record) {
      for (const id of ['staticcheck', 'govet', 'gosec']) {
        mkdirSync(path.join(record, id), { recursive: true });
        writeFileSync(
          path.join(record, id, 'basic.sarif'),
          `${JSON.stringify(by(id).sarif, null, 2)}\n`,
        );
      }
    }
  });
  it('hands the runner and its tools only the allowlisted environment, and a timeout kills them all (ruling G9-10)', async () => {
    const root = tmp();
    const marks = tmp();
    const bin = tmp();
    writeTree(root, { 'go.mod': 'module ex/slow\n\ngo 1.24\n', 'a.go': 'package slow\n' });
    // A staticcheck first on PATH: its version, then, run by the runner, its environment, its pid
    // and its parent's (the node runner), and a sleep far longer than the timeout.
    const fake = path.join(bin, 'staticcheck');
    writeFileSync(
      fake,
      [
        '#!/bin/sh',
        `if [ "$1" = "-version" ]; then echo "staticcheck ${STATICCHECK_VERSION} (0.8.1)"; exit 0; fi`,
        `env > ${marks}/env`,
        `echo $PPID > ${marks}/ppid`,
        `echo $$ > ${marks}/pid`,
        'exec sleep 300',
        '',
      ].join('\n'),
    );
    chmodSync(fake, 0o755);
    const emptyGoroot = path.join(marks, 'empty-goroot');
    mkdirSync(emptyGoroot);
    const { by } = await scan(
      root,
      {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env['PATH'] ?? ''}`,
        CI_JOB_TOKEN: 'ci-token',
        GITHUB_TOKEN: 'gh-token',
        GOSEC_AI_API_KEY: 'not-a-key',
        GOROOT: emptyGoroot,
        GOPRIVATE: 'ex.com/*',
        GOINSECURE: 'ex.com',
        GOEXPERIMENT: 'arenas',
        GOTOOLCHAIN: 'auto',
        GOFLAGS: '-toolexec=/bin/true',
        GOPROXY: 'http://127.0.0.1:9',
        CGO_ENABLED: '1',
        GOPACKAGESDRIVER: '/bin/true',
        GOWORK: '/tmp/go.work',
        CC: '/bin/true',
      },
      { analyzers: { staticcheck: { timeoutSeconds: 10 } } },
      [staticcheckAnalyzer],
    );
    expect(by('staticcheck')).toMatchObject({ status: 'timeout', reason: 'timed out after 10 s' });
    const pid = Number(readFileSync(path.join(marks, 'pid'), 'utf8'));
    const ppid = Number(readFileSync(path.join(marks, 'ppid'), 'utf8'));
    expect(await gone(pid), 'the tool').toBe(true);
    expect(await gone(ppid), 'the node runner').toBe(true);
    const env = new Map(
      readFileSync(path.join(marks, 'env'), 'utf8')
        .split('\n')
        .filter((l) => l.includes('='))
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)] as const),
    );
    for (const name of [
      'CI_JOB_TOKEN',
      'GITHUB_TOKEN',
      'GOSEC_AI_API_KEY',
      'GOROOT',
      'GOPRIVATE',
      'GOINSECURE',
      'GOEXPERIMENT',
      'CC',
    ]) {
      expect(env.has(name), name).toBe(false);
    }
    expect(Object.fromEntries(env)).toMatchObject({
      GOTOOLCHAIN: 'local',
      GOFLAGS: '',
      GOPROXY: 'off',
      CGO_ENABLED: '0',
      GOPACKAGESDRIVER: 'off',
      GOWORK: 'off',
      GOENV: 'off',
      GOVCS: '*:off',
      HTTPS_PROXY: 'http://127.0.0.1:9',
      LC_ALL: 'C.UTF-8',
    });
    expect(env.get('PATH')?.split(path.delimiter)).toContain(bin);
  });

  it('keeps the findings of a go vet that exits non-zero on a package that does not type-check, and says why', async () => {
    const root = tmp();
    writeTree(root, {
      'go.mod': 'module ex/m\n\ngo 1.24\n',
      'good/a.go':
        'package good\n\nimport "fmt"\n\nfunc F() string { return fmt.Sprintf("%d", "s") }\n',
      'bad/b.go': 'package bad\n\nfunc B() int { return undefinedThing }\n',
    });
    const { by, log } = await scan(root, process.env, {}, [govetAnalyzer]);
    expect(by('govet').status, by('govet').reason ?? '').toBe('ok');
    expect(results(by('govet').sarif).map(where)).toEqual(['good/a.go:5 printf']);
    expect(log).toContain(
      'govet: the root module: go vet exited 1: vet: bad/b.go:3:23: undefined: undefinedThing',
    );
  });
});
