// Qualor's Go runner (plan 9C, config.md §6). The CLI runs it with node, in the environment it
// built (GOTOOLCHAIN=local, GOPROXY=off, GOFLAGS=, GOWORK=off, CGO_ENABLED=0, …), on the Go
// modules it planned; it sets those Go settings again for every command it starts
// (GO_SETTINGS). Per module it asks `go list` which packages load offline, runs one tool
// (staticcheck, go vet or gosec) on the loadable packages that hold in-scope files, and writes one
// SARIF 2.1.0 log with repository-relative locations. No dependencies; MIT.
//   node run.mjs --spec <spec.json>
// stdout: one JSON summary line. stderr: `go: warning: …` lines (bounded); on exit 2 one
// `go: fatal: …` line.
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const TOOLS = ['staticcheck', 'govet', 'gosec'];
/** Warnings printed before one "N more" line; the CLI's GO_RUNNER_MAX_WARNINGS (golang.ts) must equal it. */
export const MAX_WARNINGS = 20;
/** A gosec rule id: the same pattern as GOSEC_RULE_ID of @qualor/shared (run.test.ts checks). */
export const GOSEC_ID = /^G\d{3}$/;
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
/** A tool's stderr kept in memory; more stops it (ENOBUFS) and leaves its module out. */
const MAX_STDERR_BYTES = 16 * 1024 * 1024;
/**
 * Ruling G9-10, defence in depth: the CLI already builds this environment (goEnv, config.md §6),
 * and the runner sets it again over whatever it inherited before it starts go, staticcheck or
 * gosec, so no inherited setting can switch toolchains, fetch modules, load a go.work, a package
 * driver or an env file, add -toolexec, or run a C compiler.
 */
export const GO_SETTINGS = Object.freeze({
  GOTOOLCHAIN: 'local',
  GOPROXY: 'off',
  GOFLAGS: '',
  CGO_ENABLED: '0',
  GOPACKAGESDRIVER: 'off',
  GOWORK: 'off',
  GOENV: 'off',
});
const MAX_DETAIL = 300;
const INFO = {
  staticcheck: 'https://staticcheck.dev',
  govet: 'https://pkg.go.dev/cmd/vet',
  gosec: 'https://github.com/securego/gosec',
};
// go vet analyzers whose package has another name: pkg.go.dev answers 404 for the analyzer's.
const VET_PACKAGE = { composites: 'composite', copylocks: 'copylock' };
export const HELP = {
  staticcheck: (id) => `https://staticcheck.dev/docs/checks#${id}`,
  govet: (id) =>
    `https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/${Object.hasOwn(VET_PACKAGE, id) ? VET_PACKAGE[id] : id}`,
};
// go list's and the type checker's ways of saying a dependency is not on disk (probe G3).
const MISSING_DEPENDENCY =
  /module lookup disabled|cannot find module|missing go\.sum entry|no required module provides|not in the module cache|invalid package name/;
// A package with only _test.go files: staticcheck and go vet analyse its tests.
const TEST_ONLY = /no non-test Go files/;
const POSN = /^(.*):(\d+):(\d+)$/;

// eslint-disable-next-line no-control-regex -- control characters are exactly what is removed
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

/** A line Qualor wrote, made safe for the log: control characters become spaces, bounded. */
function bounded(line) {
  return String(line)
    .replace(CONTROL, ' ')
    .slice(0, 2 * MAX_DETAIL);
}

/** One line of tool text: the first that is not blank and not a `# package` header, bounded. */
export function detail(text) {
  const line =
    String(text ?? '')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l !== '' && !l.startsWith('#')) ?? '';
  return line.replace(CONTROL, ' ').slice(0, MAX_DETAIL);
}

function fatal(message) {
  const err = new Error(message);
  err.fatal = true;
  return err;
}

/** The top-level JSON objects of a stream such as `go list -json` and `go vet -json` print. */
export function splitJsonObjects(text) {
  const s = { out: [], depth: 0, start: -1, inString: false, escaped: false };
  for (let i = 0; i < text.length; i++) {
    if (s.inString) stringChar(s, text[i]);
    else structureChar(s, text, i);
  }
  if (s.depth !== 0 || s.inString) throw new Error('truncated JSON output');
  return s.out;
}

/** One character inside a JSON string (splitJsonObjects). */
function stringChar(s, c) {
  if (s.escaped) s.escaped = false;
  else if (c === '\\') s.escaped = true;
  else if (c === '"') s.inString = false;
}

/** One character outside JSON strings: a string's start, or a brace (splitJsonObjects). */
function structureChar(s, text, i) {
  const c = text[i];
  if (c === '"') {
    s.inString = true;
  } else if (c === '{') {
    if (s.depth === 0) s.start = i;
    s.depth += 1;
  } else if (c === '}') {
    s.depth -= 1;
    if (s.depth < 0) throw new Error('unbalanced JSON output');
    if (s.depth === 0) s.out.push(JSON.parse(text.slice(s.start, i + 1)));
  }
}

export function realOr(p) {
  try {
    return realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/**
 * go list's packages → the ones to analyse (in scope, no error) as import paths and `./dir`
 * arguments, and the in-scope ones that cannot load. `scopeDirs` holds the real paths of the
 * directories of the scan's in-scope Go files.
 */
export function plannedPackages(listed, moduleDir, scopeDirs) {
  const packages = [];
  const failed = [];
  const realModule = realOr(moduleDir);
  for (const p of listed) {
    if (typeof p?.ImportPath !== 'string' || typeof p?.Dir !== 'string') continue;
    const dir = realOr(p.Dir);
    if (!scopeDirs.has(dir)) continue;
    const errors = [
      p.Error?.Err,
      ...(Array.isArray(p.DepsErrors) ? p.DepsErrors.map((e) => e?.Err) : []),
    ].filter((e) => typeof e === 'string' && !TEST_ONLY.test(e));
    if (errors.length > 0) {
      failed.push({ importPath: p.ImportPath, error: errors[0] });
      continue;
    }
    const rel = path.relative(realModule, dir).split(path.sep).join('/');
    packages.push({ importPath: p.ImportPath, dir: rel === '' ? '.' : `./${rel}` });
  }
  return { packages, failed };
}

/** A repository path as a relative URI, each segment percent-encoded (the normaliser decodes it). */
export function encodeUri(rel) {
  return rel.split('/').map(encodeURIComponent).join('/');
}

const positive = (n) => Number.isInteger(n) && n > 0;

/**
 * A result: `rule` is { ruleId, level, text }, `at` is { startLine, startColumn, endLine,
 * endColumn } (only startLine required; the others are kept when they are valid).
 */
function finding(rule, rel, at) {
  const { ruleId, level, text } = rule;
  const region = { startLine: at.startLine };
  if (positive(at.startColumn)) region.startColumn = at.startColumn;
  if (positive(at.endLine) && at.endLine >= at.startLine) {
    region.endLine = at.endLine;
    if (positive(at.endColumn)) region.endColumn = at.endColumn;
  }
  return {
    rel,
    sarif: {
      ruleId,
      level,
      message: { text },
      locations: [{ physicalLocation: { artifactLocation: { uri: encodeUri(rel) }, region } }],
    },
  };
}

/** `staticcheck -f json` lines → results, and the `compile` problems of packages it could not check. */
export function staticcheckResults(text, toRepo) {
  const results = [];
  const problems = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    const d = JSON.parse(line);
    if (d.code === 'compile') {
      problems.push(detail(d.message));
      continue;
    }
    const rel = toRepo(d.location?.file);
    if (typeof d.code !== 'string' || rel === null || !positive(d.location?.line)) continue;
    const sameFile = d.end?.file === d.location.file;
    results.push(
      finding({ ruleId: d.code, level: 'warning', text: String(d.message ?? '') }, rel, {
        startLine: d.location.line,
        startColumn: d.location.column,
        endLine: sameFile ? d.end.line : undefined,
        endColumn: sameFile ? d.end.column : undefined,
      }),
    );
  }
  return { results, problems };
}

/** `go vet -json` objects (`{pkg: {analyzer: [{posn, end, message}] | {error}}}`) → results. */
export function vetResults(objects, toRepo) {
  const out = { results: [], problems: [] };
  for (const obj of objects) {
    for (const analyzers of Object.values(obj ?? {})) {
      for (const [name, entries] of Object.entries(analyzers ?? {})) {
        vetAnalyzer(out, { name, entries }, toRepo);
      }
    }
  }
  return out;
}

/** One analyzer's go vet entries (or its error) into `out` (vetResults). */
function vetAnalyzer(out, { name, entries }, toRepo) {
  if (!Array.isArray(entries)) {
    if (typeof entries?.error === 'string') out.problems.push(detail(entries.error));
    return;
  }
  for (const e of entries) {
    const r = vetFinding(name, e, toRepo);
    if (r !== null) out.results.push(r);
  }
}

/** One go vet entry as a result, or null when it is not on a repository file. */
function vetFinding(name, e, toRepo) {
  const m = POSN.exec(String(e?.posn ?? ''));
  const rel = m === null ? null : toRepo(m[1]);
  if (m === null || rel === null) return null;
  const end = POSN.exec(String(e?.end ?? ''));
  const sameFile = end !== null && end[1] === m[1];
  return finding({ ruleId: name, level: 'warning', text: String(e.message ?? '') }, rel, {
    startLine: Number(m[2]),
    startColumn: Number(m[3]),
    endLine: sameFile ? Number(end[2]) : undefined,
    endColumn: sameFile ? Number(end[3]) : undefined,
  });
}

/**
 * The file a gosec URI names: relative to the package directory gosec was given (gosec 2.29.0 with
 * an explicit package argument, pre-flight scan), raw or percent-encoded; a `file://` URI or an
 * absolute path as it is.
 */
function gosecFile(uri, packageDir) {
  if (uri.startsWith('file://')) return fileURLToPath(uri);
  if (path.isAbsolute(uri)) return uri;
  const raw = path.resolve(packageDir, uri);
  if (existsSync(raw)) return raw;
  try {
    const decoded = path.resolve(packageDir, decodeURIComponent(uri));
    return existsSync(decoded) ? decoded : raw;
  } catch {
    return raw;
  }
}

/** One package's gosec SARIF (URIs relative to `packageDir`) → results at repository paths, and its rules. */
export function gosecResults(log, packageDir, toRepo) {
  const run = log?.runs?.[0];
  const rules = Array.isArray(run?.tool?.driver?.rules)
    ? run.tool.driver.rules.filter((r) => typeof r?.id === 'string')
    : [];
  const results = [];
  for (const r of Array.isArray(run?.results) ? run.results : []) {
    const loc = r?.locations?.[0]?.physicalLocation;
    const uri = loc?.artifactLocation?.uri;
    if (
      typeof r?.ruleId !== 'string' ||
      typeof uri !== 'string' ||
      !positive(loc?.region?.startLine)
    )
      continue;
    const rel = toRepo(gosecFile(uri, packageDir));
    if (rel === null) continue;
    const level = typeof r.level === 'string' ? r.level : 'warning';
    results.push(
      finding({ ruleId: r.ruleId, level, text: String(r.message?.text ?? '') }, rel, loc.region),
    );
  }
  return { results, rules };
}

export function toSarif(tool, version, rules, results) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      { tool: { driver: { name: tool, version, informationUri: INFO[tool], rules } }, results },
    ],
  };
}

export function readSpec(file) {
  const spec = JSON.parse(readFileSync(file, 'utf8'));
  const absolute = (p) => typeof p === 'string' && path.isAbsolute(p);
  if (!TOOLS.includes(spec?.tool)) throw new Error('spec: unknown tool');
  for (const key of ['toolPath', 'go', 'root', 'workDir', 'out']) {
    if (!absolute(spec[key])) throw new Error(`spec: ${key} must be an absolute path`);
  }
  if (typeof spec.version !== 'string') throw new Error('spec: version must be a string');
  if (!Array.isArray(spec.files) || !spec.files.every((f) => typeof f === 'string')) {
    throw new Error('spec: files must be a list of repository paths');
  }
  if (
    !Array.isArray(spec.modules) ||
    !spec.modules.every((m) => absolute(m?.dir) && typeof m?.rel === 'string')
  ) {
    throw new Error('spec: modules must be a list of { dir, rel }');
  }
  if (!Array.isArray(spec.gosecExclude) || !spec.gosecExclude.every((g) => GOSEC_ID.test(g))) {
    throw new Error('spec: gosecExclude must be a list of gosec rule ids');
  }
  return spec;
}

/**
 * Runs a command with its stdout in `file` (never in memory), its stderr captured, and
 * GO_SETTINGS over the inherited environment.
 */
function capture(file, command, args, cwd) {
  const fd = openSync(file, 'w');
  try {
    const r = spawnSync(command, args, {
      cwd,
      env: { ...process.env, ...GO_SETTINGS },
      stdio: ['ignore', fd, 'pipe'],
      encoding: 'utf8',
      maxBuffer: MAX_STDERR_BYTES,
      windowsHide: true,
    });
    return { status: r.status, error: r.error, stderr: r.stderr ?? '' };
  } finally {
    closeSync(fd);
  }
}

/**
 * A command that could not run is fatal (`go: fatal: …`); one that flooded its stderr was stopped
 * (ENOBUFS) and only its module is left out (ruling G9-10).
 */
function runError(name, error) {
  if (error?.code === 'ENOBUFS') {
    return new Error(
      `${name} wrote more than ${MAX_STDERR_BYTES / (1024 * 1024)} MiB to stderr and was stopped; the module was not analysed`,
    );
  }
  return fatal(`cannot run ${name}: ${error.message}`);
}

function readBounded(file) {
  if (statSync(file).size > MAX_OUTPUT_BYTES) throw new Error('tool output larger than 256 MiB');
  return readFileSync(file, 'utf8');
}

function toolRun(spec, m, packages, toRepo, say, label) {
  const outFile = path.join(spec.workDir, 'go-tool-output');
  const importPaths = packages.map((p) => p.importPath);
  if (spec.tool === 'staticcheck') {
    const r = capture(
      outFile,
      spec.toolPath,
      ['-f', 'json', '-fail', 'none', '--', ...importPaths],
      m.dir,
    );
    if (r.error) throw runError('staticcheck', r.error);
    const text = readBounded(outFile);
    if (r.status !== 0 && text.trim() === '') {
      say(`${label}: staticcheck stopped (exit ${r.status}): ${detail(r.stderr)}`);
      return { results: [], problems: [] };
    }
    return staticcheckResults(text, toRepo);
  }
  if (spec.tool === 'govet') {
    const r = capture(outFile, spec.go, ['vet', '-json', '--', ...importPaths], m.dir);
    if (r.error) throw runError('go', r.error);
    if (r.status !== 0) say(`${label}: go vet exited ${r.status}: ${detail(r.stderr)}`);
    return vetResults(splitJsonObjects(readBounded(outFile)), toRepo);
  }
  return gosecRun({ spec, m, outFile }, packages, { toRepo, say, label });
}

/**
 * gosec writes each URI relative to the package directory it was given, so two packages' `a.go`
 * would be indistinguishable in one run (pre-flight scan): one run per package, each URI resolved
 * against that package's directory. The scratch file is never the spec's `out`.
 */
function gosecRun({ spec, m, outFile }, packages, { toRepo, say, label }) {
  const sarifFile = path.join(spec.workDir, 'gosec-package.sarif');
  const results = [];
  const rules = [];
  for (const p of packages) {
    rmSync(sarifFile, { force: true });
    const args = [
      '-fmt=sarif',
      `-out=${sarifFile}`,
      '-no-fail',
      '-quiet',
      '-exclude-generated',
      ...(spec.gosecExclude.length > 0 ? [`-exclude=${spec.gosecExclude.join(',')}`] : []),
      // `--` ends the flags (go list, go vet, staticcheck and gosec all accept it), so no package
      // argument is ever read as a flag.
      '--',
      p.dir,
    ];
    const r = capture(outFile, spec.toolPath, args, m.dir);
    if (r.error) throw runError('gosec', r.error);
    if (r.status !== 0)
      say(`${label}: gosec exited ${r.status} on ${p.importPath}: ${detail(r.stderr)}`);
    // gosec writes no file at all when it has nothing to report (probe G3).
    if (!existsSync(sarifFile)) continue;
    const out = gosecResults(
      JSON.parse(readBounded(sarifFile)),
      path.resolve(m.dir, p.dir),
      toRepo,
    );
    results.push(...out.results);
    rules.push(...out.rules);
  }
  return { results, rules, problems: [] };
}

/** A file's repository path through either spelling of the root, or null outside it. */
function repoPathOf(roots, file) {
  if (typeof file !== 'string' || file === '') return null;
  const abs = path.resolve(file);
  for (const base of roots) {
    const rel = path.relative(base, abs);
    if (rel !== '' && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel)) {
      return rel.split(path.sep).join('/');
    }
  }
  return null;
}

/** A module's packages to analyse (null when go list failed), with the summary and warnings. */
function modulePackages(st, m, label) {
  const listFile = path.join(st.spec.workDir, 'go-list.json');
  const listed = capture(
    listFile,
    st.spec.go,
    ['list', '-e', '-json=ImportPath,Dir,Error,DepsErrors', '--', './...'],
    m.dir,
  );
  if (listed.error) throw runError('go', listed.error);
  if (listed.status !== 0) {
    st.say(`${label}: go list failed: ${detail(listed.stderr)}`);
    return null;
  }
  const { packages, failed } = plannedPackages(
    splitJsonObjects(readBounded(listFile)),
    m.dir,
    st.scopeDirs,
  );
  st.summary.modules += 1;
  st.summary.packages += packages.length;
  st.summary.notLoaded += failed.length;
  if (failed.length > 0) {
    const hint = failed.some((f) => MISSING_DEPENDENCY.test(f.error))
      ? '; their dependencies are not on disk: run `go mod download` before `qualor scan`, vendor them, or set GOMODCACHE (config.md §6)'
      : '';
    st.say(
      `${label}: ${failed.length} package(s) not analysed, e.g. ${failed[0].importPath}: ${detail(failed[0].error)}${hint}`,
    );
  }
  return packages;
}

/** One tool result: counted when out of scope, dropped when already seen, else kept. */
function addResult(st, r) {
  if (!st.inScope.has(r.rel)) {
    st.summary.outOfScope += 1;
    return;
  }
  const key = JSON.stringify([
    r.sarif.ruleId,
    r.rel,
    r.sarif.locations[0].physicalLocation.region,
    r.sarif.message.text,
  ]);
  if (st.seen.has(key)) return;
  st.seen.add(key);
  st.results.push(r.sarif);
}

/** One module: its packages, the tool run on them, and its results; a non-fatal error is a warning. */
function runModule(st, m) {
  const label = m.rel === '' ? 'the root module' : m.rel;
  try {
    const packages = modulePackages(st, m, label);
    if (packages === null || packages.length === 0) return;
    const out = toolRun(st.spec, m, packages, st.toRepo, st.say, label);
    for (const r of out.results) addResult(st, r);
    for (const rule of out.rules ?? [])
      if (!st.gosecRules.has(rule.id)) st.gosecRules.set(rule.id, rule);
    if (out.problems.length > 0) {
      st.say(
        `${label}: ${out.problems.length} package(s) could not be type-checked and were not analysed, e.g. ${out.problems[0]}`,
      );
    }
  } catch (err) {
    if (err?.fatal === true) throw err;
    st.say(`${label}: ${detail(err instanceof Error ? err.message : String(err))}`);
  }
}

export function run(spec, warn) {
  const roots = [spec.root, realOr(spec.root)];
  let warnings = 0;
  const st = {
    spec,
    toRepo: (file) => repoPathOf(roots, file),
    inScope: new Set(spec.files),
    scopeDirs: new Set(
      spec.files.map((f) => realOr(path.join(spec.root, ...path.posix.dirname(f).split('/')))),
    ),
    say: (line) => {
      if (warnings < MAX_WARNINGS) warn(bounded(line));
      warnings += 1;
    },
    summary: { tool: spec.tool, modules: 0, packages: 0, notLoaded: 0, results: 0, outOfScope: 0 },
    seen: new Set(),
    results: [],
    gosecRules: new Map(),
  };
  for (const m of spec.modules) runModule(st, m);
  const { summary, results, gosecRules } = st;
  summary.results = results.length;
  const used = new Set(results.map((r) => r.ruleId));
  const rules =
    spec.tool === 'gosec'
      ? [...gosecRules.values()].filter((r) => used.has(r.id))
      : [...used].sort().map((id) => ({ id, helpUri: HELP[spec.tool](id) }));
  writeFileSync(spec.out, JSON.stringify(toSarif(spec.tool, spec.version, rules, results)));
  if (warnings > MAX_WARNINGS) warn(`${warnings - MAX_WARNINGS} more warning(s) left out`);
  return summary;
}

export function main(
  argv = process.argv.slice(2),
  io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) },
) {
  try {
    const i = argv.indexOf('--spec');
    if (i < 0 || argv[i + 1] === undefined) throw fatal('missing --spec');
    const summary = run(readSpec(argv[i + 1]), (line) => io.err(`go: warning: ${line}\n`));
    io.out(`${JSON.stringify(summary)}\n`);
    return 0;
  } catch (err) {
    io.err(`go: fatal: ${detail(err instanceof Error ? err.message : String(err))}\n`);
    return 2;
  }
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = main();
}
