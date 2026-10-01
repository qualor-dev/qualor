/**
 * Qualor's own reader of the go.mod lines it needs (plan 9C, config.md §6): the module path, the
 * `go` and `toolchain` lines and every `replace`. It never runs the go command, which, inside a
 * module and with the CI's GOTOOLCHAIN=auto, would download and run the toolchain go.mod names.
 * Other directives (require, exclude, retract, godebug, tool, ignore) are skipped.
 */
export interface GoModReplace {
  old: string;
  oldVersion: string | null;
  target: string;
  /** null: the target is a directory (go.mod's own rule: a replacement without a version). */
  targetVersion: string | null;
}

export interface GoMod {
  module: string | null;
  go: string | null;
  toolchain: string | null;
  replaces: GoModReplace[];
}

const GO_VERSION_TEXT = /^(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?$/;

/** One line's tokens: words, "interpreted" and `raw` strings; `//` starts a comment. null: unreadable. */
export function goModTokens(line: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i] as string;
    if (c === ' ' || c === '\t' || c === '\r') {
      i += 1;
    } else if (line.startsWith('//', i)) {
      break;
    } else if (c === '"') {
      let j = i + 1;
      let escaped = false;
      for (; j < line.length; j++) {
        const d = line[j];
        if (escaped) escaped = false;
        else if (d === '\\') escaped = true;
        else if (d === '"') break;
      }
      if (j >= line.length) return null;
      try {
        out.push(JSON.parse(line.slice(i, j + 1)) as string);
      } catch {
        return null;
      }
      i = j + 1;
    } else if (c === '`') {
      const j = line.indexOf('`', i + 1);
      if (j < 0) return null;
      out.push(line.slice(i + 1, j));
      i = j + 1;
    } else {
      let j = i;
      while (j < line.length && !/[\s"`]/.test(line[j] as string) && !line.startsWith('//', j)) j++;
      out.push(line.slice(i, j));
      i = j;
    }
  }
  return out;
}

function directive(mod: GoMod, verb: string, args: string[]): string | null {
  switch (verb) {
    case 'module':
      if (args.length !== 1) return 'module needs one path';
      mod.module = args[0] as string;
      return null;
    case 'go':
      if (args.length !== 1 || !GO_VERSION_TEXT.test(args[0] as string)) {
        return 'go needs a version such as 1.24';
      }
      mod.go = args[0] as string;
      return null;
    case 'toolchain':
      mod.toolchain = args[0] ?? null;
      return null;
    case 'replace': {
      const arrow = args.indexOf('=>');
      const after = args.length - arrow - 1;
      if (arrow < 1 || arrow > 2 || after < 1 || after > 2) {
        return 'replace needs old [version] => new [version]';
      }
      mod.replaces.push({
        old: args[0] as string,
        oldVersion: arrow === 2 ? (args[1] as string) : null,
        target: args[arrow + 1] as string,
        targetVersion: args[arrow + 2] ?? null,
      });
      return null;
    }
    default:
      return null;
  }
}

export function parseGoMod(text: string): GoMod | { error: string } {
  const mod: GoMod = { module: null, go: null, toolchain: null, replaces: [] };
  let block: string | null = null;
  const lines = text.split('\n');
  for (let n = 0; n < lines.length; n++) {
    const tokens = goModTokens(lines[n] as string);
    if (tokens === null) return { error: `line ${n + 1} cannot be read` };
    if (tokens.length === 0) continue;
    if (block !== null) {
      if (tokens.length === 1 && tokens[0] === ')') {
        block = null;
        continue;
      }
      const err = directive(mod, block, tokens);
      if (err !== null) return { error: `line ${n + 1}: ${err}` };
      continue;
    }
    const [verb, ...args] = tokens as [string, ...string[]];
    if (args.length === 1 && args[0] === '(') {
      block = verb;
      continue;
    }
    const err = directive(mod, verb, args);
    if (err !== null) return { error: `line ${n + 1}: ${err}` };
  }
  if (block !== null) return { error: 'a ( block is not closed' };
  return mod;
}

/** [major, minor, kind (0 language version, 1 beta, 2 rc, 3 release), n] as the go command orders them. */
function versionKey(v: string): [number, number, number, number] {
  const m = GO_VERSION_TEXT.exec(v.replace(/^go/, ''));
  if (m === null) return [0, 0, 0, 0];
  const [, major, minor, patch, pre, n] = m;
  if (pre !== undefined) return [Number(major), Number(minor), pre === 'beta' ? 1 : 2, Number(n)];
  if (patch !== undefined) return [Number(major), Number(minor), 3, Number(patch)];
  return [Number(major), Number(minor), 0, 0];
}

/** <0, 0, >0 like the go command orders `1.27` < `1.27rc1` < `1.27.0` < `1.27.1` < `1.28rc1`. */
export function compareGoVersions(a: string, b: string): number {
  const x = versionKey(a);
  const y = versionKey(b);
  for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return (x[i] as number) - (y[i] as number);
  return 0;
}
