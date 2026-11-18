import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import {
  executable,
  isInside,
  real,
  resolveBinary,
  within,
  type ResolveBinaryOptions,
} from '../analyzers/binary';

/**
 * Ruling T12a: how the fix job starts a package manager. A program from `PATH` (never from the
 * repository, `resolveBinary`) runs as it is. On Windows npm, pnpm and Yarn are `.cmd` shims written
 * by npm (its own `npm.cmd`, and `cmd-shim` for global packages); Node starts a `.cmd` only through
 * `cmd.exe`, and B9 forbids a shell (the arguments carry names from the claim). Such a shim is run
 * as what it runs: node with the script it names, a script under the shim's own directory. Any
 * other `.cmd` (`mvn.cmd`) is not served, and says why.
 */
export interface ToolCommand {
  command: string;
  /** Arguments before the call's own (the shim's script). */
  args: readonly string[];
}

/*
 * Each pattern reads one line of the shim (`m`, CR removed first); every repeat is bounded, so
 * none can backtrack far.
 */
/** cmd-shim's last line: `"%_prog%"  "%dp0%\<script>" %*`, `_prog` being node (checked apart). */
const CMD_SHIM_RUN = /"%_prog%"[ \t]{1,16}"%dp0%\\([^"%\n]{1,1024})"[ \t]{1,16}%\*[ \t]{0,16}$/m;
const CMD_SHIM_NODE = /^[ \t]{0,16}SET[ \t]{1,16}"_prog=%dp0%\\node\.exe"[ \t]{0,16}$/im;
/** npm's own shim: `"%NODE_EXE%" "%<VAR>%" %*`, `<VAR>` set to `%~dp0\<script>`. */
const NPM_SHIM_RUN = /^"%NODE_EXE%"[ \t]{1,16}"%(\w{1,64})%"[ \t]{1,16}%\*[ \t]{0,16}$/m;
const NPM_SHIM_NODE = /^[ \t]{0,16}SET[ \t]{1,16}"NODE_EXE=%~dp0\\node\.exe"[ \t]{0,16}$/im;
const SET_SCRIPT = /^[ \t]{0,16}SET[ \t]{1,16}"(\w{1,64})=%~dp0\\([^"%]{1,1024})"[ \t]{0,16}$/i;

/** The value a shim sets `name` to, when it is `%~dp0\<script>`: the script. */
function setScript(text: string, name: string): string | null {
  for (const line of text.split('\n')) {
    const m = SET_SCRIPT.exec(line);
    if (m?.[1] === name && m[2] !== undefined) return m[2];
  }
  return null;
}

/**
 * The script a node shim of npm runs, relative to the shim's directory (`\`-separated as written),
 * or null for any other `.cmd`.
 */
export function shimScript(text: string): string | null {
  const shim = text.replaceAll('\r', '');
  const cmdShim = CMD_SHIM_RUN.exec(shim);
  if (cmdShim?.[1] !== undefined && CMD_SHIM_NODE.test(shim)) return cmdShim[1];
  const npmShim = NPM_SHIM_RUN.exec(shim);
  if (npmShim?.[1] === undefined || !NPM_SHIM_NODE.test(shim)) return null;
  return setScript(shim, npmShim[1]);
}

const isFile = (p: string): boolean => {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
};

/** The first `<tool>.cmd` on `PATH` (absolute entries, outside the repository). */
function findCmd(tool: string, o: ResolveBinaryOptions): string | null {
  const pathVar = o.env['PATH'] ?? o.env['Path'] ?? '';
  for (const dir of pathVar.split(';').filter((d) => path.isAbsolute(d))) {
    const candidate = path.join(dir, `${tool}.cmd`);
    if (isFile(candidate) && !isInside(o.root, candidate)) return candidate;
  }
  return null;
}

/** A shim's script and node, or why the shim is not served. */
function shimCommand(
  tool: string,
  shim: string,
  o: ResolveBinaryOptions,
): ToolCommand | { problem: string } {
  const name = `${tool}.cmd`;
  const shell = `${name} is not a node shim of npm, and qualor fix starts no .cmd through a shell`;
  let script: string | null;
  try {
    script = shimScript(readFileSync(shim, 'utf8'));
  } catch {
    script = null;
  }
  if (script === null) return { problem: shell };
  const dir = path.dirname(shim);
  const file = path.join(dir, ...script.split(/[\\/]/));
  if (!within(real(dir), real(file)) || !within(path.resolve(dir), path.resolve(file))) {
    return { problem: `${name} runs a script outside its own directory` };
  }
  if (!isFile(file)) return { problem: `${name} runs a script that is missing` };
  const local = path.join(dir, 'node.exe');
  const node =
    executable(local, 'win32') && !isInside(o.root, local) ? local : resolveBinary('node', o);
  if (node === null) return { problem: `${name} needs node, which is not on PATH` };
  return { command: node, args: [file] };
}

/**
 * Ruling T12a: how to start `tool`: a program from `PATH` (`resolveBinary`), else on Windows its
 * npm node shim as node with the shim's script; `{ problem }` for a `.cmd` that is not served;
 * null when the tool is not installed.
 */
export function resolveTool(
  tool: string,
  o: ResolveBinaryOptions,
): ToolCommand | { problem: string } | null {
  const binary = resolveBinary(tool, o);
  if (binary !== null) return { command: binary, args: [] };
  if ((o.platform ?? process.platform) !== 'win32') return null;
  const shim = findCmd(tool, o);
  return shim === null ? null : shimCommand(tool, shim, o);
}
