// Decides which CI change Qualor proposes for a repository, or why it shows a snippet instead.
// Pure: the caller reads the repository and applies the plan. The edit of an existing
// `.gitlab-ci.yml` is a text insertion computed from the YAML document's ranges, so every comment,
// quote and blank line of the customer's file stays byte-identical outside the inserted lines.
import {
  isAlias,
  isMap,
  isScalar,
  isSeq,
  parseDocument,
  visit,
  type Document,
  type YAMLMap,
  type YAMLSeq,
} from 'yaml';
import {
  COMPONENT_PATH,
  githubWorkflow,
  gitlabIncludeEntry,
  gitlabIncludeSnippet,
  gitlabPlainJob,
  yamlScalar,
  type ComponentOptions,
} from './ci-templates';

export type CiSnippetReason =
  'already_set_up' | 'yaml_unsupported' | 'custom_ci_path' | 'no_public_url';

export interface CiSetupInput {
  provider: 'github' | 'gitlab';
  host: 'cloud' | 'self-hosted';
  serverUrl: string;
  /** The server's VERSION. */
  version: string;
  csharp: boolean;
  defaultBranch: string;
  existing: {
    gitlabCi: string | null;
    workflowFiles: string[];
    workflowQualor: string | null;
    tokenSecretSet: boolean;
  };
}

export type CiPlan =
  | {
      kind: 'change';
      files: { path: string; content: string; update: boolean }[];
      secrets: { name: 'QUALOR_TOKEN' }[];
      variables: { key: 'QUALOR_URL'; value: string }[];
      description: string;
    }
  | { kind: 'snippet'; reason: CiSnippetReason; snippet: string };

export function minorOf(version: string): string {
  const m = /^(\d+)\.(\d+)/.exec(version);
  return m ? `${m[1]}.${m[2]}` : version;
}

const GITLAB_FILE = '.gitlab-ci.yml';
const WORKFLOW_FILE = '.github/workflows/qualor.yml';

type Parsed = { ok: true; doc: Document.Parsed; root: YAMLMap | null } | { ok: false };

function parseGitlab(text: string): Parsed {
  if (/^\.\.\.\s*$/m.test(text)) return { ok: false };
  const doc = parseDocument(text, { keepSourceTokens: true });
  if (doc.errors.length > 0) return { ok: false };
  let unsupported = false;
  visit(doc, {
    Alias() {
      unsupported = true;
      return visit.BREAK;
    },
    Node(_key, node) {
      if (isAlias(node) || (node as { anchor?: string }).anchor) {
        unsupported = true;
        return visit.BREAK;
      }
      return undefined;
    },
  });
  if (unsupported) return { ok: false };
  if (doc.contents === null) return { ok: true, doc, root: null };
  if (!isMap(doc.contents) || doc.contents.flow) return { ok: false };
  return { ok: true, doc, root: doc.contents };
}

function hasQualorEntry(root: YAMLMap | null): boolean {
  if (!root) return false;
  if (root.has('qualor')) return true;
  const include = root.get('include', true);
  if (include === undefined || include === null) return false;
  const json = JSON.stringify((include as { toJSON?: () => unknown }).toJSON?.() ?? include);
  return /qualor\/qualor/.test(json);
}

/** The stage the job needs when `stages:` lists no `test`; null keeps GitLab's default. */
function stageFor(root: YAMLMap | null): string | null {
  const stages = root?.get('stages', true);
  if (!isSeq(stages)) return null;
  const names = stages.items
    .map((i) => (isScalar(i) && typeof i.value === 'string' ? i.value : null))
    .filter((n): n is string => n !== null && n !== '.pre' && n !== '.post');
  if (names.length === 0 || names.includes('test')) return null;
  return names[names.length - 1] ?? null;
}

interface Edit {
  at: number;
  remove: number;
  text: string;
}

function applyEdits(text: string, edits: Edit[]): string {
  let out = text;
  for (const e of [...edits].sort((a, b) => b.at - a.at)) {
    out = out.slice(0, e.at) + e.text + out.slice(e.at + e.remove);
  }
  return out;
}

function lineStart(text: string, pos: number): number {
  return text.lastIndexOf('\n', pos - 1) + 1;
}

/** Where a block entry that follows the node ending at `end` starts: the next line start. */
function nextLine(text: string, end: number): { at: number; prefix: string } {
  if (end > 0 && text[end - 1] === '\n') return { at: end, prefix: '' };
  const nl = text.indexOf('\n', end);
  return nl === -1 ? { at: text.length, prefix: '\n' } : { at: nl + 1, prefix: '' };
}

function flowEntry(o: ComponentOptions): string {
  const inputs = [`image-tag: '${o.minor}'`];
  if (o.stage !== null) inputs.push(`stage: ${yamlScalar(o.stage)}`);
  if (o.csharp)
    inputs.push(
      'image: qualor/scanner-dotnet',
      'dotnet: true',
      'build-command: dotnet build --no-incremental',
    );
  return `{ component: ${COMPONENT_PATH}@${o.minor}, inputs: { ${inputs.join(', ')} } }`;
}

function includeCount(root: YAMLMap | null): number {
  const v = root?.get('include', true);
  if (v === undefined || v === null) return 0;
  return isSeq(v) ? v.items.length : 1;
}

/**
 * Re-parses the edited file: no errors, one more include entry (or one new `qualor` job), and the
 * top-level keys otherwise unchanged. A shape the text edit mishandled is caught here.
 */
export function editIsSound(
  before: YAMLMap | null,
  after: string,
  kind: 'include' | 'job',
): boolean {
  const parsed = parseGitlab(after);
  if (!parsed.ok || !parsed.root) return false;
  const keys = (m: YAMLMap | null) =>
    m ? m.items.map((p) => String((p.key as { value?: unknown }).value)) : [];
  const expected = new Set(keys(before));
  expected.add(kind === 'include' ? 'include' : 'qualor');
  const got = keys(parsed.root);
  if (
    got.length !== new Set(got).size ||
    got.length !== expected.size ||
    got.some((k) => !expected.has(k))
  ) {
    return false;
  }
  if (kind === 'job') return isMap(parsed.root.get('qualor', true));
  const inc = parsed.root.get('include', true);
  return isSeq(inc) && inc.items.length === includeCount(before) + 1;
}

function appendTopLevel(text: string, block: string): string {
  if (text.trim() === '') return text + block;
  let base = text.endsWith('\n') ? text : text + '\n';
  if (!base.endsWith('\n\n')) base += '\n';
  return base + block;
}

/** Adds the component to an existing top-level `include`; null when the shape is not handled. */
function addToInclude(text: string, root: YAMLMap, o: ComponentOptions): string | null {
  const pair = root.items.find((p) => isScalar(p.key) && p.key.value === 'include');
  if (!pair || !isScalar(pair.key) || !pair.key.range) return null;
  const value = pair.value;
  if (!value || (value as { tag?: string }).tag) return null;
  const keyCol = pair.key.range[0] - lineStart(text, pair.key.range[0]);

  if (isSeq(value)) return addToSeq(text, value, o);

  if (isMap(value)) {
    if (!value.range) return null;
    if (value.flow) {
      return applyEdits(text, [
        { at: value.range[0], remove: 0, text: '[' },
        { at: value.range[1], remove: 0, text: `, ${flowEntry(o)}]` },
      ]);
    }
    const first = value.items[0]?.key as { range?: [number, number, number] } | undefined;
    if (!first?.range) return null;
    const ls = lineStart(text, first.range[0]);
    const col = first.range[0] - ls;
    if (text.slice(ls, first.range[0]).trim() !== '' || col - 2 < keyCol) return null;
    const { at, prefix } = nextLine(text, value.range[1]);
    return applyEdits(text, [
      { at: ls, remove: col, text: `${' '.repeat(col - 2)}- ` },
      { at, remove: 0, text: prefix + gitlabIncludeEntry(o, col - 2) },
    ]);
  }

  if (isScalar(value) && typeof value.value === 'string' && value.range) {
    const [start, end] = value.range;
    const raw = text.slice(start, end);
    if (raw.includes('\n') || /^[|>]/.test(raw)) return null;
    let from = start;
    while (text[from - 1] === ' ' || text[from - 1] === '\t') from--;
    if (text[from - 1] !== ':') return null;
    const pad = keyCol + 2;
    const { at, prefix } = nextLine(text, end);
    return applyEdits(text, [
      { at: from, remove: end - from, text: `\n${' '.repeat(pad)}- ${raw}` },
      { at, remove: 0, text: prefix + gitlabIncludeEntry(o, pad) },
    ]);
  }
  return null;
}

function addToSeq(text: string, seq: YAMLSeq, o: ComponentOptions): string | null {
  if (!seq.range) return null;
  const last = seq.items[seq.items.length - 1] as { range?: [number, number, number] } | undefined;
  if (seq.flow) {
    if (!last) return applyEdits(text, [{ at: seq.range[0] + 1, remove: 0, text: flowEntry(o) }]);
    if (!last.range) return null;
    return applyEdits(text, [{ at: last.range[1], remove: 0, text: `, ${flowEntry(o)}` }]);
  }
  if (!last?.range) return null;
  const indent = seq.range[0] - lineStart(text, seq.range[0]);
  if (text.slice(lineStart(text, seq.range[0]), seq.range[0]).trim() !== '') return null;
  const { at, prefix } = nextLine(text, last.range[1]);
  return applyEdits(text, [{ at, remove: 0, text: prefix + gitlabIncludeEntry(o, indent) }]);
}

function descriptionFor(i: CiSetupInput): string {
  const lines = [
    `Qualor analyses every ${i.provider === 'gitlab' ? 'merge request' : 'pull request'} and every push to the default branch, and reports the result there.`,
    '',
  ];
  if (i.provider === 'github') {
    lines.push(
      i.host === 'cloud' && !i.csharp
        ? `The workflow \`${WORKFLOW_FILE}\` runs the Qualor Action pinned at v${minorOf(i.version)}.`
        : `The workflow \`${WORKFLOW_FILE}\` runs the Qualor scanner image ${i.csharp ? 'qualor/scanner-dotnet' : 'qualor/scanner'}:${i.version}.`,
      'The token is stored as the Actions secret `QUALOR_TOKEN`; it is not in any file. The server address is in the workflow.',
      `To remove it, delete \`${WORKFLOW_FILE}\` and the \`QUALOR_TOKEN\` secret.`,
    );
  } else {
    lines.push(
      i.host === 'cloud'
        ? `\`${GITLAB_FILE}\` includes the Qualor CI/CD component pinned at ${minorOf(i.version)}.`
        : `\`${GITLAB_FILE}\` gets a \`qualor\` job that runs the scanner image ${i.csharp ? 'qualor/scanner-dotnet' : 'qualor/scanner'}:${i.version}.`,
      'The token is stored as the masked CI/CD variable `QUALOR_TOKEN` and the server address as `QUALOR_URL`; neither is in any file.',
      `To remove it, ${i.host === 'cloud' ? 'delete the include entry' : 'delete the `qualor` job'} and the two CI/CD variables.`,
    );
  }
  if (i.provider === 'github' && i.host === 'self-hosted') {
    lines.push('The job needs a Linux runner with Docker (labels `self-hosted` and `linux`).');
  }
  if (i.host === 'self-hosted') {
    lines.push(
      'To upgrade the scanner, edit the version in the file. The runners must be able to pull the image from Docker Hub.',
    );
  }
  if (i.csharp) {
    lines.push(
      '',
      "This is a C# repository: please check the build command (`dotnet build --no-incremental`) and replace it with the project's own build if it differs.",
    );
  }
  return lines.join('\n');
}

export function planCiSetup(input: CiSetupInput): CiPlan {
  const minor = minorOf(input.version);
  const { existing } = input;
  const change = (files: { path: string; content: string; update: boolean }[]): CiPlan => ({
    kind: 'change',
    files,
    secrets: [{ name: 'QUALOR_TOKEN' }],
    variables: input.provider === 'gitlab' ? [{ key: 'QUALOR_URL', value: input.serverUrl }] : [],
    description: descriptionFor(input),
  });

  if (input.provider === 'github') {
    const content = githubWorkflow({
      host: input.host,
      csharp: input.csharp,
      serverUrl: input.serverUrl,
      version: input.version,
      minor,
      defaultBranch: input.defaultBranch,
    });
    const hasWorkflow =
      existing.workflowQualor !== null ||
      existing.workflowFiles.some((f) => /^qualor[^/]*$/i.test(f.split('/').pop() ?? ''));
    if (existing.tokenSecretSet || hasWorkflow) {
      return { kind: 'snippet', reason: 'already_set_up', snippet: content };
    }
    return change([{ path: WORKFLOW_FILE, content, update: false }]);
  }

  // GitLab
  const text = existing.gitlabCi;
  const parsed = text === null ? ({ ok: true, root: null } as const) : parseGitlab(text);
  const stage = parsed.ok ? stageFor(parsed.root) : null;
  const snippetFor = (st: string | null) =>
    input.host === 'cloud'
      ? gitlabIncludeSnippet({ minor, stage: st, csharp: input.csharp })
      : gitlabPlainJob({ version: input.version, stage: st, csharp: input.csharp });

  const already = parsed.ok
    ? hasQualorEntry(parsed.root)
    : text !== null && (/qualor\/qualor/.test(text) || /^qualor:/m.test(text));
  if (existing.tokenSecretSet || already) {
    return { kind: 'snippet', reason: 'already_set_up', snippet: snippetFor(stage) };
  }
  if (!parsed.ok) return { kind: 'snippet', reason: 'yaml_unsupported', snippet: snippetFor(null) };

  const base = text ?? '';
  const unsupported = (): CiPlan => ({
    kind: 'snippet',
    reason: 'yaml_unsupported',
    snippet: snippetFor(stage),
  });
  let content: string;
  if (input.host === 'self-hosted') {
    content = appendTopLevel(
      base,
      gitlabPlainJob({ version: input.version, stage, csharp: input.csharp }),
    );
  } else {
    const o: ComponentOptions = { minor, stage, csharp: input.csharp };
    if (parsed.root?.has('include')) {
      const edited = addToInclude(base, parsed.root, o);
      if (edited === null) return unsupported();
      content = edited;
    } else {
      content = appendTopLevel(base, gitlabIncludeSnippet(o));
    }
  }
  if (!editIsSound(parsed.root, content, input.host === 'self-hosted' ? 'job' : 'include')) {
    return unsupported();
  }
  return change([{ path: GITLAB_FILE, content, update: text !== null }]);
}
