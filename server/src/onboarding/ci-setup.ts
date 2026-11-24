// Decides which CI change Qualor proposes for a repository, or why it shows a snippet instead.
// Pure: the caller reads the repository and applies the plan. The edit of an existing
// `.gitlab-ci.yml` is a text insertion computed from the YAML document's ranges, so every comment,
// quote and blank line of the customer's file stays byte-identical outside the inserted lines.
import { assertNever, type ScmProvider } from '@qualor/shared';
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
import { codeSpan } from '../scm/markdown';
import {
  COMPONENT_PATH,
  azurePipeline,
  githubWorkflow,
  gitlabIncludeEntry,
  gitlabIncludeSnippet,
  gitlabPlainJob,
  projectKeyArg,
  yamlScalar,
  type AzurePipelineOptions,
  type AzurePool,
  type ComponentOptions,
} from './ci-templates';

export type CiSnippetReason =
  'already_set_up' | 'yaml_unsupported' | 'custom_ci_path' | 'no_public_url';

export interface CiSetupInput {
  provider: ScmProvider;
  host: 'cloud' | 'self-hosted';
  serverUrl: string;
  /**
   * The project's key, written into every file and snippet: it may differ from the repository's
   * path (a `-2` suffix, an adopted project), which the scanner would use otherwise.
   */
  projectKey: string;
  /** The server's VERSION. */
  version: string;
  csharp: boolean;
  defaultBranch: string;
  existing: {
    gitlabCi: string | null;
    /** The names of the files in `.github/workflows`. */
    workflowFiles: string[];
    /** The texts of the workflow files Qualor read, searched for a Qualor step. */
    workflowTexts: string[];
    /** The repository's own QUALOR_TOKEN secret (GitHub) or CI/CD variable (GitLab) exists. */
    tokenSecretSet: boolean;
    /** A QUALOR_TOKEN the repository inherits exists: an organisation secret on GitHub. */
    inheritedTokenSet: boolean;
  };
  /** Azure DevOps only: the agent pool of the pipeline and what the repository already holds. */
  azure?: {
    pool: AzurePool;
    existing: {
      /** `.azure-pipelines/qualor.yml` exists on the default branch. */
      pipelineFile: boolean;
      /** The text of `azure-pipelines.yml` on the default branch, when it exists. */
      azurePipelinesYml: string | null;
      /** A pipeline definition of the repository: the file it runs and whether its secret is set. */
      definition: { yamlPath: string | null; secretSet: boolean } | null;
    };
  };
}

/**
 * A CI file that already runs Qualor: the Action, the scanner image, the scanner's commands, or a
 * CI/CD component include of a `qualor` component from any path (a mirror's too).
 */
const QUALOR_IN_CI = /qualor-dev\/scan-action|qualor\/scanner|qualor\s+(scan|dotnet)\b|\/qualor@/;

/** Whether a CI file's text shows a Qualor step. */
export function runsQualor(text: string): boolean {
  return QUALOR_IN_CI.test(text);
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
export const AZURE_FILE = '.azure-pipelines/qualor.yml';

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
  const inputs = [`image-tag: '${o.minor}'`, `args: ${yamlScalar(projectKeyArg(o.projectKey))}`];
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
  if (isMap(value)) return addToIncludeMap(text, value, keyCol, o);
  if (isScalar(value) && typeof value.value === 'string' && value.range) {
    return addToIncludeScalar(text, value.range, keyCol, o);
  }
  return null;
}

/** `include:` holds a single mapping: turns it into a sequence and appends the component. */
function addToIncludeMap(
  text: string,
  value: YAMLMap,
  keyCol: number,
  o: ComponentOptions,
): string | null {
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

/** `include:` holds a single string: turns it into a sequence and appends the component. */
function addToIncludeScalar(
  text: string,
  range: [number, number, number],
  keyCol: number,
  o: ComponentOptions,
): string | null {
  const [start, end] = range;
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

function scannerImage(i: CiSetupInput): string {
  return i.csharp ? 'qualor/scanner-dotnet' : 'qualor/scanner';
}

function githubDescription(i: CiSetupInput): string[] {
  return [
    i.host === 'cloud' && !i.csharp
      ? `The workflow \`${WORKFLOW_FILE}\` runs the Qualor Action pinned at v${minorOf(i.version)}.`
      : `The workflow \`${WORKFLOW_FILE}\` runs the Qualor scanner image ${scannerImage(i)}:${i.version}.`,
    'The token is stored as the Actions secret `QUALOR_TOKEN`; it is not in any file. The server address and the project key are in the workflow.',
    `To remove it, delete \`${WORKFLOW_FILE}\` and the \`QUALOR_TOKEN\` secret.`,
  ];
}

function gitlabDescription(i: CiSetupInput): string[] {
  const cloud = i.host === 'cloud';
  const removal = cloud ? 'delete the include entry' : 'delete the `qualor` job';
  return [
    cloud
      ? `\`${GITLAB_FILE}\` includes the Qualor CI/CD component pinned at ${minorOf(i.version)}.`
      : `\`${GITLAB_FILE}\` gets a \`qualor\` job that runs the scanner image ${scannerImage(i)}:${i.version}.`,
    'The token is stored as the masked CI/CD variable `QUALOR_TOKEN` and the server address as `QUALOR_URL`; neither is in any file.',
    `To remove it, ${removal} and the two CI/CD variables.`,
  ];
}

/** The name of the pipeline Qualor creates, as the description names it. */
const PIPELINE_MENTION = 'the pipeline `Qualor`';

/**
 * The description with the pipeline's own name, when `Qualor` was taken in the Azure DevOps project
 * and the pipeline got another (setup-run.ts): every mention, as a code span.
 */
export function azurePipelineNamed(description: string, name: string): string {
  if (name === 'Qualor') return description;
  return description.replaceAll(PIPELINE_MENTION, `the pipeline ${codeSpan(name)}`);
}

function azureDescription(i: CiSetupInput): string[] {
  const pool = i.azure?.pool ?? { vmImage: 'ubuntu-latest' as const };
  const image = codeSpan(`${scannerImage(i)}:${i.version}`);
  return [
    `The pipeline file ${codeSpan(AZURE_FILE)} runs the Qualor scanner image ${image}.`,
    `Qualor creates ${PIPELINE_MENTION} from it. The token is its secret variable \`QUALOR_TOKEN\` and the server address its variable \`QUALOR_URL\`; neither is in any file.`,
    // Probe item 26: the hosted queue is open to every pipeline; another pool's queue is not.
    'vmImage' in pool
      ? `The pipeline runs on the Microsoft-hosted image ${codeSpan(pool.vmImage)}, whose agent pool is open to every pipeline.`
      : `The pipeline runs on the agent pool ${codeSpan(pool.name)}. It needs a Linux agent with Docker, and the agent pool must be authorised for ${PIPELINE_MENTION}. The agents must be able to pull the image from Docker Hub.`,
    'After the first analysis of the default branch, Qualor adds the Build validation policy that runs the pipeline on every pull request into that branch.',
    `To remove it, delete ${codeSpan(AZURE_FILE)}, ${PIPELINE_MENTION} (its secret goes with it) and the Build validation policy.`,
  ];
}

const CHANGE_REQUEST_WORD: Record<ScmProvider, string> = {
  gitlab: 'merge request',
  github: 'pull request',
  azure: 'pull request',
};

function providerDescription(i: CiSetupInput): string[] {
  switch (i.provider) {
    case 'github':
      return githubDescription(i);
    case 'gitlab':
      return gitlabDescription(i);
    case 'azure':
      return azureDescription(i);
    default:
      return assertNever(i.provider, 'provider');
  }
}

function descriptionFor(i: CiSetupInput): string {
  const lines = [
    `Qualor analyses every ${CHANGE_REQUEST_WORD[i.provider]} and every push to the default branch, and reports the result there.`,
    "On each tag, it records a version: the release's dependency list.",
    `The analyses go to the Qualor project \`${i.projectKey}\`.`,
    '',
    ...providerDescription(i),
  ];
  const githubRunner = i.provider === 'github' && i.host === 'self-hosted'; // provider-guard: only GitHub has runner labels
  if (githubRunner) {
    lines.push('The job needs a Linux runner with Docker (labels `self-hosted` and `linux`).');
  }
  if (i.host === 'self-hosted' && i.provider !== 'azure') {
    // provider-guard: the Azure lines cover the agents' image pull
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

type ChangeFiles = { path: string; content: string; update: boolean }[];

function changePlan(input: CiSetupInput, files: ChangeFiles): CiPlan {
  return {
    kind: 'change',
    files,
    secrets: [{ name: 'QUALOR_TOKEN' }],
    variables:
      input.provider === 'gitlab' || input.provider === 'azure' // provider-guard: only GitLab and Azure have a CI/CD variable for the address
        ? [{ key: 'QUALOR_URL', value: input.serverUrl }]
        : [],
    description: descriptionFor(input),
  };
}

function planGithub(input: CiSetupInput): CiPlan {
  const { existing } = input;
  const content = githubWorkflow({
    host: input.host,
    csharp: input.csharp,
    serverUrl: input.serverUrl,
    projectKey: input.projectKey,
    version: input.version,
    minor: minorOf(input.version),
    defaultBranch: input.defaultBranch,
  });
  const hasWorkflow =
    existing.workflowFiles.some((f) => /^qualor[^/]*$/i.test(f.split('/').pop() ?? '')) ||
    existing.workflowTexts.some(runsQualor);
  if (existing.tokenSecretSet || existing.inheritedTokenSet || hasWorkflow) {
    return { kind: 'snippet', reason: 'already_set_up', snippet: content };
  }
  return changePlan(input, [{ path: WORKFLOW_FILE, content, update: false }]);
}

/** True when the repository already runs Qualor, judged from its `.gitlab-ci.yml`. */
function gitlabAlreadyRunsQualor(
  text: string | null,
  parsed: Parsed | { ok: true; root: null },
): boolean {
  if (text !== null && runsQualor(text)) return true;
  if (parsed.ok) return hasQualorEntry(parsed.root);
  return text !== null && (/qualor\/qualor/.test(text) || /^qualor:/m.test(text));
}

function planGitlab(input: CiSetupInput): CiPlan {
  const minor = minorOf(input.version);
  const { existing, projectKey } = input;
  const text = existing.gitlabCi;
  const parsed = text === null ? ({ ok: true, root: null } as const) : parseGitlab(text);
  const stage = parsed.ok ? stageFor(parsed.root) : null;
  const snippetFor = (st: string | null) =>
    input.host === 'cloud'
      ? gitlabIncludeSnippet({ minor, stage: st, csharp: input.csharp, projectKey })
      : gitlabPlainJob({ version: input.version, stage: st, csharp: input.csharp, projectKey });

  if (
    existing.tokenSecretSet ||
    existing.inheritedTokenSet ||
    gitlabAlreadyRunsQualor(text, parsed)
  ) {
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
      gitlabPlainJob({ version: input.version, stage, csharp: input.csharp, projectKey }),
    );
  } else {
    const o: ComponentOptions = { minor, stage, csharp: input.csharp, projectKey };
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
  return changePlan(input, [{ path: GITLAB_FILE, content, update: text !== null }]);
}

/**
 * The file, with the header of a snippet, plus the steps Qualor would do outside it, as trailing
 * comments (one YAML document): every Azure DevOps snippet, the planner's and the setup run's
 * (setup-run.ts `freshSnippet`).
 */
export function azureSnippet(options: AzurePipelineOptions, serverUrl: string): string {
  return (
    azurePipeline({ ...options, snippet: true }) +
    [
      '',
      `# Save this as ${AZURE_FILE}, then:`,
      '#   1. Create a pipeline from it (Pipelines, New pipeline, Azure Repos Git, Existing Azure Pipelines YAML file).',
      `#   2. Add the pipeline variable QUALOR_URL = ${serverUrl}.`,
      '#   3. Add the pipeline variable QUALOR_TOKEN (a project analysis token) and mark it secret.',
      '#   4. After the first analysis of the default branch, add the pipeline as a Build validation',
      '#      policy of that branch.',
      '',
    ].join('\n')
  );
}

function planAzure(input: CiSetupInput): CiPlan {
  const azure = input.azure ?? {
    pool: { vmImage: 'ubuntu-latest' as const },
    existing: { pipelineFile: false, azurePipelinesYml: null, definition: null },
  };
  const { existing } = azure;
  const options: AzurePipelineOptions = {
    projectKey: input.projectKey,
    version: input.version,
    pool: azure.pool,
    csharp: input.csharp,
  };
  const definitionSet =
    existing.definition?.yamlPath === AZURE_FILE && existing.definition.secretSet;
  if (
    existing.pipelineFile ||
    definitionSet ||
    (existing.azurePipelinesYml !== null && runsQualor(existing.azurePipelinesYml))
  ) {
    return {
      kind: 'snippet',
      reason: 'already_set_up',
      snippet: azureSnippet(options, input.serverUrl),
    };
  }
  return changePlan(input, [{ path: AZURE_FILE, content: azurePipeline(options), update: false }]);
}

export function planCiSetup(input: CiSetupInput): CiPlan {
  switch (input.provider) {
    case 'github':
      return planGithub(input);
    case 'gitlab':
      return planGitlab(input);
    case 'azure':
      return planAzure(input);
    default:
      return assertNever(input.provider, 'provider');
  }
}
