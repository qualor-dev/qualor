// The CI files Qualor proposes for a repository. Pure strings: no file reads at run time.
// Keep in step with templates/qualor.yml, integrations/github/*.yml and docs/guide/{github,gitlab}.md.

/** Pinned like the repository's own templates (integrations/github/qualor.yml). */
const CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0';
const FORK_GUARD =
  "github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository";
const REF = '${{ github.event.pull_request.head.sha || github.sha }}';
const TOKEN = '${{ secrets.QUALOR_TOKEN }}';

const GITLAB_REPORT_FLAGS =
  '--gitlab-code-quality gl-code-quality-report.json --gitlab-sast gl-sast-report.json --gitlab-dependency-scanning gl-dependency-scanning-report.json';

export const COMPONENT_PATH = 'gitlab.com/qualor/qualor/qualor';

/** A YAML scalar: plain when that is safe, else single-quoted. */
export function yamlScalar(value: string): string {
  // Plain only when it starts with a letter (never a number) and is no boolean/null word in
  // YAML 1.2 core or 1.1 (GitLab parses 1.1: yes/no/on/off/y/n).
  const special = /^(true|false|yes|no|on|off|y|n|null)$/i;
  return /^[A-Za-z][A-Za-z0-9_./@:+-]*$/.test(value) && !/:$/.test(value) && !special.test(value)
    ? value
    : `'${value.replace(/'/g, "''")}'`;
}

/**
 * The scanner's `--project-key` flag for a key, as one shell word (a key has no space or shell
 * character, PROJECT_KEY_PATTERN). A key that starts with a dash is joined with `=`, so the scanner
 * reads it as the flag's value rather than another flag.
 */
export function projectKeyArg(key: string): string {
  return key.startsWith('-') ? `--project-key=${key}` : `--project-key ${key}`;
}

export interface ComponentOptions {
  minor: string;
  stage: string | null;
  csharp: boolean;
  /** The project's key: the component passes it to the scan as `args`. */
  projectKey: string;
}

/** The `include` list entry for the GitLab CI/CD component, with its first line at `indent` spaces. */
export function gitlabIncludeEntry(o: ComponentOptions, indent: number): string {
  const pad = ' '.repeat(indent);
  const lines = [
    `${pad}- component: ${COMPONENT_PATH}@${o.minor}`,
    `${pad}  inputs:`,
    `${pad}    image-tag: '${o.minor}'`,
    `${pad}    args: ${yamlScalar(projectKeyArg(o.projectKey))}`,
  ];
  if (o.stage !== null) lines.push(`${pad}    stage: ${yamlScalar(o.stage)}`);
  if (o.csharp) {
    lines.push(`${pad}    image: qualor/scanner-dotnet`);
    lines.push(`${pad}    dotnet: true`);
    lines.push(`${pad}    build-command: dotnet build --no-incremental`);
  }
  return lines.join('\n') + '\n';
}

export function gitlabIncludeSnippet(o: ComponentOptions): string {
  return `include:\n${gitlabIncludeEntry(o, 2)}`;
}

export interface JobOptions {
  version: string;
  stage: string | null;
  csharp: boolean;
  projectKey: string;
}

/** The plain `qualor:` job for self-managed GitLab (the guide's "Without the component"). */
export function gitlabPlainJob(o: JobOptions): string {
  const image = o.csharp ? 'qualor/scanner-dotnet' : 'qualor/scanner';
  const key = `      ${projectKeyArg(o.projectKey)}`;
  const script = o.csharp
    ? [
        '    - qualor dotnet begin',
        '    - dotnet build --no-incremental',
        '    - >-',
        '      qualor dotnet end',
        key,
        ...GITLAB_REPORT_FLAGS.split(' --').map((f, i) => `      ${i === 0 ? f : `--${f}`}`),
      ]
    : [
        '    - >-',
        '      qualor scan',
        key,
        ...GITLAB_REPORT_FLAGS.split(' --').map((f, i) => `      ${i === 0 ? f : `--${f}`}`),
      ];
  const lines = [
    'qualor:',
    `  stage: ${yamlScalar(o.stage ?? 'test')}`,
    `  image: { name: ${image}:${o.version}, entrypoint: [''] }`,
    "  variables: { GIT_DEPTH: '0' }",
    '  script:',
    ...script,
  ];
  if (o.csharp) lines.push('  after_script:', '    - qualor dotnet abort');
  lines.push(
    '  interruptible: true',
    '  artifacts:',
    '    when: always',
    '    reports:',
    '      codequality: gl-code-quality-report.json',
    '      sast: gl-sast-report.json',
    '      dependency_scanning: gl-dependency-scanning-report.json',
    '  rules:',
    '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
    '    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH',
  );
  return lines.join('\n') + '\n';
}

export interface WorkflowOptions {
  /** `github.com` / GHE.com: the Action; `self-hosted` (GHES): a container job. */
  host: 'cloud' | 'self-hosted';
  csharp: boolean;
  serverUrl: string;
  projectKey: string;
  version: string;
  minor: string;
  defaultBranch: string;
}

function header(o: WorkflowOptions): string[] {
  return [
    'name: qualor',
    'on:',
    '  pull_request:',
    '  push:',
    `    branches: [${yamlScalar(o.defaultBranch)}]`,
    'permissions:',
    '  contents: read',
    'jobs:',
    '  qualor:',
    '    # Pull requests from forks get no secrets, so they are skipped.',
    `    if: ${FORK_GUARD}`,
    `    runs-on: ${o.host === 'self-hosted' ? '[self-hosted, linux]' : 'ubuntu-latest'}`,
  ];
}

const checkoutStep = (o: WorkflowOptions): string[] => [
  `      - uses: ${o.host === 'self-hosted' ? 'actions/checkout@v4' : CHECKOUT}`,
  '        with:',
  '          fetch-depth: 0',
  '          persist-credentials: false',
  `          ref: ${REF}`,
];

/**
 * The workflow file `.github/workflows/qualor.yml`. The server address and the project key are
 * written literally.
 */
export function githubWorkflow(o: WorkflowOptions): string {
  const url = yamlScalar(o.serverUrl);
  const key = yamlScalar(o.projectKey);
  const container = (image: string) => [
    '    container:',
    `      image: ${image}:${o.version}`,
    '      options: --user 1001',
  ];
  let lines: string[];
  if (o.csharp) {
    lines = [
      ...header(o),
      ...container('qualor/scanner-dotnet'),
      '    steps:',
      ...checkoutStep(o),
      '      - run: qualor dotnet begin',
      "      # Check this build command: use the repository's own build (restore, feeds, configuration)",
      '      # and keep --no-incremental, so every project is compiled and writes its analysis log.',
      '      - run: dotnet build --no-incremental',
      "      # The token is in this step only: the build runs the repository's code and must not see it.",
      '      - run: qualor dotnet end',
      '        env:',
      `          QUALOR_URL: ${url}`,
      `          QUALOR_PROJECT_KEY: ${key}`,
      `          QUALOR_TOKEN: ${TOKEN}`,
      '      - if: failure() || cancelled()',
      '        run: qualor dotnet abort',
    ];
  } else if (o.host === 'cloud') {
    lines = [
      ...header(o),
      '    steps:',
      ...checkoutStep(o),
      '      # Install dependencies (JS/TS, Go) or build (Java) here, before the scan.',
      `      - uses: qualor-dev/scan-action@v${o.minor}`,
      '        with:',
      `          server-url: ${url}`,
      `          project-key: ${key}`,
      `          token: ${TOKEN}`,
    ];
  } else {
    lines = [
      ...header(o),
      ...container('qualor/scanner'),
      '    steps:',
      ...checkoutStep(o),
      '      # Install dependencies (JS/TS, Go) or build (Java) here, before the scan.',
      '      - run: qualor scan',
      '        env:',
      `          QUALOR_URL: ${url}`,
      `          QUALOR_PROJECT_KEY: ${key}`,
      `          QUALOR_TOKEN: ${TOKEN}`,
    ];
  }
  return lines.join('\n') + '\n';
}
