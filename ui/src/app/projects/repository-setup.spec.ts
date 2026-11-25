import { errorText, mergeRequestNumber, type RunItem } from './repository-setup';

describe('mergeRequestNumber', () => {
  it('reads /pull/N and /merge_requests/N and gives null for any other URL', () => {
    expect(mergeRequestNumber('https://github.com/acme/api/pull/7')).toBe('#7');
    expect(mergeRequestNumber('https://gitlab.example/acme/api/-/merge_requests/12/')).toBe('!12');
    expect(mergeRequestNumber('https://dev.azure.com/acme/p/_git/r/pullrequest/5')).toBe('!5');
    expect(mergeRequestNumber('https://tfs.acme.example/tfs/C/p/_git/r/pullrequest/12/')).toBe(
      '!12',
    );
    expect(mergeRequestNumber('https://example.com/acme/api/issues/3')).toBeNull();
  });
});

describe('errorText', () => {
  const failed = (code: string, message: string, stage: 'read' | 'change' | null = null) =>
    ({ error: { code, message, stage } }) as RunItem;
  const github = { provider: 'github', baseUrl: 'https://api.github.com' } as const;
  const gitlab = { provider: 'gitlab', baseUrl: 'https://gitlab.example' } as const;
  const azure = { provider: 'azure', baseUrl: 'https://dev.azure.com/acme' } as const;

  it('tells a refused read from a refused change, by the stage, never the message', () => {
    expect(errorText(failed('refused', 'any text', 'change'), github)).toBe(
      'GitHub refused the change.',
    );
    const read = failed('refused', 'any text', 'read');
    expect(errorText(read, github)).toBe('GitHub refused a request to read the repository.');
    expect(errorText(read, null)).toBe('The provider refused a request to read the repository.');
    expect(
      errorText(failed('refused', 'The provider refused a request to read', null), azure),
    ).toBe('Azure DevOps refused the change.');
  });

  it('words a permission error by provider and stage', () => {
    const change = (p: typeof github | typeof gitlab | typeof azure) =>
      errorText(failed('permission', 'ignored', 'change'), p);
    expect(change(github)).toContain('The GitHub App needs');
    expect(change(gitlab)).toContain('The GitLab token needs');
    expect(change(azure)).toContain('The Azure DevOps identity needs');
    // A Project Contributor has Edit build pipeline; the pipeline create also needs the queue's role.
    expect(change(azure)).toContain(
      "Edit build pipeline in the project, the User role on the agent pool's queue",
    );
    // Azure DevOps refuses a personal access token without the pipelines scopes (HTTP 401): a
    // token's connection, or one whose sign-in is not known, names them; a service principal's not.
    const scopes =
      'A personal access token also needs the Build (Read & execute), Agent Pools (Read) and Pipeline Resources (Use and manage) scopes.';
    const signedIn = (auth: 'pat' | 'service_principal_secret') =>
      ({ ...azure, azure: { auth } }) as unknown as typeof azure;
    expect(change(azure)).toContain(scopes);
    expect(change(signedIn('pat'))).toContain(scopes);
    expect(change(signedIn('service_principal_secret'))).not.toContain('personal access token');
    expect(change(signedIn('service_principal_secret'))).toContain(
      "Edit build pipeline in the project, the User role on the agent pool's queue",
    );
    expect(errorText(failed('permission', 'The GitHub App needs', 'read'), github)).toBe(
      'The connection was refused access to the repository.',
    );
    expect(errorText(failed('permission', 'x', 'change'), null)).toBe(
      'The connection was refused access to the repository.',
    );
  });
});
