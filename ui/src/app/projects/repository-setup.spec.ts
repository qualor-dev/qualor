import { errorText, mergeRequestNumber, type RunItem } from './repository-setup';

describe('mergeRequestNumber', () => {
  it('reads /pull/N and /merge_requests/N and gives null for any other URL', () => {
    expect(mergeRequestNumber('https://github.com/acme/api/pull/7')).toBe('#7');
    expect(mergeRequestNumber('https://gitlab.example/acme/api/-/merge_requests/12/')).toBe('!12');
    expect(mergeRequestNumber('https://dev.azure.com/acme/p/_git/r/pullrequest/5')).toBeNull();
    expect(mergeRequestNumber('https://example.com/acme/api/issues/3')).toBeNull();
  });
});

describe('errorText', () => {
  const failed = (code: string, message: string) => ({ error: { code, message } }) as RunItem;

  it('tells a refused read from a refused change, by the server’s text', () => {
    expect(errorText(failed('refused', 'The provider refused the change'), 'GitHub')).toBe(
      'GitHub refused the change.',
    );
    const read = failed('refused', 'The provider refused a request to read the repository');
    expect(errorText(read, 'GitHub')).toBe('GitHub refused a request to read the repository.');
    expect(errorText(read, null)).toBe('The provider refused a request to read the repository.');
  });
});
