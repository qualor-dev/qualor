import { errorText, type RunItem } from './repository-setup';

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
