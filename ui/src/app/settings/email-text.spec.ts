import { messageKindText } from './email-text';

describe('messageKindText', () => {
  it('names the vulnerability emails', () => {
    expect(messageKindText('notify.vulnerabilities-digest')).toBe('Vulnerability digest');
    expect(messageKindText('notify.vulnerabilities-exploited')).toBe('Exploited vulnerability');
  });
  it('falls back to the raw kind', () => {
    expect(messageKindText('something.else')).toBe('something.else');
  });
});
