import { label } from './labels';

describe('label', () => {
  it('maps enum values to their English labels', () => {
    expect(label('severity', 'blocker')).toBe('Blocker');
    expect(label('status', 'wont_fix')).toBe("Won't fix");
    expect(label('gate', 'none')).toBe('No gate');
    expect(label('language', '*')).toBe('Other engines');
    expect(label('language', 'kotlin')).toBe('Kotlin');
    expect(label('language', 'swift')).toBe('Swift');
    expect(label('language', 'php')).toBe('PHP');
    expect(label('language', 'ruby')).toBe('Ruby');
    expect(label('gateWarning', 'NEW_CODE_DEFINITION_FALLBACK')).toBe(
      'No earlier version was found for the new-code baseline; the last 30 days are new code instead.',
    );
    expect(label('gateWarning', 'SOMETHING_NEWER')).toBe('SOMETHING_NEWER');
  });

  it('names the single sign-on protocols', () => {
    expect(label('ssoProtocol', 'oidc')).toBe('OpenID Connect');
    expect(label('ssoProtocol', 'saml')).toBe('SAML');
  });

  it('labels new-code metrics from their base metric', () => {
    expect(label('metric', 'coverage')).toBe('Coverage');
    expect(label('metric', 'new_coverage')).toBe('Coverage on new code');
  });

  it('falls back to the raw value for an unknown value, and to empty for none', () => {
    expect(label('severity', 'catastrophic')).toBe('catastrophic');
    expect(label('metric', 'new_mystery')).toBe('mystery on new code');
    expect(label('status', null)).toBe('');
  });
});
