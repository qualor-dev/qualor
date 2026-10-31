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
    expect(label('language', 'go')).toBe('Go');
    expect(label('language', 'c')).toBe('C');
    expect(label('language', 'cpp')).toBe('C++');
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

  it('names the qualor engine "Qualor" and the ai engine "AI review", and leaves every other engine id as it is (plan 6B-1, 6I-3)', () => {
    expect(label('engine', 'qualor')).toBe('Qualor');
    expect(label('engine', 'ai')).toBe('AI review');
    expect(label('engine', 'spotbugs')).toBe('spotbugs');
    expect(label('engine', 'ext-osv')).toBe('ext-osv');
  });

  it('never returns an inherited member for an engine id such as "constructor"', () => {
    expect(label('engine', 'constructor')).toBe('constructor');
    expect(label('engine', '__proto__')).toBe('__proto__');
    expect(label('engine', 'toString')).toBe('toString');
  });

  it('names the licensing quality, its metrics and the licence groups (6M)', () => {
    expect(label('quality', 'licensing')).toBe('Licensing');
    expect(label('metric', 'licensing_issues')).toBe('Licensing issues');
    expect(label('metric', 'new_licensing_issues')).toBe('Licensing issues on new code');
    expect(label('metric', 'forbidden_licenses')).toBe('Forbidden licences');
    expect(label('metric', 'new_forbidden_licenses')).toBe('Forbidden licences on new code');
    expect(label('metric', 'unknown_licenses_ratio')).toBe('Unknown licences');
    expect(label('licenseGroup', 'strong-copyleft')).toBe('Strong copyleft');
    expect(label('licenseGroup', 'non-commercial-or-source-available')).toBe(
      'Non-commercial or source-available',
    );
    expect(label('verdict', 'forbidden')).toBe('Forbidden');
  });

  it('names vulnerability severities, decision statuses and VEX reasons (vuln 2b)', () => {
    expect(label('vulnSeverity', 'critical')).toBe('Critical');
    expect(label('vulnSeverity', 'high')).toBe('High');
    expect(label('vulnSeverity', 'medium')).toBe('Medium');
    expect(label('vulnSeverity', 'low')).toBe('Low');
    expect(label('vulnSeverity', 'unknown')).toBe('Unknown');
    expect(label('decisionStatus', 'open')).toBe('Open');
    expect(label('decisionStatus', 'false_positive')).toBe('Not affected');
    expect(label('decisionStatus', 'wont_fix')).toBe("Won't fix");
    expect(label('vexReason', 'component_not_present')).toBe('The package is not in the build');
    expect(label('vexReason', 'vulnerable_code_not_present')).toBe(
      'The vulnerable code is not in the build',
    );
    expect(label('vexReason', 'vulnerable_code_not_in_execute_path')).toBe(
      'The vulnerable code is never called',
    );
    expect(label('vexReason', 'vulnerable_code_cannot_be_controlled_by_adversary')).toBe(
      'An attacker cannot control the input',
    );
    expect(label('vexReason', 'inline_mitigations_already_exist')).toBe(
      'Another control already protects it',
    );
  });

  it('falls back to the raw value for an unknown value, and to empty for none', () => {
    expect(label('severity', 'catastrophic')).toBe('catastrophic');
    expect(label('metric', 'new_mystery')).toBe('mystery on new code');
    expect(label('status', null)).toBe('');
  });
});
