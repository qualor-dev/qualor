import { describe, expect, it } from 'vitest';
import {
  FINDSECBUGS_PATTERNS,
  FINDSECBUGS_TABLE_VERSION,
  FINDSECBUGS_VERSION,
  findsecbugsPattern,
  findsecbugsSeverity,
} from './findsecbugs';

describe('the FindSecBugs pattern table (plan 6A, decision M1)', () => {
  it('describes the bundled plugin version', () => {
    expect(FINDSECBUGS_TABLE_VERSION).toBe(FINDSECBUGS_VERSION);
    expect(FINDSECBUGS_PATTERNS.size).toBeGreaterThan(0);
  });

  it('follows the principle: issue exactly for taint and misuse, with the severities of its basis', () => {
    for (const [id, p] of FINDSECBUGS_PATTERNS) {
      expect(p.kind === 'issue', id).toBe(p.basis === 'taint' || p.basis === 'misuse');
      if (p.kind === 'issue') expect(['high', 'medium'], id).toContain(p.severity);
      if (p.basis === 'review') expect(['medium', 'low'], id).toContain(p.severity);
      if (p.basis === 'source') expect(p.severity, id).toBe('low');
      if (p.basis === 'endpoint') expect(p.severity, id).toBe('info');
    }
  });

  it('keeps the examples of decision M1', () => {
    for (const id of [
      'SQL_INJECTION_JDBC',
      'COMMAND_INJECTION',
      'PATH_TRAVERSAL_IN',
      'XXE_DOCUMENT',
    ]) {
      expect(findsecbugsPattern(id)?.kind, id).toBe('issue');
    }
    for (const id of [
      'SPRING_ENDPOINT',
      'INSECURE_COOKIE',
      'HTTPONLY_COOKIE',
      'PREDICTABLE_RANDOM',
      'PERMISSIVE_CORS',
      'WEAK_MESSAGE_DIGEST_MD5',
      'SSL_CONTEXT',
    ]) {
      expect(findsecbugsPattern(id)?.kind, id).toBe('hotspot');
    }
  });

  it('names no core SpotBugs pattern and answers undefined for an unknown id', () => {
    for (const id of [
      'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
      'DMI_CONSTANT_DB_PASSWORD',
      'PT_RELATIVE_PATH_TRAVERSAL',
      'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER',
    ]) {
      expect(findsecbugsPattern(id), id).toBeUndefined();
    }
    expect(findsecbugsPattern('__proto__')).toBeUndefined();
    expect(findsecbugsPattern('A_PATTERN_OF_ANOTHER_VERSION')).toBeUndefined();
  });

  it('lowers the severity one step for a result at SARIF note, never below info', () => {
    const sqli = findsecbugsPattern('SQL_INJECTION_JDBC')!;
    const source = findsecbugsPattern('SERVLET_PARAMETER')!;
    const endpoint = findsecbugsPattern('SPRING_ENDPOINT')!;
    expect(findsecbugsSeverity(sqli, 'warning')).toBe('high');
    expect(findsecbugsSeverity(sqli, 'error')).toBe('high');
    expect(findsecbugsSeverity(sqli, undefined)).toBe('high');
    expect(findsecbugsSeverity(sqli, 'note')).toBe('medium');
    expect(findsecbugsSeverity(source, 'note')).toBe('info');
    expect(findsecbugsSeverity(endpoint, 'note')).toBe('info');
  });
});
