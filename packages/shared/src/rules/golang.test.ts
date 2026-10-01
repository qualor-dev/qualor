import { describe, expect, it } from 'vitest';
import {
  GO_MIN_VERSION,
  GO_RULES_TABLE,
  GO_VERSION,
  GOSEC_DEFAULT_EXCLUDE,
  GOSEC_RULES,
  GOVET_ANALYZERS,
  STATICCHECK_CHECKS,
  gosecSeverity,
  govetRule,
  staticcheckRule,
  GOSEC_VERSION,
  goVersionSupported,
  gosecVersionSupported,
  STATICCHECK_VERSION,
  staticcheckVersionSupported,
} from './golang';

const parts = (v: string) => v.split('.').map(Number) as [number, number, number];

describe('the Go version policy (config.md §6, plan 9C)', () => {
  it('runs a go of GO_MIN_VERSION or newer, release candidates included', () => {
    const [major, minor] = parts(GO_MIN_VERSION);
    expect(goVersionSupported(`${major}.${minor}`)).toBe(true);
    expect(goVersionSupported(`${major}.${minor}.7`)).toBe(true);
    expect(goVersionSupported(`${major}.${minor + 3}rc1`)).toBe(true);
    expect(goVersionSupported(`${major}.${minor - 1}.9`)).toBe(false);
    expect(goVersionSupported('devel')).toBe(false);
  });

  it('runs every patch of the pinned staticcheck year.minor and gosec major.minor, nothing else', () => {
    const [y, m] = parts(STATICCHECK_VERSION);
    expect(staticcheckVersionSupported(STATICCHECK_VERSION)).toBe(true);
    expect(staticcheckVersionSupported(`${y}.${m}.9`)).toBe(true);
    expect(staticcheckVersionSupported(`${y}.${m + 1}.0`)).toBe(false);
    expect(staticcheckVersionSupported(`${y - 1}.${m}.0`)).toBe(false);
    const [g, n] = parts(GOSEC_VERSION);
    expect(gosecVersionSupported(GOSEC_VERSION)).toBe(true);
    expect(gosecVersionSupported(`${g}.${n}.4`)).toBe(true);
    expect(gosecVersionSupported(`${g}.${n - 1}.0`)).toBe(false);
    expect(gosecVersionSupported('')).toBe(false);
  });
});

describe('the Go rule tables and their mapping (report-format.md §7.1, plan 9C)', () => {
  it('describe the pinned tools', () => {
    expect(GO_RULES_TABLE).toEqual({
      go: GO_VERSION,
      staticcheck: STATICCHECK_VERSION,
      gosec: GOSEC_VERSION,
    });
    for (const id of ['SA5009', 'SA4000', 'S1002', 'U1000'])
      expect(STATICCHECK_CHECKS.has(id), id).toBe(true);
    for (const a of ['printf', 'copylocks', 'bools', 'unreachable'])
      expect(GOVET_ANALYZERS.has(a), a).toBe(true);
    for (const g of [...GOSEC_DEFAULT_EXCLUDE, 'G401', 'G501'])
      expect(GOSEC_RULES.has(g), g).toBe(true);
  });

  it('grades staticcheck by check family', () => {
    expect(staticcheckRule('SA5009')).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(staticcheckRule('SA2000')).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(staticcheckRule('SA4000')).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(staticcheckRule('SA1019')).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(staticcheckRule('SA6002')).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(staticcheckRule('U1000')).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    for (const id of ['S1002', 'ST1003', 'QF1001', 'compile', '']) {
      expect(staticcheckRule(id), id).toEqual({
        quality: 'maintainability',
        kind: 'issue',
        defaultSeverity: 'low',
      });
    }
  });

  it('grades go vet as reliability, unkeyed fields as style', () => {
    expect(govetRule('printf')).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(govetRule('composites')).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
  });

  it("takes gosec's severity from its rule's tag", () => {
    expect(gosecSeverity(['security', 'HIGH'])).toBe('high');
    expect(gosecSeverity(['security', 'MEDIUM'])).toBe('medium');
    expect(gosecSeverity(['security', 'LOW'])).toBe('low');
    expect(gosecSeverity([])).toBe('medium');
  });
});
