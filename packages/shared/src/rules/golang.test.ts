import { describe, expect, it } from 'vitest';
import {
  GO_MIN_VERSION,
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
