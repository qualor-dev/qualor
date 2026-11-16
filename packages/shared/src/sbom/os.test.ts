import { describe, expect, it } from 'vitest';
import {
  isOsPackageType,
  OS_FAMILY_ALIASES,
  osFamilyOf,
  sameOsVersion,
  TRIVY_OS_FAMILIES,
  TRIVY_RELEASE_MAJORS,
  trivyChecksRelease,
} from './os';

describe('osFamilyOf', () => {
  it.each([
    ['rhel', 'redhat'],
    ['almalinux', 'alma'],
    ['amzn', 'amazon'],
    ['ol', 'oracle'],
    ['mariner', 'cbl-mariner'],
    ['Debian', 'debian'],
    ['ubuntu', 'ubuntu'],
    ['opensuse-leap', 'opensuse-leap'],
  ])('%s is %s', (raw, family) => {
    expect(osFamilyOf(raw)).toEqual({ family, known: true });
  });

  it('keeps an unknown name, lowercased', () => {
    expect(osFamilyOf('plan9')).toEqual({ family: 'plan9', known: false });
    expect(osFamilyOf('Plan9')).toEqual({ family: 'plan9', known: false });
  });

  it('is not fooled by prototype names', () => {
    expect(osFamilyOf('constructor')).toEqual({ family: 'constructor', known: false });
  });

  it('maps only to Trivy families', () => {
    for (const family of Object.values(OS_FAMILY_ALIASES)) {
      expect(TRIVY_OS_FAMILIES.has(family), family).toBe(true);
    }
  });
});

describe('trivyChecksRelease (R29)', () => {
  it.each([
    ['redhat', '6.10', true],
    ['redhat', '9.4', true],
    ['redhat', '10.0', false],
    ['redhat', '5', false],
    ['redhat', '', false],
    ['redhat', 'x', false],
    ['redhat', '09', false],
    ['centos', '7.9.2009', true],
    ['centos', '10', false],
    ['debian', '13', true],
    ['rocky', '10.0', true],
    ['plan9', '1', true],
  ])('%s %s: %s', (family, version, checked) => {
    expect(trivyChecksRelease(family, version)).toBe(checked);
  });

  it('names only Trivy families', () => {
    for (const family of Object.keys(TRIVY_RELEASE_MAJORS)) {
      expect(TRIVY_OS_FAMILIES.has(family), family).toBe(true);
    }
  });
});

describe('sameOsVersion', () => {
  it.each([
    ['12', '12.15'],
    ['12.15', '12'],
    ['3.20', '3.20.3'],
    ['12', '12'],
  ])('%s and %s are the same', (a, b) => {
    expect(sameOsVersion(a, b)).toBe(true);
  });
  it.each([
    ['11', '12'],
    ['12.1', '12.15'],
    ['1', '10'],
  ])('%s and %s differ', (a, b) => {
    expect(sameOsVersion(a, b)).toBe(false);
  });
});

describe('isOsPackageType', () => {
  it('knows deb, rpm and apk', () => {
    expect(['deb', 'rpm', 'apk', 'npm'].map(isOsPackageType)).toEqual([true, true, true, false]);
  });
});
