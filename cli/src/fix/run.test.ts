import type { FixLockfile } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { targetRuleProblem, type TargetFields } from './run';

const TARGET = { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' };
const LINE: FixLockfile = {
  path: 'package-lock.json',
  relation: 'direct',
  mechanism: null,
  dependents: [],
};
const js: TargetFields = {
  targets: [TARGET],
  lockfiles: [LINE],
  targetVersion: '1.2.6',
  installedVersion: '1.2.5',
};
const JS_FILES = ['package.json', 'package-lock.json'];

describe('targetRuleProblem (rulings T9c, T9i: the server’s target rules, checked before the upload)', () => {
  it('passes an upload whose targets agree with its files', () => {
    expect(targetRuleProblem('js', js, JS_FILES)).toBeNull();
  });

  it('refuses an upload without targets', () => {
    expect(targetRuleProblem('js', { ...js, targets: [] }, JS_FILES)).toEqual({
      rule: 'no_targets',
      path: '',
    });
  });

  it('refuses a target at or below its installed version', () => {
    for (const target of ['1.2.5', '1.2.4']) {
      const at = { ...js, targets: [{ ...TARGET, target }], targetVersion: target };
      expect(targetRuleProblem('js', at, JS_FILES)).toEqual({
        rule: 'target_mismatch',
        path: 'package-lock.json',
      });
    }
  });

  it('refuses a target or a lockfile line whose file is not uploaded', () => {
    expect(targetRuleProblem('js', js, ['package.json'])).toEqual({
      rule: 'target_mismatch',
      path: 'package-lock.json',
    });
    const line = {
      ...js,
      lockfiles: [...js.lockfiles, { ...LINE, path: 'apps/a/package-lock.json' }],
    };
    expect(targetRuleProblem('js', line, JS_FILES)).toEqual({
      rule: 'target_mismatch',
      path: 'apps/a/package-lock.json',
    });
  });

  it('refuses an uploaded lockfile no target names; a go.sum counts through the go.mod beside it', () => {
    expect(targetRuleProblem('js', js, [...JS_FILES, 'apps/a/package-lock.json'])).toEqual({
      rule: 'target_mismatch',
      path: 'apps/a/package-lock.json',
    });
    const go: TargetFields = {
      targets: [{ installed: 'v1.2.5', target: 'v1.2.6', lockfile: 'svc/go.mod' }],
      lockfiles: [{ path: 'svc/go.mod', relation: 'direct', mechanism: null, dependents: [] }],
      targetVersion: 'v1.2.6',
      installedVersion: 'v1.2.5',
    };
    expect(targetRuleProblem('go', go, ['svc/go.mod', 'svc/go.sum'])).toBeNull();
    expect(targetRuleProblem('go', go, ['svc/go.mod', 'svc/go.sum', 'other/go.sum'])).toEqual({
      rule: 'target_mismatch',
      path: 'other/go.sum',
    });
  });

  it('refuses a targetVersion that is not the greatest target, or an installedVersion of no such target', () => {
    const two: TargetFields = {
      ...js,
      targets: [
        { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
        { installed: '2.0.1', target: '2.0.3', lockfile: 'package-lock.json' },
      ],
      targetVersion: '2.0.3',
      installedVersion: '2.0.1',
    };
    expect(targetRuleProblem('js', two, JS_FILES)).toBeNull();
    expect(targetRuleProblem('js', { ...two, targetVersion: '1.2.6' }, JS_FILES)).toEqual({
      rule: 'target_mismatch',
      path: '',
    });
    expect(targetRuleProblem('js', { ...two, installedVersion: '1.2.5' }, JS_FILES)).toEqual({
      rule: 'target_mismatch',
      path: '',
    });
  });
});
