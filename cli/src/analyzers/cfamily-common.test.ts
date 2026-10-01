import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { OUTSIDE_PLACEHOLDER, redactForeignPaths } from './cfamily-common';

const ROOT = path.resolve('/repo');
const REAL = path.resolve('/real/repo');
const O = OUTSIDE_PLACEHOLDER;

describe('redactForeignPaths (ruling D9-11)', () => {
  it('replaces absolute paths outside the bases and makes paths inside them relative', () => {
    expect(
      redactForeignPaths("'/usr/include/host-secret.h' file not found, see /repo/src/a.h:3:5.", [
        ROOT,
        REAL,
      ]),
    ).toBe(`'${O}' file not found, see src/a.h:3:5.`);
    expect(
      redactForeignPaths('included from /real/repo/include/x.h and /opt/ci/y.h', [ROOT, REAL]),
    ).toBe(`included from include/x.h and ${O}`);
    expect(redactForeignPaths('the root /repo itself; /repository/x is not inside', [ROOT])).toBe(
      `the root . itself; ${O} is not inside`,
    );
    expect(redactForeignPaths('a path that leaves: /repo/../etc/passwd', [ROOT])).toBe(
      `a path that leaves: ${O}`,
    );
  });

  it('redacts Windows paths, and leaves relative paths, operators, numbers and URLs alone', () => {
    expect(redactForeignPaths('header C:\\Users\\ci\\secret.h (C:/tools/x.h)', [ROOT])).toBe(
      `header ${O} (${O})`,
    );
    const plain =
      "Division by zero in 'a / z', 1/0, operator/=, src/a.h, ./b.h, see https://clang.llvm.org/x/y and 'x'";
    expect(redactForeignPaths(plain, [ROOT])).toBe(plain);
  });
});
