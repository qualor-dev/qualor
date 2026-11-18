import { describe, expect, it } from 'vitest';
import { muslProblem } from './musl';

const muslX64 = (p: string) => p === '/lib/ld-musl-x86_64.so.1';
const muslArm = (p: string) => p === '/lib/ld-musl-aarch64.so.1';
const nothing = () => false;

describe('muslProblem (B8, R20)', () => {
  it('stops the compiled binary on Linux when a musl loader exists', () => {
    const message = muslProblem({ platform: 'linux', compiled: true, exists: muslX64 });
    expect(message).toContain('glibc');
    expect(message).toContain('musl');
    expect(message).toContain('/lib/ld-musl-x86_64.so.1');
    expect(muslProblem({ platform: 'linux', compiled: true, exists: muslArm })).toContain(
      '/lib/ld-musl-aarch64.so.1',
    );
  });

  it('is null when the CLI is not the compiled binary', () => {
    expect(muslProblem({ platform: 'linux', compiled: false, exists: muslX64 })).toBeNull();
  });

  it('is null off Linux, and on a glibc Linux', () => {
    expect(muslProblem({ platform: 'darwin', compiled: true, exists: muslX64 })).toBeNull();
    expect(muslProblem({ platform: 'win32', compiled: true, exists: muslX64 })).toBeNull();
    expect(muslProblem({ platform: 'linux', compiled: true, exists: nothing })).toBeNull();
  });
});
