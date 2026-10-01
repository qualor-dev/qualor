import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const pin = (name: string) =>
  new RegExp(`^${name}=(.+)$`, 'm').exec(
    readFileSync('tools/analyzers/install-go.sh', 'utf8'),
  )?.[1];

describe('the Go toolchain in NOTICE.md (plan 9C)', () => {
  it('names Go, staticcheck and gosec at the pinned versions, with their licence files', () => {
    const notice = readFileSync('deploy/scanner/NOTICE.md', 'utf8');
    for (const s of [
      `| Go `,
      `| ${pin('GO_VERSION')} `,
      `| ${pin('STATICCHECK_VERSION')} `,
      `| ${pin('GOSEC_VERSION')} `,
      'GO-LICENSE.txt',
      'STATICCHECK-LICENSE.txt',
      'GOSEC-LICENSE.txt',
      'GOSEC-THIRD-PARTY.txt',
      'tree-sitter-go',
    ]) {
      expect(notice, s).toContain(s);
    }
  });

  it('keeps the licence files of the pinned releases', () => {
    const read = (f: string) => readFileSync(`deploy/scanner/licenses/${f}`, 'utf8');
    expect(read('GO-LICENSE.txt')).toContain('Copyright 2009 The Go Authors.');
    expect(read('GO-LICENSE.txt')).toContain('Additional IP Rights Grant (Patents)');
    expect(read('STATICCHECK-LICENSE.txt')).toContain('Copyright (c) 2016 Dominik Honnef');
    expect(read('GOSEC-LICENSE.txt')).toContain('Apache License');
    expect(read('GOSEC-THIRD-PARTY.txt')).toContain(
      `github.com/securego/gosec/v2@v${pin('GOSEC_VERSION')}`,
    );
  });
});
