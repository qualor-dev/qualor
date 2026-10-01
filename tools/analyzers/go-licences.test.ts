import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { resolveBinary } from '../../cli/src/analyzers/binary';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { classify, parseBuildInfo } from './go-licences.mjs';

const NOTICE = 'deploy/scanner/licenses/GOSEC-THIRD-PARTY.txt';
const where = { root: process.cwd(), env: process.env };
const go = resolveBinary('go', where);
const gosec = resolveBinary('gosec', where);

describe('go-licences.mjs (plan 9C)', () => {
  it('reads the modules `go version -m` lists, replacements included', () => {
    const text = [
      '/b/gosec: go1.27.0',
      '\tpath\tgithub.com/securego/gosec/v2/cmd/gosec',
      '\tmod\tgithub.com/securego/gosec/v2\tv2.29.0\t',
      '\tdep\tgolang.org/x/mod\tv0.40.0\th1:x=',
      '\tmod\texample.com/self\t(devel)\t',
      '\tdep\texample.com/a\tv1.0.0',
      '\t=>\texample.com/b\tv1.1.0\th1:y=',
      '\tbuild\t-trimpath=true',
      '',
    ].join('\n');
    expect(parseBuildInfo(text)).toEqual([
      { path: 'github.com/securego/gosec/v2', version: 'v2.29.0' },
      { path: 'golang.org/x/mod', version: 'v0.40.0' },
      { path: 'example.com/b', version: 'v1.1.0' },
    ]);
  });

  it('recognises the permissive licences and nothing else', () => {
    expect(
      classify('                  Apache License\n            Version 2.0, January 2004'),
    ).toBe('Apache-2.0');
    expect(classify('Permission is hereby granted, free of charge, to any person')).toBe('MIT');
    expect(
      classify('Redistribution and use in source and binary forms … Neither the name of Google'),
    ).toBe('BSD-3-Clause');
    expect(classify('Redistribution and use in source and binary forms, with or without')).toBe(
      'BSD-2-Clause',
    );
    expect(classify('GNU GENERAL PUBLIC LICENSE Version 3')).toBeNull();
  });

  it.runIf(go !== null && gosec !== null)('names every module the installed gosec embeds', () => {
    const modules = parseBuildInfo(
      execFileSync(go as string, ['version', '-m', gosec as string], { encoding: 'utf8' }),
    ) as { path: string }[];
    const notice = readFileSync(NOTICE, 'utf8');
    const named = new Set([...notice.matchAll(/^={78}\n(\S+)@\S+ \(/gm)].map((m) => m[1]));
    for (const m of modules) expect(named.has(m.path), m.path).toBe(true);
    expect(notice).not.toMatch(/GNU (Lesser )?General Public License/);
  });
});
