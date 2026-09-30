import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * What swiftlint-static links (Verified facts F6 of plan 8F, plus musl-fts, which Foundation
 * autolinks and the binary contains): each has a section in SWIFTLINT-THIRD-PARTY-NOTICES.txt,
 * headed by a line of 78 `=` and then `<name> (<licence>)`.
 */
export const SWIFTLINT_COMPONENTS = [
  'SourceKitten',
  'Yams',
  'swift-syntax',
  'swift-argument-parser',
  'CollectionConcurrencyKit',
  'CryptoSwift',
  'swift-filename-matcher',
  'SwiftyTextTable',
  'SWXMLHash',
  'Swift runtime and standard library',
  'swift-corelibs-foundation',
  'swift-foundation',
  'swift-foundation-icu',
  'swift-corelibs-libdispatch',
  'LLVM libc++, libc++abi, libunwind and compiler-rt',
  'musl',
  'musl-fts',
  'curl',
  'BoringSSL',
  'libxml2',
  'zlib',
] as const;

const read = (f: string) => readFileSync(`deploy/scanner/licenses/${f}`, 'utf8');

describe('SwiftLint licence files (plan 8F)', () => {
  it("ship SwiftLint's own MIT licence and mimalloc's, as the release zip has them", () => {
    const text = read('SWIFTLINT-LICENSE.txt');
    expect(text).toContain('Copyright (c) 2025 The SwiftLint Contributors.');
    expect(text).toContain('Copyright (c) 2018-2025 Microsoft Corporation, Daan Leijen');
  });

  it('name every component linked into swiftlint-static with a licence text', () => {
    const text = read('SWIFTLINT-THIRD-PARTY-NOTICES.txt');
    const headers = [...text.matchAll(/^={78}\n(.+) \((.+)\)$/gm)].map((m) => m[1]);
    expect(headers).toEqual([...SWIFTLINT_COMPONENTS]);
    for (const copyleft of [
      /\bGNU (Lesser )?General Public License\b/,
      /\bMozilla Public License\b/,
    ]) {
      expect(text).not.toMatch(copyleft);
    }
    expect(text).toContain(
      'This product includes software developed by the "Marcin Krzyzanowski" (http://krzyzanowskim.com/).',
    );
  });

  it('say where each text comes from: a tag or commit, never a moving branch (ruling F20)', () => {
    const text = read('SWIFTLINT-THIRD-PARTY-NOTICES.txt');
    const sources = [...text.matchAll(/^={78}\n.+\nSource: (\S+)/gm)].map((m) => m[1]);
    expect(sources).toHaveLength(SWIFTLINT_COMPONENTS.length);
    for (const url of sources) {
      expect(url).toMatch(/^https:\/\//);
      expect(url).not.toMatch(/\/(main|master|HEAD)\/|[?&]h=(main|master)\b/);
    }
    // BoringSSL at the commit the Swift 6.3.2 static SDK builds: OpenSSL/SSLeay and ISC terms.
    expect(text).toContain('/google/boringssl/817ab07ebb53da35afea409ab9328f578492832d/LICENSE');
  });
});
