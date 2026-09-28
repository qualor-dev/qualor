import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import {
  engine,
  file,
  finding,
  gzipDeeplyNestedArray,
  gzipJson,
  reportWith,
  sampleReport,
} from '../../test/reports';
import { decodeStoredReport, isDecodedTooLarge, MAX_JSON_DEPTH, stripNulDeep } from './decode';

const limits = { maxCompressedBytes: 1024 * 1024, maxDecompressedBytes: 1024 * 1024 };

describe('decodeStoredReport', () => {
  it('returns the validated report', () => {
    const result = decodeStoredReport(gzipJson(sampleReport()), limits);
    expect(result).toEqual({ ok: true, report: sampleReport() });
  });

  it('keeps a valid scm.gitlab, rejects a malformed one and drops unknown keys (scm.md §3)', () => {
    const at = (gitlab: unknown) => {
      const r = sampleReport();
      return gzipJson({ ...r, scm: { ...r.scm, gitlab } });
    };
    const good = { projectId: '4711', pipelineId: '99001', mergeRequestEventType: 'detached' };
    const kept = decodeStoredReport(at(good), limits);
    if (!kept.ok) throw new Error('expected success');
    expect(kept.report.scm.gitlab).toEqual(good);
    // A report from an older CLI (no scm.gitlab) is still accepted, without the field.
    const old = decodeStoredReport(gzipJson(sampleReport()), limits);
    if (!old.ok) throw new Error('expected success');
    expect(old.report.scm).not.toHaveProperty('gitlab');
    // Extra keys (a token a hostile CLI adds) never reach the server's report.
    const extra = decodeStoredReport(at({ ...good, jobToken: 'glcbt-SECRET' }), limits);
    if (!extra.ok) throw new Error('expected success');
    expect(JSON.stringify(extra.report)).not.toContain('SECRET');
    for (const bad of [
      { projectId: '1 OR 1=1' },
      { pipelineId: '9'.repeat(21) },
      { projectId: 4711 },
      { mergeRequestEventType: 'push' },
      'detached',
    ]) {
      const result = decodeStoredReport(at(bad), limits);
      if (result.ok) throw new Error(`expected a failure for ${JSON.stringify(bad)}`);
      expect(result.error.errors?.[0]?.path).toMatch(/^scm\.gitlab/);
    }
  });

  it('reports malformed JSON and an undecompressable body as REPORT_INVALID', () => {
    expect(decodeStoredReport(gzipSync(Buffer.from('{"schemaVersion":')), limits)).toEqual({
      ok: false,
      error: { code: 'REPORT_INVALID', message: 'The report is not valid JSON' },
    });
    expect(decodeStoredReport(Buffer.from('not gzip'), limits)).toMatchObject({
      ok: false,
      error: { code: 'REPORT_INVALID' },
    });
  });

  it('names the supported schemaVersion range', () => {
    const result = decodeStoredReport(gzipJson({ ...sampleReport(), schemaVersion: 2 }), limits);
    expect(result).toEqual({
      ok: false,
      error: {
        code: 'REPORT_INVALID',
        message: 'Unsupported schemaVersion; this server accepts 1..1',
        errors: [{ path: 'schemaVersion', message: 'Unsupported schemaVersion' }],
      },
    });
  });

  it('lists schema violations with dotted paths, capped at 100', () => {
    const bad = sampleReport();
    bad.findings = Array.from({ length: 150 }, () => ({
      ...bad.findings[0]!,
      location: { path: 'src/missing.ts', startLine: 1 },
    }));
    const result = decodeStoredReport(gzipJson(bad), limits);
    if (result.ok) throw new Error('expected a failure');
    expect(result.error.code).toBe('REPORT_INVALID');
    expect(result.error.errors).toHaveLength(100);
    expect(result.error.errors![0]).toEqual({
      path: 'findings.0.location.path',
      message: 'location.path is not listed in files[]',
    });
  });

  it('refuses a stored body that inflates past the limit', () => {
    const result = decodeStoredReport(gzipJson(sampleReport()), {
      maxCompressedBytes: 1024,
      maxDecompressedBytes: 64,
    });
    expect(result).toMatchObject({ ok: false, error: { code: 'REPORT_TOO_LARGE' } });
  });

  it('classifies a too-long-string error the same as a too-large-buffer error (ruling S13 #3)', () => {
    // Actually triggering V8's own ~500 MiB+ string ceiling would need a multi-hundred-MiB
    // allocation in a unit test; exercise the classification predicate directly instead.
    expect(
      isDecodedTooLarge(Object.assign(new RangeError('x'), { code: 'ERR_STRING_TOO_LONG' })),
    ).toBe(true);
    expect(isDecodedTooLarge(Object.assign(new Error('x'), { code: 'ERR_BUFFER_TOO_LARGE' }))).toBe(
      true,
    );
    expect(isDecodedTooLarge(new Error('some other zlib failure'))).toBe(false);
    expect(isDecodedTooLarge('not even an object')).toBe(false);
  });

  it('strips U+0000 from every string in the report, including a rule id, metadata, a message and a properties key, before validating it (ruling U4)', () => {
    const dirty = reportWith({
      engines: [engine('eslint', [{ id: 'a\u0000b', name: 'Rule\u0000Name' }])],
      files: [file('src/a.ts')],
      findings: [
        {
          ...finding({ ruleId: 'a\u0000b', line: 1 }),
          message: 'bad thing\u0000 happened',
          properties: { 'a\u0000b': 'c\u0000d' },
        },
      ],
    });
    const result = decodeStoredReport(gzipJson(dirty), limits);
    if (!result.ok) throw new Error(`expected ok, got ${JSON.stringify(result.error)}`);
    expect(result.report.engines[0]!.rules[0]).toMatchObject({ id: 'ab', name: 'RuleName' });
    expect(result.report.findings[0]).toMatchObject({
      ruleId: 'ab',
      message: 'bad thing happened',
      properties: { ab: 'cd' },
    });
  });

  it('rejects a report nested far past any real report as REPORT_INVALID, without retrying (ruling U4 fix round 2)', () => {
    // Built by string concatenation, never JSON.stringify or recursion on our own part, so the
    // test itself does not depend on this depth being safe to build recursively — only on
    // JSON.parse accepting it (which V8 does far past this) and stripNulDeep then rejecting it.
    const result = decodeStoredReport(gzipDeeplyNestedArray(5_000), limits);
    expect(result).toEqual({
      ok: false,
      error: { code: 'REPORT_INVALID', message: 'The report is nested too deeply' },
    });
  });

  it('logs a caught parse/depth failure at debug, with no report content, when given a logger (ruling U4 fix round 3)', () => {
    const debugCalls: unknown[][] = [];
    const warnCalls: unknown[][] = [];
    const logger = {
      debug: (...args: unknown[]) => debugCalls.push(args),
      warn: (...args: unknown[]) => warnCalls.push(args),
    };

    const notJson = decodeStoredReport(gzipSync(Buffer.from('not json at all')), limits, logger);
    expect(notJson).toMatchObject({ ok: false, error: { code: 'REPORT_INVALID' } });
    expect(debugCalls).toHaveLength(1);
    expect(debugCalls[0]?.[0]).toEqual({ errorType: 'SyntaxError' });
    // Never the report body/text itself, only the error's own type.
    expect(JSON.stringify(debugCalls[0])).not.toContain('not json at all');

    const tooDeep = decodeStoredReport(gzipDeeplyNestedArray(5_000), limits, logger);
    expect(tooDeep).toMatchObject({ ok: false, error: { code: 'REPORT_INVALID' } });
    expect(debugCalls).toHaveLength(2);
    expect(debugCalls[1]?.[0]).toEqual({ errorType: 'JsonTooDeepError' });
    expect(warnCalls).toHaveLength(0);

    // Omitting the logger (every other test above does) is still fully supported.
    expect(() => decodeStoredReport(Buffer.from('not gzip'), limits)).not.toThrow();
  });
});

describe('stripNulDeep', () => {
  it('strips U+0000 from strings, including object keys, recursively through arrays and objects', () => {
    expect(
      stripNulDeep({
        a: 'x\u0000y',
        'k\u0000ey': ['p\u0000q', { nested: 'r\u0000s' }],
        n: null,
        num: 1,
        bool: true,
      }),
    ).toEqual({ a: 'xy', key: ['pq', { nested: 'rs' }], n: null, num: 1, bool: true });
  });

  it('returns the exact same reference when nothing anywhere needs stripping (no copy at all)', () => {
    const value = { a: 'plain', b: [1, 2, { c: 'also plain' }] };
    expect(stripNulDeep(value)).toBe(value);
  });

  it('only clones a container with something changed beneath it; an untouched subtree comes back by reference', () => {
    const cleanNested = { c: 'also plain' };
    const cleanArray = [1, 2, cleanNested];
    const value = { a: 'x\u0000y', b: cleanArray };
    const result = stripNulDeep(value) as { a: string; b: unknown[] };
    expect(result).not.toBe(value);
    expect(result).toEqual({ a: 'xy', b: [1, 2, { c: 'also plain' }] });
    expect(result.b).toBe(cleanArray);
    expect(result.b[2]).toBe(cleanNested);
  });

  it('resolves two keys that collide once U+0000 is stripped as last-write-wins, in report order — the same rule JSON.parse itself applies to two literally identical keys', () => {
    expect(stripNulDeep({ ab: 1, 'a\u0000b': 2 })).toEqual({ ab: 2 });
    // Order shouldn't matter: whichever key comes last in the source wins, NUL or not.
    expect(stripNulDeep({ 'a\u0000b': 1, ab: 2 })).toEqual({ ab: 2 });
    expect(Object.keys(stripNulDeep({ ab: 1, 'a\u0000b': 2 }) as object)).toEqual(['ab']);
  });

  it('rejects nesting past MAX_JSON_DEPTH without native recursion (an iterative walk, an explicit stack)', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < MAX_JSON_DEPTH + 1; i += 1) deep = [deep];
    expect(() => stripNulDeep(deep)).toThrow();
    let shallow: unknown = 'leaf';
    for (let i = 0; i < MAX_JSON_DEPTH; i += 1) shallow = [shallow];
    expect(() => stripNulDeep(shallow)).not.toThrow();
  });

  it('never lets a "__proto__" key pollute a clone\'s prototype — an object value would otherwise replace it, a primitive would otherwise vanish (ruling U4 fix round 3)', () => {
    // Built with JSON.parse, exactly how stripNulDeep's real input always arrives: unlike a JS
    // object literal's own `__proto__: value` syntax, and unlike `obj[key] = value`, JSON.parse
    // makes "__proto__" an ordinary own property, per spec, never touching the actual prototype —
    // so this is a faithful stand-in for a report that carries the key in `properties` or
    // `partialFingerprints`.
    const objectValue = JSON.parse('{"other":"a\\u0000b","__proto__":{"polluted":true}}') as Record<
      string,
      unknown
    >;
    expect(Object.getPrototypeOf(objectValue)).toBe(Object.prototype); // sanity: not already polluted
    const result = stripNulDeep(objectValue) as Record<string, unknown>;
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(Object.keys(result).sort()).toEqual(['__proto__', 'other']);
    expect(result.other).toBe('ab');
    expect(result['__proto__']).toEqual({ polluted: true });
    // JSON.stringify only serialises OWN enumerable properties; if "__proto__" had instead become
    // the clone's actual prototype (the bug), it would be entirely absent from this output.
    expect(JSON.parse(JSON.stringify(result))).toEqual(
      JSON.parse('{"other":"ab","__proto__":{"polluted":true}}'),
    );

    // The primitive-value sub-case: the inherited accessor's setter silently drops a non-object,
    // non-null assignment instead of ever creating an own property.
    const primitiveValue = JSON.parse('{"other":"c\\u0000d","__proto__":42}') as Record<
      string,
      unknown
    >;
    const result2 = stripNulDeep(primitiveValue) as Record<string, unknown>;
    expect(Object.getPrototypeOf(result2)).toBe(Object.prototype);
    expect(result2['__proto__']).toBe(42);
    expect(Object.keys(result2).sort()).toEqual(['__proto__', 'other']);

    // "__proto__" first, unchanged, and only a later sibling forces the clone: this exercises the
    // lazy backfill copy (of entries seen before the change), not just the live-write sites above.
    const protoFirst = JSON.parse('{"__proto__":{"polluted":true},"other":"e\\u0000f"}') as Record<
      string,
      unknown
    >;
    const result3 = stripNulDeep(protoFirst) as Record<string, unknown>;
    expect(Object.getPrototypeOf(result3)).toBe(Object.prototype);
    expect(result3['__proto__']).toEqual({ polluted: true });
    expect(result3.other).toBe('ef');
  });

  it('leaves a clean object containing a "__proto__" key untouched (nothing to clone, so no risk)', () => {
    const value = JSON.parse('{"a":"plain","__proto__":{"x":1}}') as Record<string, unknown>;
    expect(stripNulDeep(value)).toBe(value);
  });
});
