import { describe, expect, it } from 'vitest';
import { detailLine, shown, stderrLines } from './reason';

describe('reason helpers', () => {
  it('shown: bounded, control characters replaced', () => {
    expect(shown('a\nb')).toBe('a?b');
    expect(shown('x'.repeat(300))).toHaveLength(200);
  });

  it('detailLine: one printable line of at most 300 characters', () => {
    expect(detailLine('  a\u001b[2Jb  ')).toBe('a [2Jb');
    expect(detailLine('y'.repeat(1000))).toHaveLength(300);
  });

  it("stderrLines: drops blank lines and the JVM's echo of its option variables (fix round 2)", () => {
    const stderr = [
      'Picked up JAVA_TOOL_OPTIONS: -Dhttp.proxyPassword=s3cret',
      'NOTE: Picked up JDK_JAVA_OPTIONS: -Dtoken=s3cret',
      'Picked up _JAVA_OPTIONS: -Xmx1g -Dpw=s3cret',
      '',
      '   ',
      'Error: the real reason',
      'Picked up JAVA_TOOL_OPTIONS in the middle is not the JVM echo',
      '',
    ].join('\r\n');
    expect(stderrLines(stderr)).toEqual([
      'Error: the real reason',
      'Picked up JAVA_TOOL_OPTIONS in the middle is not the JVM echo',
    ]);
    expect(stderrLines('')).toEqual([]);
  });
});
