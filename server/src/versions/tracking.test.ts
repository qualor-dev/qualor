import { describe, expect, it } from 'vitest';
import { computeTracking, type TrackingInput, type VersionRule } from './tracking';

function v(label: string, tracking: TrackingInput['tracking'] = 'auto', day = 1): TrackingInput {
  return {
    id: `${label}#${tracking}`,
    label,
    analyzedAt: new Date(Date.UTC(2026, 0, day)),
    tracking,
  };
}
const lines = (n: number): VersionRule => ({ kind: 'lines', lines: n });

function summary(inputs: TrackingInput[], rule: VersionRule): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [id, r] of computeTracking(inputs, rule)) {
    out[id] = `${r.tracked ? 'T' : 'U'}:${r.reason}`;
  }
  return out;
}

describe('computeTracking lines', () => {
  it('follows the brief table', () => {
    const inputs = [
      v('2.3.0'),
      v('2.3.4'),
      v('2.2.7', 'unsupported'),
      v('2.1.9'),
      v('2.4.0-rc.1'),
      v('1.9.12', 'pinned'),
    ];
    expect(summary(inputs, lines(2))).toEqual({
      '2.3.0#auto': 'U:replaced',
      '2.3.4#auto': 'T:newest_in_line',
      '2.2.7#unsupported': 'U:unsupported',
      '2.1.9#auto': 'U:older_line',
      '2.4.0-rc.1#auto': 'U:prerelease',
      '1.9.12#pinned': 'T:pinned',
    });
  });

  it('does not promote another version when the newest in a line is unsupported', () => {
    const inputs = [v('2.3.0'), v('2.3.4', 'unsupported')];
    expect(summary(inputs, lines(2))).toEqual({
      '2.3.0#auto': 'U:replaced',
      '2.3.4#unsupported': 'U:unsupported',
    });
  });

  it('lets a pinned version count for its line and track whatever its line', () => {
    const inputs = [v('3.0.0'), v('2.0.0'), v('1.0.0', 'pinned'), v('1.0.1')];
    expect(summary(inputs, lines(1))).toEqual({
      '3.0.0#auto': 'T:newest_in_line',
      '2.0.0#auto': 'U:older_line',
      '1.0.0#pinned': 'T:pinned',
      '1.0.1#auto': 'U:older_line',
    });
  });

  it('breaks ties by the later analyzedAt', () => {
    const a = { ...v('2.3.4', 'auto', 1), id: 'a' };
    const b = { ...v('2.3.4', 'auto', 2), id: 'b' };
    expect(summary([a, b], lines(1))).toEqual({ a: 'U:replaced', b: 'T:newest_in_line' });
  });

  it('tracks the most recent N labels that are not versions', () => {
    const inputs = [
      { ...v('build-a', 'auto', 1), id: 'a' },
      { ...v('build-b', 'auto', 2), id: 'b' },
      { ...v('build-c', 'auto', 3), id: 'c' },
      { ...v('build-d', 'unsupported', 4), id: 'd' },
    ];
    expect(summary(inputs, lines(2))).toEqual({
      a: 'U:older',
      b: 'T:recent',
      c: 'T:recent',
      d: 'U:unsupported',
    });
  });

  it('computes 1 000 versions under 50 ms', () => {
    const inputs: TrackingInput[] = [];
    for (let i = 0; i < 1000; i++) {
      inputs.push({
        id: `id${i}`,
        label: i % 7 === 0 ? `build-${i}` : `${i % 30}.${i % 11}.${i}`,
        analyzedAt: new Date(Date.UTC(2026, 0, 1) + i * 1000),
        tracking: i % 50 === 0 ? 'pinned' : 'auto',
      });
    }
    const start = performance.now();
    const result = computeTracking(inputs, lines(5));
    expect(performance.now() - start).toBeLessThan(50);
    expect(result.size).toBe(1000);
  });
});

describe('computeTracking all and none', () => {
  const inputs = [
    v('2.3.4'),
    v('2.3.0'),
    v('2.4.0-rc.1'),
    v('2.2.0', 'unsupported'),
    v('1.0.0', 'pinned'),
    v('nightly'),
  ];
  it('all tracks everything except pre-releases and unsupported', () => {
    expect(summary(inputs, { kind: 'all' })).toEqual({
      '2.3.4#auto': 'T:rule_all',
      '2.3.0#auto': 'T:rule_all',
      '2.4.0-rc.1#auto': 'U:prerelease',
      '2.2.0#unsupported': 'U:unsupported',
      '1.0.0#pinned': 'T:pinned',
      'nightly#auto': 'T:rule_all',
    });
  });
  it('none tracks only pinned', () => {
    expect(summary(inputs, { kind: 'none' })).toEqual({
      '2.3.4#auto': 'U:rule_none',
      '2.3.0#auto': 'U:rule_none',
      '2.4.0-rc.1#auto': 'U:prerelease',
      '2.2.0#unsupported': 'U:unsupported',
      '1.0.0#pinned': 'T:pinned',
      'nightly#auto': 'U:rule_none',
    });
  });
});
