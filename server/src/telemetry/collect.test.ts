import { describe, expect, it } from 'vitest';
import { cleanList, detectRuntime } from './collect';

describe('cleanList', () => {
  it('lowercases, deduplicates, sorts and drops anything that is not a short token', () => {
    expect(
      cleanList(['TypeScript', 'java', 'java', 'c++', 'c#', null, undefined, ' go ', 'x'.repeat(41), 'my project', '<b>', 'https://a']),
    ).toEqual(['c#', 'c++', 'go', 'java', 'typescript']);
  });
  it('keeps at most 50 items', () => {
    expect(cleanList(Array.from({ length: 80 }, (_, i) => `l${String(i).padStart(2, '0')}`))).toHaveLength(50);
  });
});

describe('detectRuntime', () => {
  it('kubernetes beats docker beats node', () => {
    expect(detectRuntime({ KUBERNETES_SERVICE_HOST: '10.0.0.1', QUALOR_UI_DIR: '/app/ui' }, true)).toBe('kubernetes');
    expect(detectRuntime({}, true)).toBe('docker');
    expect(detectRuntime({ QUALOR_UI_DIR: '/app/ui' }, false)).toBe('docker');
    expect(detectRuntime({}, false)).toBe('node');
  });
});
