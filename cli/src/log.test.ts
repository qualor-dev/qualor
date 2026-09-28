import { describe, expect, it } from 'vitest';
import { CliError } from './errors';
import { createLogger, parseLogLevel } from './log';

describe('logger', () => {
  it('writes messages at or above the level, prefixed except for info', () => {
    const lines: string[] = [];
    const log = createLogger('info', (t) => lines.push(t));
    log.error('e');
    log.warn('w');
    log.info('i');
    log.debug('d');
    expect(lines).toEqual(['error: e\n', 'warn: w\n', 'i\n']);
  });

  it('parses QUALOR_LOG_LEVEL case-insensitively, defaulting to info', () => {
    expect(parseLogLevel(undefined)).toBe('info');
    expect(parseLogLevel('')).toBe('info');
    expect(parseLogLevel('DEBUG')).toBe('debug');
    expect(() => parseLogLevel('verbose')).toThrow(CliError);
  });
});
