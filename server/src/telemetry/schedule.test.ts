import { describe, expect, it } from 'vitest';
import { telemetryBootMessage } from './schedule';

describe('telemetryBootMessage', () => {
  it('says telemetry is disabled, or what it sends', () => {
    expect(telemetryBootMessage(false)).toBe('Telemetry: disabled');
    expect(telemetryBootMessage(true)).toContain('anonymous usage statistics are sent daily');
  });

  it('names the official download while the vulnerability database switch is on', () => {
    expect(telemetryBootMessage(false, 'official')).toBe(
      'Telemetry: disabled. The Trivy vulnerability database is downloaded from ghcr.io while Vulnerability monitoring is on (see /docs/vulnerability-database)',
    );
    expect(telemetryBootMessage(true, 'official')).toMatch(
      /^Telemetry: enabled .*\(see \/docs\/telemetry\)\. The Trivy vulnerability database is downloaded from ghcr\.io /,
    );
  });

  it('names a mirror, and says nothing for an upload or a switch that is off', () => {
    expect(telemetryBootMessage(false, 'mirror')).toContain('from the mirror set in Settings');
    expect(telemetryBootMessage(false, 'upload')).toBe('Telemetry: disabled');
    expect(telemetryBootMessage(false, null)).toBe('Telemetry: disabled');
  });
});
