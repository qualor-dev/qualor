import { describe, expect, it } from 'vitest';
import type { VulndbSource } from '../vulndb/settings';
import { priorityBootHosts, telemetryBootMessage } from './schedule';

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

  describe('with vuln.priority', () => {
    const mirror = (kevUrl: string | null, epssUrl: string | null): VulndbSource => ({
      kind: 'mirror',
      repository: 'registry.corp:5000/mirror/trivy-db:2',
      username: null,
      passwordEnc: null,
      kevUrl,
      epssUrl,
    });

    it('names the official KEV and EPSS hosts after the Trivy download', () => {
      const hosts = priorityBootHosts({ kind: 'official' });
      expect(hosts).toEqual({ kev: 'www.cisa.gov', epss: 'epss.empiricalsecurity.com' });
      expect(telemetryBootMessage(false, 'official', hosts)).toBe(
        'Telemetry: disabled. The Trivy vulnerability database is downloaded from ghcr.io, CISA KEV from www.cisa.gov and FIRST EPSS from epss.empiricalsecurity.com while Vulnerability monitoring is on (see /docs/vulnerability-database)',
      );
    });

    it("names each dataset's own host with a mirror, official ones included", () => {
      const hosts = priorityBootHosts(
        mirror(null, 'https://files.corp.example:8443/epss/current.csv.gz?token=x'),
      );
      expect(hosts).toEqual({ kev: 'www.cisa.gov', epss: 'files.corp.example:8443' });
      expect(telemetryBootMessage(false, 'mirror', hosts)).toBe(
        'Telemetry: disabled. The Trivy vulnerability database is downloaded from the mirror set in Settings → Vulnerability database, CISA KEV from www.cisa.gov and FIRST EPSS from files.corp.example:8443 while Vulnerability monitoring is on (see /docs/vulnerability-database)',
      );
      expect(priorityBootHosts(mirror('https://kev.corp.example/kev.json', null))).toEqual({
        kev: 'kev.corp.example',
        epss: 'epss.empiricalsecurity.com',
      });
    });

    it('says nothing more for an upload or a switch that is off', () => {
      const hosts = priorityBootHosts({ kind: 'official' });
      expect(telemetryBootMessage(false, 'upload', hosts)).toBe('Telemetry: disabled');
      expect(telemetryBootMessage(false, null, hosts)).toBe('Telemetry: disabled');
    });

    it('is the message of today without the feature', () => {
      expect(telemetryBootMessage(false, 'official', null)).toBe(
        'Telemetry: disabled. The Trivy vulnerability database is downloaded from ghcr.io while Vulnerability monitoring is on (see /docs/vulnerability-database)',
      );
    });
  });
});
