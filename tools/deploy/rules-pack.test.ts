import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { qualorRulesPins } from '../../cli/test/install-pins';
import { qualorRulesPublished, scannerBuildArgs } from './rules-pack';

const INSTALL_SH = readFileSync('tools/analyzers/install.sh', 'utf8');
const pins = (url: string) => `QUALOR_RULES_VERSION=2026.10.0\nQUALOR_RULES_URL=${url}\n`;
const URL =
  'https://github.com/qualor-dev/qualor-rules/releases/download/v$QUALOR_RULES_VERSION/qualor-rules-$QUALOR_RULES_VERSION.tar.gz';

describe('the rules pack in a release build (plan 6B-1)', () => {
  it('is published once install.sh sets QUALOR_RULES_URL, and not before', () => {
    expect(qualorRulesPublished(pins(''))).toBe(false);
    expect(qualorRulesPublished(pins(URL))).toBe(true);
    // A commented-out or indented line is not a pin.
    expect(qualorRulesPublished(`# QUALOR_RULES_URL=${URL}\n  QUALOR_RULES_URL=${URL}\n`)).toBe(
      false,
    );
    expect(qualorRulesPublished('')).toBe(false);
  });

  it('requires the pack in the scanner image only once it is published (hotfixes are never blocked)', () => {
    const before = scannerBuildArgs(pins(''));
    expect(before.join(' ')).not.toContain('QUALOR_RULES_REQUIRED');
    expect(before.slice(0, 2)).toEqual(['-f', path.join('deploy', 'scanner', 'Dockerfile')]);
    expect(before.at(-1)).toBe('.');
    const after = scannerBuildArgs(pins(URL));
    expect(after).toContain('QUALOR_RULES_REQUIRED=1');
    expect(after[after.indexOf('QUALOR_RULES_REQUIRED=1') - 1]).toBe('--build-arg');
    expect(after.at(-1)).toBe('.');
  });

  it('reads the pins of the committed install.sh, and release-images.ts uses it', () => {
    const pins = qualorRulesPins(INSTALL_SH);
    expect(pins.version).toMatch(/^\d{4}\.([1-9]|1[0-2])\.(0|[1-9]\d*)$/);
    expect(pins.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(pins.opengrep).toMatch(/^\d+\.\d+\.\d+$/);
    expect(qualorRulesPublished(INSTALL_SH)).toBe(pins.url !== '');
    expect(readFileSync('tools/deploy/release-images.ts', 'utf8')).toContain('scannerBuildArgs(');
  });
});
