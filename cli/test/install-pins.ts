import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/** The text of tools/analyzers/install.sh, which pins every tool the images and CI install. */
export function installShText(): string {
  return readFileSync(path.resolve(here, '../../tools/analyzers/install.sh'), 'utf8');
}

/**
 * Plan 6B-1: the pins of Qualor's security rules pack and of the OpenGrep it is made for, read
 * from install.sh's text. The one parser of these lines: the real-tool tests, the fixture harness
 * and the release build (tools/deploy/rules-pack.ts) all use it. An unset or absent pin is ''.
 */
export function qualorRulesPins(installSh: string = installShText()): {
  version: string;
  sha256: string;
  url: string;
  opengrep: string;
} {
  const pin = (name: string) =>
    new RegExp(`^${name}=([^\r\n]*)`, 'm').exec(installSh)?.[1]?.trim() ?? '';
  return {
    version: pin('QUALOR_RULES_VERSION'),
    sha256: pin('QUALOR_RULES_SHA256'),
    url: pin('QUALOR_RULES_URL'),
    opengrep: pin('OPENGREP_VERSION'),
  };
}
