import path from 'node:path';
import { qualorRulesPins } from '../../cli/test/install-pins';

/**
 * Qualor's security rules pack in a release build (plan 6B-1). A release requires the pack only
 * once it is published, that is once `tools/analyzers/install.sh` sets `QUALOR_RULES_URL`: until
 * then there is nothing to download, and a release (a hotfix included) ships without the pack, its
 * `qualor` analyzer skipping with a message. The pack is never required from a git-ignored local
 * tarball, because a release build runs from a checkout that cannot hold one.
 */

/** Whether install.sh's text pins a URL for the pack (`QUALOR_RULES_URL=` is empty until then). */
export function qualorRulesPublished(installSh: string): boolean {
  return qualorRulesPins(installSh).url !== '';
}

/** The `docker build` arguments of qualor/scanner: the pack becomes a build requirement once published. */
export function scannerBuildArgs(installSh: string): string[] {
  return [
    '-f',
    path.join('deploy', 'scanner', 'Dockerfile'),
    ...(qualorRulesPublished(installSh) ? ['--build-arg', 'QUALOR_RULES_REQUIRED=1'] : []),
    '.',
  ];
}
