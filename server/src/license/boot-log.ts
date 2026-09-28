import type { PluginReport } from '../plugins/contract';
import type { BootLicense } from './source';
import type { LicenseState } from './state';

export interface BootLogLine {
  level: 'info' | 'error';
  fields: Record<string, unknown>;
  message: string;
}

/**
 * The one licence line at boot (enterprise.md §6): the state, the edition, where the key came from
 * and which plugins loaded. It never holds the key, its hash, the customer or the licence id, so
 * shipping logs to a third party identifies neither the key nor the customer.
 */
export function bootLicenseLog(
  boot: BootLicense,
  state: LicenseState,
  plugins: readonly PluginReport[],
): BootLogLine {
  const edition = state.licensed ? 'enterprise' : 'community';
  const fields: Record<string, unknown> = { licence: state.state, edition, source: boot.source };
  if (state.license) fields['expires'] = state.license.expires;
  if (state.state === 'invalid') fields['reason'] = state.reason;
  fields['plugins'] = plugins.filter((p) => p.state === 'loaded').map((p) => p.name);
  const failed = plugins.filter((p) => p.state === 'failed').map((p) => p.name);
  if (failed.length > 0) fields['failedPlugins'] = failed;
  if (state.state === 'invalid') {
    return { level: 'error', fields, message: 'licence key rejected' };
  }
  return { level: 'info', fields, message: `running as the ${edition} edition` };
}
