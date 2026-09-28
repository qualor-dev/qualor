import type { ResponseBody } from '../api/types';

export type LicenseStatus = ResponseBody<'/api/v0/license', 'get'>;
export type LicenseReason = NonNullable<LicenseStatus['reason']>;
export type LicenseSource = NonNullable<LicenseStatus['source']>;

/** The longest text the server takes for a key (enterprise.md §9: 16 KiB); longer is not a key. */
export const MAX_KEY_TEXT = 16_384;

/**
 * The key as the server should see it: every space, line break, tab and invisible format
 * character removed (a mail client wraps a key, a PDF adds no-break spaces, a copy from a web page
 * can bring zero-width spaces or a byte order mark). The server removes ASCII whitespace itself;
 * a key is plain ASCII, so nothing else of it is lost.
 */
export function cleanKey(text: string): string {
  return text.replace(/[\s\p{Cf}]/gu, '');
}

/**
 * Why a key was rejected (enterprise.md §4), in the UI's own words (plan 1F ruling Y3). Each has
 * the meaning of the server's text in server/src/license/reasons.ts.
 */
export function reasonText(reason: LicenseReason): string {
  switch (reason) {
    case 'malformed':
      return $localize`:@@license.reason.malformed:This is not a Qualor licence key; check that it was copied completely`;
    case 'unknown-key':
      return $localize`:@@license.reason.unknownKey:This key was signed with a key this version of Qualor does not accept`;
    case 'bad-signature':
      return $localize`:@@license.reason.badSignature:The key has been changed: its signature does not match`;
    case 'bad-payload':
      return $localize`:@@license.reason.badPayload:The contents of the key are not valid`;
    case 'revoked':
      return $localize`:@@license.reason.revoked:This licence has been revoked`;
    case 'not-yet-valid':
      return $localize`:@@license.reason.notYetValid:This licence is not valid yet`;
  }
}

const REASONS: readonly LicenseReason[] = [
  'malformed',
  'unknown-key',
  'bad-signature',
  'bad-payload',
  'revoked',
  'not-yet-valid',
];

/**
 * The UI's words for a reason code the server sent (the top-level `reason` of a 422
 * `LICENSE_INVALID`, or the status's `reason`), or null when it sent none or a code this UI does
 * not know (a newer server). The server's English text is never read (enterprise.md §9).
 */
export function knownReasonText(reason: unknown): string | null {
  const known = REASONS.find((r) => r === reason);
  return known === undefined ? null : reasonText(known);
}

export const licenseTexts = {
  required: () => $localize`:@@license.keyRequired:Paste the licence key you received.`,
  rejected: () =>
    $localize`:@@license.rejectedUnknown:The key was not accepted. Check that it was copied completely, or ask for a new one.`,
  rejectedAtStart: () =>
    $localize`:@@license.state.invalidUnknown:The key was rejected. Check that it was copied completely, or ask for a new one.`,
  expired: () =>
    $localize`:@@license.expiredKey:This licence is past its grace period. Ask for a renewed key.`,
  managedByEnvironment: () =>
    $localize`:@@license.managedByEnvironment:The key is set by QUALOR_LICENSE or QUALOR_LICENSE_FILE, so it cannot be changed here.`,
  saved: () => $localize`:@@license.saved:Saved. Restart the server to apply the new key.`,
  savedSame: () =>
    $localize`:@@license.savedSame:Saved. This is the key the server is running with; no restart is needed.`,
  removed: () =>
    $localize`:@@license.removed:Removed. Restart the server to run as the community edition.`,
  removedNothing: () => $localize`:@@license.removedNothing:Removed. No key is saved in Qualor.`,
  confirmRemove: () =>
    $localize`:@@license.confirmRemove:Remove the saved licence key? At the next start the server runs as the community edition. Nothing is deleted.`,
};
