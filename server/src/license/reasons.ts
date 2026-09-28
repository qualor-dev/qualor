import type { InvalidReason } from './verify';

/** The text of each rejection (API `errors[].message`, the boot log); the UI has its own labels. */
export const INVALID_REASON_TEXT: Readonly<Record<InvalidReason, string>> = {
  malformed: 'This is not a Qualor licence key; check that it was copied completely',
  'unknown-key': 'This key was signed with a key this version of Qualor does not accept',
  'bad-signature': 'The key has been changed: its signature does not match',
  'bad-payload': 'The contents of the key are not valid',
  revoked: 'This licence has been revoked',
  'not-yet-valid': 'This licence is not valid yet',
};
