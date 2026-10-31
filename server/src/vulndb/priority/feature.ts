import { ProblemError } from '../../http/problem';

/** The enterprise feature behind CISA KEV and FIRST EPSS. */
export const PRIORITY_FEATURE = 'vuln.priority';

/** 403 for a KEV or EPSS request while the feature is not licensed. */
export const priorityNotLicensed = (): ProblemError =>
  new ProblemError(
    403,
    'FEATURE_NOT_LICENSED',
    `The enterprise feature "${PRIORITY_FEATURE}" is not licensed`,
  );
