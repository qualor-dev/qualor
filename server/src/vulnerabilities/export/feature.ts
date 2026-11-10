import { ProblemError } from '../../http/problem';

/** The enterprise feature behind the SBOM and VEX export. */
export const SBOM_FEATURE = 'sbom';

/** 403 for an export request while the feature is not licensed. */
export const sbomNotLicensed = (): ProblemError =>
  new ProblemError(
    403,
    'FEATURE_NOT_LICENSED',
    `The enterprise feature "${SBOM_FEATURE}" is not licensed`,
  );
