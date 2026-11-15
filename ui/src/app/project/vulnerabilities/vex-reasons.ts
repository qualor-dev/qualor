import type { RequestBody } from '../../api/types';

type Decision = RequestBody<'/api/v0/projects/{id}/vulnerability-decisions', 'put'>;
/** The VEX justification of a Not affected decision. */
export type Reason = NonNullable<Decision['reason']>;

/** The reasons the Reason fields offer, in order: the change-status dialog and the issue pages. */
export const VEX_REASONS: Reason[] = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
];
