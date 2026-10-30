import { describe, expect, it } from 'vitest';
import { licensePolicyStage } from '../licenses/stage';
import { measuresStage } from '../measures/stage';
import { notificationStage } from '../notifications/stage';
import { reviewSnapshotStage } from '../review/stage';
import { rulesStage } from '../rules/stage';
import { scmStage } from '../scm/stage';
import { trackingStage } from '../tracking/stage';
import { versionLabelStage } from '../versions/stage';
import { webhookStage } from '../webhooks/stage';
import { DEFAULT_STAGES } from './stages';

describe('DEFAULT_STAGES', () => {
  it('ends with the webhook stage, then only the notification stage, which writes no analysis', () => {
    expect(DEFAULT_STAGES.at(-2)).toBe(webhookStage);
    expect(DEFAULT_STAGES.at(-1)).toBe(notificationStage);
    expect(DEFAULT_STAGES.filter((s) => s === webhookStage)).toHaveLength(1);
    expect(DEFAULT_STAGES.filter((s) => s === notificationStage)).toHaveLength(1);
  });

  it('judges licences after the rules stage and before tracking (6M §6)', () => {
    const at = DEFAULT_STAGES.indexOf(licensePolicyStage);
    expect(licensePolicyStage.name).toBe('license-policy');
    expect(DEFAULT_STAGES[at - 1]).toBe(rulesStage);
    expect(DEFAULT_STAGES[at + 1]).toBe(trackingStage);
  });

  it('takes versions from labels right after the measures stage', () => {
    const at = DEFAULT_STAGES.indexOf(versionLabelStage);
    expect(versionLabelStage.name).toBe('version-label');
    expect(DEFAULT_STAGES[at - 1]).toBe(measuresStage);
    expect(DEFAULT_STAGES.filter((s) => s === versionLabelStage)).toHaveLength(1);
  });

  it('links the review snapshot after the SCM stage and before the webhooks (6I-2)', () => {
    const at = DEFAULT_STAGES.indexOf(reviewSnapshotStage);
    expect(reviewSnapshotStage.name).toBe('review-snapshot');
    expect(DEFAULT_STAGES[at - 1]).toBe(scmStage);
    expect(DEFAULT_STAGES[at + 1]).toBe(webhookStage);
    expect(DEFAULT_STAGES.filter((s) => s === reviewSnapshotStage)).toHaveLength(1);
  });
});
