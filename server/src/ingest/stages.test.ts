import { describe, expect, it } from 'vitest';
import { webhookStage } from '../webhooks/stage';
import { DEFAULT_STAGES } from './stages';

describe('DEFAULT_STAGES', () => {
  it('ends with the webhook stage: its payload is the analysis as ingestion stores it', () => {
    expect(DEFAULT_STAGES.at(-1)).toBe(webhookStage);
    expect(DEFAULT_STAGES.filter((s) => s === webhookStage)).toHaveLength(1);
  });
});
