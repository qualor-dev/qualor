import { describe, expect, it } from 'vitest';
import {
  chargeAcrossAttempts,
  type TransitionAudit,
  type TransitionInOptions,
} from './transitions';

describe('chargeAcrossAttempts', () => {
  it('charges the first attempt whole and a retried one only past what was charged', () => {
    const charged: number[] = [];
    const charge = chargeAcrossAttempts((count) => charged.push(count));
    charge?.(3);
    // A deadlock rolled the first attempt back; the second finds the same 3 issues, then 5.
    charge?.(3);
    charge?.(2);
    charge?.(5);
    expect(charged).toEqual([3, 2]);
  });

  it('charges again after a refusal: nothing was charged then', () => {
    const charged: number[] = [];
    let refuse = true;
    const charge = chargeAcrossAttempts((count) => {
      if (refuse) throw new Error('RATE_LIMITED');
      charged.push(count);
    });
    expect(() => charge?.(4)).toThrow('RATE_LIMITED');
    refuse = false;
    charge?.(4);
    expect(charged).toEqual([4]);
  });

  it('is absent without a charge', () => {
    expect(chargeAcrossAttempts(undefined)).toBeUndefined();
  });
});

describe('TransitionInOptions', () => {
  it('cannot defer the re-evaluations of a transition that records audit events', () => {
    const audit = {} as TransitionAudit;
    const deferred: TransitionInOptions = { deferReevaluation: true };
    const audited: TransitionInOptions = { audit };
    // @ts-expect-error: audit events would precede the re-evaluations the caller queues later.
    const both: TransitionInOptions = { audit, deferReevaluation: true };
    expect([deferred, audited, both]).toHaveLength(3);
  });
});
