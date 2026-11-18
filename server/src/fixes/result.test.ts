import { FIX_RULE_TEXT, FIX_RULES } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { openApiDocument } from '../http/openapi-doc';
import { UPLOAD_RULE_TEXT, UPLOAD_RULES } from './result';

describe('the rules of a fix upload (0.16 fix MRs §6.7, B1, R7, ruling T3h)', () => {
  it('are the content rules and the route rules, each once, each with one fixed sentence', () => {
    expect(UPLOAD_RULES.slice(0, FIX_RULES.length)).toEqual([...FIX_RULES]);
    expect(new Set(UPLOAD_RULES).size).toBe(UPLOAD_RULES.length);
    expect(Object.keys(UPLOAD_RULE_TEXT).toSorted()).toEqual([...UPLOAD_RULES].toSorted());
    for (const rule of FIX_RULES) expect(UPLOAD_RULE_TEXT[rule]).toBe(FIX_RULE_TEXT[rule]);
    for (const rule of UPLOAD_RULES) expect(UPLOAD_RULE_TEXT[rule]).toMatch(/^[A-Zg].*\.$/);
    // Rulings T9g, T9h, T9i: every way the targets can disagree with the upload.
    expect(UPLOAD_RULE_TEXT.target_mismatch).toBe(
      'The targets do not match the upload: each target must be above its installed version, the target version must be the greatest target, each target and each lockfile line must name an uploaded file, and each uploaded lockfile must have a target.',
    );
    expect(UPLOAD_RULE_TEXT.base_outdated).toBe(
      'Main changed this file after the fix was prepared; the next run starts from the new main.',
    );
  });

  it('are each named where the API document describes the problem `reason`', async () => {
    const doc = (await openApiDocument()) as {
      components: { schemas: { Problem: { properties: { reason: { description: string } } } } };
    };
    const text = doc.components.schemas.Problem.properties.reason.description;
    for (const rule of UPLOAD_RULES) expect(text).toContain(rule);
  });
});
