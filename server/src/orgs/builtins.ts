import { and, eq } from 'drizzle-orm';
import { QUALOR_WAY_GATE } from '@qualor/shared';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { gateConditions, qualityGates, qualityProfiles } from '../db/schema';

/** The name of every built-in profile and of the built-in gate (data-model.md §4.4, gates.md §7). */
export const BUILTIN_NAME = 'Qualor way';

/** data-model.md §4.4: one profile per language, plus `*` for engines not tied to a language. */
export const PROFILE_LANGUAGES = [
  'typescript',
  'javascript',
  'java',
  'csharp',
  'python',
  'html',
  'css',
  'kotlin',
  '*',
] as const;
export type ProfileLanguage = (typeof PROFILE_LANGUAGES)[number];

export interface EnsureBuiltinsResult {
  createdProfiles: number;
  createdGate: boolean;
}

/**
 * Creates the organisation's read-only built-in profiles ("Qualor way" per language and `*`, no
 * rule rows, `unknown_rules = 'activate'`: every reported rule is active, ruling P1) and the
 * built-in "Qualor way" gate with the conditions of `QUALOR_WAY_GATE`. Idempotent: an existing
 * built-in is never touched, so re-running this never takes the default flag back from a profile
 * or gate an admin chose. A newly created built-in becomes the default only when its
 * organisation (and language) has no default yet.
 *
 * Callers must serialise concurrent calls for one organisation: `createOrganization` runs it
 * under the organisation-create advisory lock, `bootstrap` under the bootstrap lock.
 */
export async function ensureBuiltins(
  tx: Executor,
  organizationId: string,
): Promise<EnsureBuiltinsResult> {
  let createdProfiles = 0;
  for (const language of PROFILE_LANGUAGES) {
    const existing = await tx
      .select({ id: qualityProfiles.id, isBuiltin: qualityProfiles.isBuiltin })
      .from(qualityProfiles)
      .where(
        and(
          eq(qualityProfiles.organizationId, organizationId),
          eq(qualityProfiles.language, language),
        ),
      );
    if (existing.some((p) => p.isBuiltin)) continue;
    const [hasDefault] = await tx
      .select({ id: qualityProfiles.id })
      .from(qualityProfiles)
      .where(
        and(
          eq(qualityProfiles.organizationId, organizationId),
          eq(qualityProfiles.language, language),
          eq(qualityProfiles.isDefault, true),
        ),
      );
    await tx.insert(qualityProfiles).values({
      organizationId,
      name: BUILTIN_NAME,
      language,
      isBuiltin: true,
      isDefault: hasDefault === undefined,
      unknownRules: 'activate',
    });
    createdProfiles += 1;
  }

  const [builtinGate] = await tx
    .select({ id: qualityGates.id })
    .from(qualityGates)
    .where(and(eq(qualityGates.organizationId, organizationId), eq(qualityGates.isBuiltin, true)));
  if (builtinGate) return { createdProfiles, createdGate: false };
  const [defaultGate] = await tx
    .select({ id: qualityGates.id })
    .from(qualityGates)
    .where(and(eq(qualityGates.organizationId, organizationId), eq(qualityGates.isDefault, true)));
  const gate = first(
    await tx
      .insert(qualityGates)
      .values({
        organizationId,
        name: BUILTIN_NAME,
        isBuiltin: true,
        isDefault: defaultGate === undefined,
      })
      .returning({ id: qualityGates.id }),
  );
  await tx.insert(gateConditions).values(
    QUALOR_WAY_GATE.conditions.map((c) => ({
      gateId: gate.id,
      metricKey: c.metric,
      operator: c.operator,
      threshold: c.threshold,
    })),
  );
  return { createdProfiles, createdGate: true };
}
