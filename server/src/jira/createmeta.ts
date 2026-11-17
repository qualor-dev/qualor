import type { CreateMetaField } from './client';

/**
 * spec §6.2: the fields of a create screen Qualor fills in itself (it sends no other); every other
 * field that is required without a default makes the issue type unsupported.
 */
export const QUALOR_SET_FIELDS = [
  'project',
  'issuetype',
  'summary',
  'reporter',
  'description',
  'labels',
  'priority',
] as const;

export interface IssueTypeSupport {
  supported: boolean;
  /** The names (as Jira shows them) of the fields Qualor cannot fill. */
  missingFields: string[];
  /** Whether the screen has the labels field. */
  labels: boolean;
  /**
   * The priority field: its values, and whether a create must set it (required without a default,
   * R12: then the mapping needs a priority for every severity). Null without the field.
   */
  priority: { allowed: { id: string; name: string }[]; required: boolean } | null;
}

const SET: ReadonlySet<string> = new Set(QUALOR_SET_FIELDS);

/**
 * Whether Qualor can create an issue of the type, from its create screen (spec §6.2).
 * `prioritiesForEverySeverity` is whether the mapping gives a priority for every severity; `'any'`
 * (the listing, R12) counts a required priority as settable, as the panel then asks for them all.
 */
export function analyzeIssueType(
  fields: readonly CreateMetaField[],
  prioritiesForEverySeverity: boolean | 'any',
): IssueTypeSupport {
  const missingFields: string[] = [];
  for (const f of fields) {
    if (!f.required || f.hasDefaultValue) continue;
    if (f.fieldId === 'priority' ? prioritiesForEverySeverity === false : !SET.has(f.fieldId)) {
      missingFields.push(f.name);
    }
  }
  // Qualor writes into the description, so the screen must have it, required or not.
  if (!fields.some((f) => f.fieldId === 'description')) missingFields.push('Description');
  const priority = fields.find((f) => f.fieldId === 'priority');
  return {
    supported: missingFields.length === 0,
    missingFields,
    labels: fields.some((f) => f.fieldId === 'labels'),
    priority: priority
      ? {
          allowed: priority.allowedValues.map((v) => ({ id: v.id, name: v.name })),
          required: priority.required && !priority.hasDefaultValue,
        }
      : null,
  };
}
