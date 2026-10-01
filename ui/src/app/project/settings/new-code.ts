import type { ProjectDto } from '../current-project';

export type NewCodeDefinition = NonNullable<ProjectDto['newCodeDefinition']>;
export type NewCodeChoice = 'default' | 'days' | 'previous_version' | 'analysis';

/** The days the server falls back to when a project has no definition. */
export const DEFAULT_DAYS = 30;
const MIN_DAYS = 1;
const MAX_DAYS = 3650;

export interface NewCodeForm {
  choice: NewCodeChoice;
  days: string;
  analysisId: string;
}

export function formFromDefinition(d: NewCodeDefinition | null): NewCodeForm {
  const form: NewCodeForm = { choice: 'default', days: String(DEFAULT_DAYS), analysisId: '' };
  if (d === null) return form;
  switch (d.type) {
    case 'days':
      return { ...form, choice: 'days', days: String(d.value) };
    case 'previous_version':
      return { ...form, choice: 'previous_version' };
    case 'analysis':
      return { ...form, choice: 'analysis', analysisId: d.analysisId };
  }
}

/** The PATCH body value, or the field whose value is not acceptable. */
export function definitionFromForm(
  f: NewCodeForm,
): { value: NewCodeDefinition | null } | { error: 'days' | 'analysis' } {
  switch (f.choice) {
    case 'default':
      return { value: null };
    case 'previous_version':
      return { value: { type: 'previous_version' } };
    case 'days': {
      const text = f.days.trim();
      if (!/^\d{1,4}$/.test(text)) return { error: 'days' };
      const value = Number(text);
      return value >= MIN_DAYS && value <= MAX_DAYS
        ? { value: { type: 'days', value } }
        : { error: 'days' };
    }
    case 'analysis':
      return f.analysisId === ''
        ? { error: 'analysis' }
        : { value: { type: 'analysis', analysisId: f.analysisId } };
  }
}

export function sameDefinition(a: NewCodeDefinition | null, b: NewCodeDefinition | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.type !== b.type) return false;
  if (a.type === 'days') return b.type === 'days' && a.value === b.value;
  if (a.type === 'analysis') return b.type === 'analysis' && a.analysisId === b.analysisId;
  return true;
}
