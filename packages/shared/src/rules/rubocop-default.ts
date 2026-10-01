/**
 * `qualor-default` of the rubocop engine (plan 9B, config.md §6), apart from rubocop.ts so that
 * tools/analyzers/rubocop-cops.ts can use it before the generated table exists. The cop-name
 * regex and the table schema live here only: the generator and rubocop.ts both validate with them.
 */
import { z } from 'zod';

export type RubocopCopState = 'enabled' | 'pending' | 'disabled';

/** A RuboCop cop name (`Lint/UselessAssignment`). */
export const RUBOCOP_COP_NAME = /^[A-Z][A-Za-z]*\/[A-Z][A-Za-z0-9]*$/;

/** packages/shared/rules/rubocop-cops.json, generated from `run.rb --cops`. */
export const rubocopTableSchema = z.strictObject({
  $comment: z.string(),
  version: z.string(),
  targetRubies: z.array(z.string().regex(/^\d+\.\d+$/)).min(1),
  cops: z.record(
    z.string().regex(RUBOCOP_COP_NAME),
    z.enum(['enabled', 'pending', 'disabled'] as const satisfies readonly RubocopCopState[]),
  ),
});
export type RubocopTable = z.infer<typeof rubocopTableSchema>;

/** The departments qualor-default draws from: the cops RuboCop enables by default there. */
export const RUBOCOP_DEFAULT_DEPARTMENTS: readonly string[] = ['Lint', 'Security'];

/** RuboCop's parse errors: always on in RuboCop, never a rule in Qualor (dropped by the CLI). */
export const RUBOCOP_SYNTAX_COP = 'Lint/Syntax';

/** What qualor-default leaves out (measured, plan 9B fact F7). */
export const RUBOCOP_DEFAULT_EXCLUDE: readonly string[] = [
  // They judge the project's own directives against a configuration Qualor does not use.
  'Lint/CopDirectiveSyntax',
  'Lint/MissingCopEnableDirective',
  'Lint/RedundantCopDisableDirective',
  'Lint/RedundantCopEnableDirective',
  // Idioms of Rails callbacks, RSpec and DSL blocks.
  'Lint/AmbiguousBlockAssociation',
  'Lint/AssignmentInCondition',
  'Lint/ConstantDefinitionInBlock',
  'Lint/MissingSuper',
  'Lint/UnderscorePrefixedVariableName',
  'Lint/UnusedBlockArgument',
  'Lint/UnusedMethodArgument',
];

/** `Lint` of `Lint/UselessAssignment`; the whole string when it has no `/`. */
export function departmentOf(cop: string): string {
  const slash = cop.indexOf('/');
  return slash < 0 ? cop : cop.slice(0, slash);
}

/** The cops qualor-default runs, sorted. */
export function qualorDefaultCops(cops: ReadonlyMap<string, RubocopCopState>): string[] {
  return [...cops]
    .filter(
      ([name, state]) =>
        state === 'enabled' &&
        RUBOCOP_DEFAULT_DEPARTMENTS.includes(departmentOf(name)) &&
        name !== RUBOCOP_SYNTAX_COP &&
        !RUBOCOP_DEFAULT_EXCLUDE.includes(name),
    )
    .map(([name]) => name)
    .sort();
}
