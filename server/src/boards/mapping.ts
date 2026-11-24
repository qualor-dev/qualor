import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { projectBoardsSettings, type JiraAutoSeverity } from '../db/schema';
import { conflict, type ProblemError } from '../http/problem';
import type { AzureJsonPatch, AzureWorkItemType } from '../scm/azure/client';

export type BoardsMappingRow = typeof projectBoardsSettings.$inferSelect;

/** `GET /projects/{id}/boards`'s `mapping` (design §7.8). */
export interface BoardsMappingDto {
  connectionId: string;
  azureProject: { id: string; name: string };
  workItemType: { referenceName: string; name: string };
  /** Null: the project's root. */
  areaPath: string | null;
  iterationPath: string | null;
  tags: string[];
  autoCreate: { minSeverity: JiraAutoSeverity | null; exploited: boolean; since: string | null };
  updatedAt: string;
}

/** The project's Boards mapping, or null. */
export async function boardsMappingOf(
  db: Executor,
  projectId: string,
): Promise<BoardsMappingRow | null> {
  const [row] = await db
    .select()
    .from(projectBoardsSettings)
    .where(eq(projectBoardsSettings.projectId, projectId));
  return row ?? null;
}

export function boardsMappingDto(row: BoardsMappingRow): BoardsMappingDto {
  return {
    connectionId: row.connectionId,
    azureProject: { id: row.azureProjectId, name: row.azureProjectName },
    workItemType: { referenceName: row.workItemTypeRef, name: row.workItemTypeName },
    areaPath: row.areaPath,
    iterationPath: row.iterationPath,
    tags: row.tags,
    autoCreate: {
      minSeverity: row.autoMinSeverity,
      exploited: row.autoExploited,
      since: row.autoSince === null ? null : row.autoSince.toISOString(),
    },
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** The one tag every work item of Qualor's carries (design §7.8): reserved, never a mapping tag. */
export const QUALOR_TAG = 'qualor';
/** A mapping adds at most this many tags (`project_boards_settings_tags_check`). */
export const MAX_BOARDS_TAGS = 10;
/** Azure DevOps' own words, where they may appear at all, are cut to this many characters. */
export const AZURE_WORDS_MAX = 500;

export const DESCRIPTION_FIELD = 'System.Description';
export const REPRO_STEPS_FIELD = 'Microsoft.VSTS.TCM.ReproSteps';

/**
 * Design §7.8, probe item 18: the fields of a work item Qualor sets itself, or that Azure DevOps
 * fills from what it sets (the area and iteration fall back to the project's root, the project and
 * the type come from the request's path). Every other field that is always required without a
 * default makes the type unsupported.
 */
export const BOARDS_SET_FIELDS = [
  'System.Title',
  DESCRIPTION_FIELD,
  REPRO_STEPS_FIELD,
  'System.Tags',
  'System.AreaId',
  'System.AreaPath',
  'System.IterationId',
  'System.IterationPath',
  'System.TeamProject',
  'System.WorkItemType',
] as const;

const SET: ReadonlySet<string> = new Set(BOARDS_SET_FIELDS);

export interface WorkItemTypeSupport {
  supported: boolean;
  /** The reference names of the fields Qualor cannot fill. */
  missingFields: string[];
  /** Whether the type has Repro Steps, which then also gets the description (a Bug). */
  reproSteps: boolean;
}

/**
 * Whether Qualor can create work items of the type (design §7.8): every field that is always
 * required without a default must be one it sets, and the type needs a field for the description
 * (Description or Repro Steps; without either, `System.Description` is named as missing).
 */
export function analyzeWorkItemType(type: AzureWorkItemType): WorkItemTypeSupport {
  const missingFields = type.fields
    .filter((f) => f.alwaysRequired && !f.hasDefault && !SET.has(f.referenceName))
    .map((f) => f.referenceName);
  const has = (referenceName: string) => type.fields.some((f) => f.referenceName === referenceName);
  const reproSteps = has(REPRO_STEPS_FIELD);
  if (!reproSteps && !has(DESCRIPTION_FIELD)) missingFields.push(DESCRIPTION_FIELD);
  return { supported: missingFields.length === 0, missingFields, reproSteps };
}

/** `System.Tags` of a work item: `qualor`, then the mapping's tags, joined by `; `. */
export function workItemTags(tags: readonly string[]): string {
  return [QUALOR_TAG, ...tags].join('; ');
}

/** What a mapping's dry run sends where a work item has its finding. */
export const MAPPING_CHECK_TITLE = 'Qualor mapping check';
const MAPPING_CHECK_TEXT =
  '<p>Qualor checks that it can create work items with this mapping. Nothing is created.</p>';

const add = (field: string, value: unknown): AzureJsonPatch => ({
  op: 'add',
  path: `/fields/${field}`,
  value,
});

/**
 * The JSON Patch of the mapping PUT's `validateOnly` create (check 5): a work item as Qualor would
 * create it with this mapping (Title, Description, Repro Steps when the type has it, the tags, a
 * set area and iteration path), with a fixed text where a finding would go.
 */
export function mappingCheckOps(
  mapping: {
    tags: readonly string[];
    areaPath: string | null;
    iterationPath: string | null;
  },
  reproSteps: boolean,
): AzureJsonPatch[] {
  return [
    add('System.Title', MAPPING_CHECK_TITLE),
    add(DESCRIPTION_FIELD, MAPPING_CHECK_TEXT),
    ...(reproSteps ? [add(REPRO_STEPS_FIELD, MAPPING_CHECK_TEXT)] : []),
    add('System.Tags', workItemTags(mapping.tags)),
    ...(mapping.areaPath === null ? [] : [add('System.AreaPath', mapping.areaPath)]),
    ...(mapping.iterationPath === null ? [] : [add('System.IterationPath', mapping.iterationPath)]),
  ];
}

/**
 * Design §3, §7.8: a project uses one tracker. The 409 of a mapping PUT while the project is mapped
 * to the other one, named by `inUse`.
 */
export function trackerInUse(inUse: 'jira' | 'boards'): ProblemError {
  return conflict(
    'TRACKER_IN_USE',
    inUse === 'jira'
      ? 'The project uses Jira; remove its Jira mapping first'
      : 'The project uses Azure Boards; remove its Boards mapping first',
  );
}
