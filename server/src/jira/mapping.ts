import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { projectJiraSettings, type JiraAutoSeverity, type JiraPriorities } from '../db/schema';
import type { JiraProjectRef } from './client';

export type JiraMappingRow = typeof projectJiraSettings.$inferSelect;

/** `GET /projects/{id}/jira`'s `mapping` (spec §6.8). */
export interface JiraMappingDto {
  jiraProject: JiraProjectRef;
  issueType: { id: string; name: string };
  labels: string[];
  priorities: JiraPriorities | null;
  /** Whether the issue type's create screen had the labels / priority field when it was saved. */
  labelsAvailable: boolean;
  priorityAvailable: boolean;
  autoCreate: { minSeverity: JiraAutoSeverity | null; exploited: boolean; since: string | null };
  updatedAt: string;
}

/** The project's mapping, or null. */
export async function mappingOf(db: Executor, projectId: string): Promise<JiraMappingRow | null> {
  const [row] = await db
    .select()
    .from(projectJiraSettings)
    .where(eq(projectJiraSettings.projectId, projectId));
  return row ?? null;
}

export function mappingDto(row: JiraMappingRow): JiraMappingDto {
  return {
    jiraProject: {
      id: row.jiraProjectId,
      key: row.jiraProjectKey,
      name: row.jiraProjectName,
    },
    issueType: { id: row.issueTypeId, name: row.issueTypeName },
    labels: row.labels,
    priorities: row.priorities,
    labelsAvailable: row.labelsAvailable,
    priorityAvailable: row.priorityAvailable,
    autoCreate: {
      minSeverity: row.autoMinSeverity,
      exploited: row.autoExploited,
      since: row.autoSince === null ? null : row.autoSince.toISOString(),
    },
    updatedAt: row.updatedAt.toISOString(),
  };
}
