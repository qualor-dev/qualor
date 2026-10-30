import { and, eq, isNull } from 'drizzle-orm';
import { projectRefs } from '../audit/refs';
import { generateToken } from '../auth/tokens';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { apiTokens, type TokenScope } from '../db/schema';
import type { AuditedActor } from './create';

export type ApiTokenRow = typeof apiTokens.$inferSelect;

/**
 * A project analysis token and its `project_token.created` event, in the caller's transaction
 * (`POST /projects/:id/tokens`, and the repository-setup run). The plain token is returned once,
 * here: only its hash is stored, and neither the event nor any log holds it.
 */
export async function createProjectToken(
  tx: Executor,
  input: {
    projectId: string;
    name: string;
    scopes: TokenScope[];
    expiresAt: Date | null;
    /** The user the token row names as its creator, and the actor of the event. */
    createdBy: AuditedActor & { userId: string | null };
  },
): Promise<{ row: ApiTokenRow; token: string }> {
  const generated = generateToken('project');
  const row = first(
    await tx
      .insert(apiTokens)
      .values({
        kind: 'project',
        projectId: input.projectId,
        name: input.name,
        prefix: generated.prefix,
        secretHash: generated.secretHash,
        scopes: input.scopes,
        expiresAt: input.expiresAt,
        createdBy: input.createdBy.userId,
      })
      .returning(),
  );
  const { audit, actor } = input.createdBy;
  if (audit.active()) {
    const refs = await projectRefs(tx, input.projectId);
    await audit.record(tx, actor, [
      {
        action: 'project_token.created',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'token', id: row.id, label: row.name },
        details: {
          name: row.name,
          prefix: row.prefix,
          expiresAt: row.expiresAt?.toISOString() ?? null,
        },
      },
    ]);
  }
  return { row, token: generated.token };
}

/**
 * Revokes a live project token and records `project_token.revoked` (a revocation is never blocked
 * by a malformed audit anchor, rbac-audit.md §10.2.1). False when it was not live.
 */
export async function revokeProjectToken(
  tx: Executor,
  input: { projectId: string; tokenId: string; revokedBy: AuditedActor },
): Promise<boolean> {
  const rows = await tx
    .update(apiTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(apiTokens.id, input.tokenId),
        eq(apiTokens.projectId, input.projectId),
        isNull(apiTokens.revokedAt),
      ),
    )
    .returning({ id: apiTokens.id, name: apiTokens.name, prefix: apiTokens.prefix });
  const [token] = rows;
  if (!token) return false;
  const { audit, actor } = input.revokedBy;
  if (audit.active()) {
    const refs = await projectRefs(tx, input.projectId);
    await audit.recordOrSkipWhenAnchorMalformed(tx, actor, [
      {
        action: 'project_token.revoked',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'token', id: token.id, label: token.name },
        details: { name: token.name, prefix: token.prefix },
      },
    ]);
  }
  return true;
}
