import { eq } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { Db, Executor } from '../db/client';
import { memberships, organizations, type OrganizationRole, type TokenScope } from '../db/schema';
import { forbidden, notFound, unauthenticated } from '../http/problem';
import { grantInOrganization, memberOf, NO_PERMISSIONS, organizationFacts } from './facts';
import {
  organizationPermissions,
  permissionScope,
  type OrganizationPermission,
  type Permission,
} from './policy';
import type { Principal, UserPrincipal } from './principal';

export type AccessScope = Exclude<TokenScope, 'analysis:write'>;
const RANK: Record<AccessScope, number> = { read: 1, write: 2, admin: 3 };

/** A session carries every scope; token scopes are hierarchical (admin ⊃ write ⊃ read) except analysis:write. */
export function hasScope(principal: Principal, scope: TokenScope): boolean {
  if (principal.kind === 'session') return true;
  if (principal.kind === 'project') return scope === 'analysis:write';
  if (scope === 'analysis:write') return principal.scopes.includes('analysis:write');
  return principal.scopes.some((s) => s !== 'analysis:write' && RANK[s] >= RANK[scope]);
}

export function requirePrincipal(request: FastifyRequest): Principal {
  if (!request.principal) throw unauthenticated();
  return request.principal;
}

export function requireUser(request: FastifyRequest, scope: AccessScope = 'read'): UserPrincipal {
  const principal = requirePrincipal(request);
  if (principal.kind === 'project') {
    throw forbidden(
      'TOKEN_NOT_ALLOWED',
      'Project analysis tokens can only upload and read analyses',
    );
  }
  if (!hasScope(principal, scope))
    throw forbidden('INSUFFICIENT_SCOPE', `This token lacks the "${scope}" scope`);
  return principal;
}

export function requireSession(request: FastifyRequest): Extract<Principal, { kind: 'session' }> {
  const principal = requirePrincipal(request);
  if (principal.kind !== 'session') {
    throw forbidden('SESSION_REQUIRED', 'This action requires a browser session, not a token');
  }
  return principal;
}

export function requireInstanceAdmin(request: FastifyRequest): UserPrincipal {
  const principal = requireUser(request, 'admin');
  if (!principal.user.isInstanceAdmin) throw forbidden('FORBIDDEN', 'Instance administrators only');
  return principal;
}

export interface AccessContext {
  db: Executor;
}

type AccessDeps = { db: Db };

/** The access context of a request (rbac-audit.md §5); give `db` to read inside a transaction. */
export function accessOf(deps: AccessDeps): AccessContext & { db: Db };
export function accessOf(deps: AccessDeps, db: Executor): AccessContext;
export function accessOf(deps: AccessDeps, db: Executor = deps.db): AccessContext {
  return { db };
}

/**
 * rbac-audit.md §3.3 steps 3–5: 404 when the caller holds not even `visibility` (the object is
 * invisible to it), 403 FORBIDDEN when its role lacks `permission` (whatever the token), 403
 * INSUFFICIENT_SCOPE when the role allows it but the token lacks the permission's scope.
 */
export function requirePermission<P extends Permission>(
  principal: UserPrincipal,
  granted: ReadonlySet<P>,
  permission: P,
  visibility: P,
  what: string,
): void {
  if (!granted.has(visibility)) throw notFound(what);
  if (!granted.has(permission)) throw forbidden('FORBIDDEN', 'Your role does not allow this');
  const scope = permissionScope(permission);
  if (!hasScope(principal, scope)) {
    throw forbidden('INSUFFICIENT_SCOPE', `This token lacks the "${scope}" scope`);
  }
}

export interface OrganizationAccess {
  organizationId: string;
  /** The organisation's key (an audit event's organization reference, rbac-audit.md §8). */
  organizationKey: string;
  role: OrganizationRole | null;
  permissions: ReadonlySet<OrganizationPermission>;
}

/**
 * One query: the organisation, the caller's membership, and whether it has a grant in it. Then
 * rbac-audit.md §3.3: 404, 403 FORBIDDEN, 403 INSUFFICIENT_SCOPE.
 */
export async function requireOrganizationAccess(
  access: AccessContext,
  principal: UserPrincipal,
  organizationId: string,
  permission: OrganizationPermission,
): Promise<OrganizationAccess> {
  const [row] = await access.db
    .select({
      organizationKey: organizations.key,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, organizations.id),
    })
    .from(organizations)
    .leftJoin(memberships, memberOf(principal.user, organizations.id))
    .where(eq(organizations.id, organizationId));
  const permissions = row
    ? organizationPermissions(organizationFacts(principal.user, row))
    : NO_PERMISSIONS;
  requirePermission(principal, permissions, permission, 'org.read', 'Organization');
  // requirePermission refused a missing organisation (it holds not even org.read).
  if (!row) throw notFound('Organization');
  return {
    organizationId,
    organizationKey: row.organizationKey,
    role: row.organizationRole ?? null,
    permissions,
  };
}

/**
 * GET /users/lookup (rbac-audit.md §3.4 notes): an instance admin, or a user holding
 * `org.members.manage` in at least one organisation, with a token of the `admin` scope.
 */
export async function requireMembersManager(
  access: AccessContext,
  principal: UserPrincipal,
): Promise<void> {
  if (!hasScope(principal, 'admin')) {
    throw forbidden('INSUFFICIENT_SCOPE', 'This token lacks the "admin" scope');
  }
  if (principal.user.isInstanceAdmin) return;
  const rows = await access.db
    .select({ role: memberships.role })
    .from(memberships)
    .where(eq(memberships.userId, principal.user.id));
  const manages = rows.some((r) =>
    organizationPermissions({
      instanceAdmin: false,
      organizationRole: r.role,
      projectRole: null,
      hasProjectGrantInOrganization: false,
    }).has('org.members.manage'),
  );
  if (!manages) throw forbidden('FORBIDDEN', 'Your role does not allow this');
}
