import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import type { Executor } from '../db/client';
import type { AuditAction } from './catalogue';
import {
  ACCESS_REMOVING_ACTIONS,
  actorOf,
  anonymousActor,
  createAuditRecorder,
  removesAccess,
  SYSTEM_ACTOR,
  type AuditEventInput,
} from './recorder';

const user = { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60', username: 'alice' };

function request(principal: unknown, userAgent?: string): FastifyRequest {
  return {
    principal,
    ip: '10.0.0.5',
    headers: userAgent === undefined ? {} : { 'user-agent': userAgent },
  } as unknown as FastifyRequest;
}

describe('the audit actor (rbac-audit.md §9)', () => {
  it('is the session user, with no token', () => {
    expect(actorOf(request({ kind: 'session', user, sessionSecret: 's' }, 'ua'))).toEqual({
      actor: { type: 'user', userId: user.id, username: 'alice', tokenId: null },
      ip: '10.0.0.5',
      userAgent: 'ua',
    });
  });

  it('is the personal token user, with the token id and never the token', () => {
    const context = actorOf(
      request({
        kind: 'personal',
        user,
        tokenId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e61',
        scopes: [],
      }),
    );
    expect(context.actor).toEqual({
      type: 'user',
      userId: user.id,
      username: 'alice',
      tokenId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e61',
    });
    expect(context.userAgent).toBeNull();
  });

  it('is anonymous without a user (no principal, or a project token)', () => {
    expect(actorOf(request(null)).actor).toEqual({
      type: 'anonymous',
      userId: null,
      username: null,
    });
    expect(actorOf(request({ kind: 'project', tokenId: 't', projectId: 'p' })).actor).toEqual({
      type: 'anonymous',
      userId: null,
      username: null,
    });
  });

  it('names a failed sign-in’s user only when the typed name belongs to one', () => {
    expect(anonymousActor(request(null), null).actor).toEqual({
      type: 'anonymous',
      userId: null,
      username: null,
    });
    expect(anonymousActor(request(null), user).actor).toEqual({
      type: 'anonymous',
      userId: user.id,
      username: 'alice',
    });
  });

  it('clips the user agent to 256 characters', () => {
    expect(actorOf(request(null, 'x'.repeat(300))).userAgent).toBe('x'.repeat(256));
  });

  it('keeps the system actor frozen', () => {
    expect(Object.isFrozen(SYSTEM_ACTOR)).toBe(true);
    expect(SYSTEM_ACTOR).toEqual({ actor: { type: 'system' }, ip: null, userAgent: null });
  });
});

describe('the access-removing events (rbac-audit.md §10.2.1)', () => {
  const target = { type: 'user' as const, id: user.id, label: 'alice' };
  const token = { type: 'token' as const, id: user.id, label: 'ci' };

  it('lists exactly the actions of the spec', () => {
    expect([...ACCESS_REMOVING_ACTIONS].sort()).toEqual(
      [
        'auth.sign_out',
        'token.revoked',
        'project_token.revoked',
        'user.updated',
        'member.removed',
        'member.role_changed',
        'project_member.removed',
        'project_member.role_changed',
        'scim.user_deactivated',
        'scim.user_deleted',
        'scim_token.revoked',
        'sso.identity_unlinked',
        'sso.connection_deleted',
      ].sort(),
    );
  });

  it.each([
    'scim.user_deactivated',
    'scim.user_deleted',
    'scim_token.revoked',
    'sso.identity_unlinked',
    'sso.connection_deleted',
  ])('%s removes access (rbac-audit.md §10.2.1, sso-scim.md §15)', (action) => {
    expect(ACCESS_REMOVING_ACTIONS.has(action as AuditAction)).toBe(true);
  });

  it('classifies the five SSO and SCIM actions as always removing access, never widening it', () => {
    const scimUser = {
      scimTokenId: user.id,
      connectionId: user.id,
      sessionsEnded: 1,
      tokensRevoked: 1,
    };
    expect(removesAccess({ action: 'scim.user_deactivated', target, details: scimUser })).toBe(
      true,
    );
    expect(removesAccess({ action: 'scim.user_deleted', target, details: scimUser })).toBe(true);
    expect(
      removesAccess({
        action: 'scim_token.revoked',
        target: { type: 'scim_token', id: user.id },
        details: { connectionId: user.id, name: 'Entra', prefix: 'qlr_scim_abc' },
      }),
    ).toBe(true);
    expect(
      removesAccess({
        action: 'sso.identity_unlinked',
        target,
        details: { connectionId: user.id, byAdmin: true },
      }),
    ).toBe(true);
    expect(
      removesAccess({
        action: 'sso.connection_deleted',
        target: { type: 'sso_connection', id: user.id },
        details: { name: 'Acme', protocol: 'oidc', identities: 1, managedMemberships: 0 },
      }),
    ).toBe(true);
  });

  it('counts sign-out, a revocation and a removal always', () => {
    expect(removesAccess({ action: 'auth.sign_out', target, details: {} })).toBe(true);
    for (const action of ['token.revoked', 'project_token.revoked'] as const) {
      expect(removesAccess({ action, target: token, details: { name: 'ci', prefix: 'q' } })).toBe(
        true,
      );
    }
    for (const action of ['member.removed', 'project_member.removed'] as const) {
      expect(removesAccess({ action, target, details: { role: 'member' } })).toBe(true);
    }
  });

  it('counts a role change only when it demotes', () => {
    for (const action of ['member.role_changed', 'project_member.role_changed'] as const) {
      expect(removesAccess({ action, target, details: { from: 'member', to: 'viewer' } })).toBe(
        true,
      );
      expect(
        removesAccess({ action, target, details: { from: 'project_admin', to: 'member' } }),
      ).toBe(true);
      expect(removesAccess({ action, target, details: { from: 'viewer', to: 'member' } })).toBe(
        false,
      );
      expect(removesAccess({ action, target, details: { from: 'member', to: 'member' } })).toBe(
        false,
      );
    }
    expect(
      removesAccess({
        action: 'member.role_changed',
        target,
        details: { from: 'admin', to: 'project_admin' },
      }),
    ).toBe(true);
    expect(
      removesAccess({
        action: 'member.role_changed',
        target,
        details: { from: 'project_admin', to: 'admin' },
      }),
    ).toBe(false);
  });

  it('counts a user change only when it deactivates or demotes, without a password reset', () => {
    const updated = (
      changes: {
        field: 'displayName' | 'email' | 'active' | 'isInstanceAdmin';
        from: unknown;
        to: unknown;
      }[],
      passwordReset = false,
    ) =>
      removesAccess({
        action: 'user.updated',
        target,
        details: { changes, passwordReset },
      } as AuditEventInput);
    expect(updated([{ field: 'active', from: true, to: false }])).toBe(true);
    expect(updated([{ field: 'isInstanceAdmin', from: true, to: false }])).toBe(true);
    expect(
      updated([
        { field: 'active', from: true, to: false },
        { field: 'isInstanceAdmin', from: true, to: false },
      ]),
    ).toBe(true);
    expect(updated([{ field: 'active', from: false, to: true }])).toBe(false);
    expect(updated([{ field: 'isInstanceAdmin', from: false, to: true }])).toBe(false);
    expect(
      updated([
        { field: 'active', from: true, to: false },
        { field: 'displayName', from: 'A', to: 'B' },
      ]),
    ).toBe(false);
    expect(updated([{ field: 'active', from: true, to: false }], true)).toBe(false);
    expect(updated([], true)).toBe(false);
    expect(updated([])).toBe(false);
  });

  it('counts nothing else', () => {
    expect(removesAccess({ action: 'auth.sign_in', target, details: { method: 'password' } })).toBe(
      false,
    );
    expect(
      removesAccess({
        action: 'quality_gate.created',
        target: { type: 'quality_gate', id: user.id },
        details: { name: 'g' },
      }),
    ).toBe(false);
    expect(removesAccess({ action: 'member.added', target, details: { role: 'viewer' } })).toBe(
      false,
    );
  });
});

describe('recordOrSkipWhenAnchorMalformed (rbac-audit.md §10.2.1)', () => {
  it('skips only the anchor error: any other failure rejects, and nothing is logged', async () => {
    const error = vi.fn();
    const recorder = createAuditRecorder({ isActive: () => true, log: { error } });
    const failing = {
      transaction: async () => {
        throw new Error('connection lost');
      },
    } as unknown as Executor;
    await expect(
      recorder.recordOrSkipWhenAnchorMalformed(failing, SYSTEM_ACTOR, [
        {
          action: 'member.removed',
          target: { type: 'user', id: user.id, label: 'alice' },
          details: { role: 'member' },
        },
      ]),
    ).rejects.toThrow('connection lost');
    expect(error).not.toHaveBeenCalled();
  });
});
