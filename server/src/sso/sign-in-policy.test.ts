import { describe, expect, it } from 'vitest';
import { effectivePasswordPolicy, mayUsePassword } from './sign-in-policy';

const limited = { passwordSignIn: 'break_glass_only' as const, breakGlassUserIds: ['bg'] };
const everyone = { passwordSignIn: 'everyone' as const, breakGlassUserIds: [] };
const admin = { id: 'bg', active: true, isInstanceAdmin: true };
const alice = { id: 'alice', active: true, isInstanceAdmin: false };

describe('the password policy (sso-scim.md §10, ruling SS6)', () => {
  it.each([
    [everyone, { sso: true, forced: false }, 'everyone'],
    [limited, { sso: true, forced: false }, 'break_glass_only'],
    [limited, { sso: false, forced: false }, 'everyone'],
    [limited, { sso: true, forced: true }, 'everyone'],
  ])('%j with %j is %s', (stored, facts, expected) => {
    expect(effectivePasswordPolicy(stored, facts)).toBe(expected);
  });

  it('lets a listed active instance admin in, and nobody else, while limited', () => {
    const facts = { sso: true, forced: false };
    expect(mayUsePassword(admin, limited, facts)).toEqual({ allowed: true, forced: false });
    expect(mayUsePassword(alice, limited, facts)).toEqual({ allowed: false, forced: false });
    expect(mayUsePassword({ ...admin, isInstanceAdmin: false }, limited, facts)).toEqual({
      allowed: false,
      forced: false,
    });
    expect(mayUsePassword({ ...admin, active: false }, limited, facts)).toEqual({
      allowed: false,
      forced: false,
    });
  });

  it('marks a sign-in that only the variable allowed', () => {
    expect(mayUsePassword(alice, limited, { sso: true, forced: true })).toEqual({
      allowed: true,
      forced: true,
    });
    expect(mayUsePassword(admin, limited, { sso: true, forced: true })).toEqual({
      allowed: true,
      forced: false,
    });
    expect(mayUsePassword(alice, everyone, { sso: true, forced: true })).toEqual({
      allowed: true,
      forced: false,
    });
  });
});
