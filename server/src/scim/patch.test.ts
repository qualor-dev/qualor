import { describe, expect, it } from 'vitest';
import { applyGroupPatch, applyUserPatch, scimBoolean, type UserState } from './patch';

const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const base: UserState = {
  userName: 'alice@acme.example',
  externalId: 'e1',
  displayName: 'Alice',
  name: {},
  email: 'alice@acme.example',
  active: true,
};
const ops = (...Operations: unknown[]) => ({ schemas: [PATCH], Operations });
const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const CORE_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';

describe('SCIM PATCH for Users (sso-scim.md §12.6)', () => {
  it.each<[string, unknown, Partial<UserState>]>([
    [
      'Entra deactivation',
      ops({ op: 'Replace', path: 'active', value: 'False' }),
      { active: false },
    ],
    ['Okta deactivation', ops({ op: 'replace', value: { active: false } }), { active: false }],
    [
      'a display name',
      ops({ op: 'replace', path: 'displayName', value: 'Alice B' }),
      { displayName: 'Alice B' },
    ],
    [
      'the work email by filter path',
      ops({ op: 'replace', path: 'emails[type eq "work"].value', value: 'a2@acme.example' }),
      { email: 'a2@acme.example' },
    ],
    [
      'the primary email by filter path',
      ops({ op: 'Replace', path: 'emails[primary eq true].value', value: 'a3@acme.example' }),
      { email: 'a3@acme.example' },
    ],
    [
      'given and family names',
      ops(
        { op: 'add', path: 'name.givenName', value: 'Al' },
        { op: 'add', path: 'name.familyName', value: 'Ice' },
      ),
      { name: { givenName: 'Al', familyName: 'Ice' } },
    ],
    [
      'an ignored extension attribute',
      ops({ op: 'replace', path: `${ENTERPRISE}:manager`, value: { value: 'x' } }),
      {},
    ],
    ['remove externalId', ops({ op: 'remove', path: 'externalId' }), { externalId: null }],
    // Entra's and Okta's other shapes.
    ['Entra reactivation', ops({ op: 'Replace', path: 'active', value: 'True' }), {}],
    [
      'Entra deactivation after reactivation, in order',
      ops(
        { op: 'Replace', path: 'active', value: 'true' },
        { op: 'Replace', path: 'active', value: 'FALSE' },
      ),
      { active: false },
    ],
    [
      'Entra no-path values named as paths',
      ops({
        op: 'Replace',
        value: { 'name.givenName': 'Al', 'emails[type eq "work"].value': 'w@acme.example' },
      }),
      { name: { givenName: 'Al' }, email: 'w@acme.example' },
    ],
    [
      'Entra default attributes Qualor does not store',
      ops(
        { op: 'Add', path: 'title', value: 'Engineer' },
        { op: 'Add', path: 'preferredLanguage', value: 'en-US' },
        { op: 'Add', path: 'phoneNumbers[type eq "work"].value', value: '+1 555' },
        { op: 'Add', path: 'addresses[type eq "work"].streetAddress', value: '1 Main St' },
        { op: 'Add', path: `${ENTERPRISE}:employeeId`, value: '42' },
        { op: 'Add', path: `${ENTERPRISE}:manager`, value: 'm1' },
      ),
      {},
    ],
    [
      'Okta profile replace with a nested name and the extension object',
      ops({
        op: 'replace',
        value: {
          id: 'ignored',
          userName: 'alice2@acme.example',
          name: { givenName: 'Al', familyName: 'Ice', formatted: 'Al Ice' },
          displayName: 'Al Ice',
          [ENTERPRISE]: { department: 'R&D' },
        },
      }),
      {
        userName: 'alice2@acme.example',
        displayName: 'Al Ice',
        name: { givenName: 'Al', familyName: 'Ice', formatted: 'Al Ice' },
      },
    ],
    [
      'a core-schema URN path',
      ops({ op: 'replace', path: `${CORE_USER}:displayName`, value: 'Full' }),
      { displayName: 'Full' },
    ],
    [
      'the core-schema object without a path',
      ops({ op: 'replace', value: { [CORE_USER]: { displayName: 'Nested' } } }),
      { displayName: 'Nested' },
    ],
    [
      'paths and ops in any case',
      ops(
        { op: 'REPLACE', path: 'DISPLAYNAME', value: 'Up' },
        { op: 'Add', path: 'Name.GivenName', value: 'G' },
        { op: 'replace', path: 'EMAILS[TYPE EQ "WORK"].VALUE', value: 'u@acme.example' },
      ),
      { displayName: 'Up', name: { givenName: 'G' }, email: 'u@acme.example' },
    ],
    [
      'emails as a list: the primary one',
      ops({
        op: 'replace',
        path: 'emails',
        value: [
          { value: 'home@acme.example', type: 'home' },
          { value: 'p@acme.example', type: 'other', primary: true },
          { value: 'w@acme.example', type: 'work' },
        ],
      }),
      { email: 'p@acme.example' },
    ],
    [
      'emails as a list: else the first work one',
      ops({
        op: 'add',
        path: 'emails',
        value: [
          { value: 'home@acme.example', type: 'home' },
          { value: 'w@acme.example', type: 'work' },
        ],
      }),
      { email: 'w@acme.example' },
    ],
    [
      'emails as a list: else the first',
      ops({ op: 'replace', value: { emails: [{ value: 'h@acme.example', type: 'home' }] } }),
      { email: 'h@acme.example' },
    ],
    [
      'Entra primary as the string "True"',
      ops({
        op: 'replace',
        path: 'emails',
        value: [
          { value: 'w@acme.example', type: 'work' },
          { value: 'p@acme.example', primary: 'True' },
        ],
      }),
      { email: 'p@acme.example' },
    ],
    ['removing the emails', ops({ op: 'remove', path: 'emails' }), { email: null }],
    [
      'removing the display name',
      ops({ op: 'remove', path: 'displayName' }),
      { displayName: null },
    ],
    [
      'an empty string clears an optional attribute',
      ops({ op: 'replace', path: 'externalId', value: '' }),
      { externalId: null },
    ],
    [
      'null clears an optional attribute',
      ops({ op: 'replace', path: 'displayName', value: null }),
      { displayName: null },
    ],
    [
      'removing the work email by filter path',
      ops({ op: 'remove', path: 'emails[type eq "work"].value' }),
      { email: null },
    ],
    [
      'a userName change',
      ops({ op: 'replace', path: 'userName', value: 'al@acme.example' }),
      { userName: 'al@acme.example' },
    ],
    [
      'a value of exactly 255 characters',
      ops({ op: 'replace', path: 'displayName', value: 'x'.repeat(255) }),
      { displayName: 'x'.repeat(255) },
    ],
    [
      '255 characters counted as code points',
      ops({ op: 'replace', path: 'displayName', value: String.fromCodePoint(0x1f600).repeat(255) }),
      { displayName: String.fromCodePoint(0x1f600).repeat(255) },
    ],
    [
      'name members and email forms Qualor does not store',
      ops(
        { op: 'add', path: 'name.middleName', value: 'M' },
        { op: 'add', path: 'emails[type eq "home"].value', value: 'h@acme.example' },
        { op: 'add', path: 'members', value: [{ value: 'g1' }] },
        { op: 'replace', value: { name: { honorificPrefix: 'Dr' } } },
      ),
      {},
    ],
    [
      '100 operations',
      ops(...Array.from({ length: 100 }, () => ({ op: 'remove', path: 'title' }))),
      {},
    ],
    [
      'the primary email by a string-boolean filter',
      ops({ op: 'replace', path: 'emails[primary eq "True"].value', value: 'p@acme.example' }),
      { email: 'p@acme.example' },
    ],
    [
      'the primary email by a lower-case string-boolean filter',
      ops({ op: 'replace', path: 'emails[primary eq "true"].value', value: 'p@acme.example' }),
      { email: 'p@acme.example' },
    ],
    [
      'a filter separated by tabs',
      ops({ op: 'replace', path: 'emails[type\teq\t"work"].value', value: 't@acme.example' }),
      { email: 't@acme.example' },
    ],
    [
      'a non-primary filter is not the primary email',
      ops(
        { op: 'replace', path: 'emails[primary eq "False"].value', value: 'n@acme.example' },
        { op: 'replace', path: 'emails[primary eq false].value', value: 'n@acme.example' },
        { op: 'replace', path: 'emails[primary eq "maybe"].value', value: 'n@acme.example' },
      ),
      {},
    ],
  ])('%s', (_n, body, change) => {
    expect(applyUserPatch(base, body)).toEqual({
      ...base,
      ...change,
      name: { ...base.name, ...(change.name ?? {}) },
    });
  });

  it('removes one name member and keeps the others', () => {
    const named: UserState = {
      ...base,
      name: { givenName: 'A', familyName: 'B', formatted: 'A B' },
    };
    expect(applyUserPatch(named, ops({ op: 'remove', path: 'name.familyName' })).name).toEqual({
      givenName: 'A',
      formatted: 'A B',
    });
    expect(applyUserPatch(named, ops({ op: 'remove', path: 'name' })).name).toEqual({});
    expect(
      applyUserPatch(named, ops({ op: 'replace', path: 'name', value: { givenName: 'Z' } })).name,
    ).toEqual({ givenName: 'Z', familyName: 'B', formatted: 'A B' });
  });

  it('is pure: the state passed in is never changed', () => {
    const state: UserState = { ...base, name: { givenName: 'A' } };
    const frozen = JSON.stringify(state);
    applyUserPatch(
      state,
      ops(
        { op: 'replace', path: 'name.givenName', value: 'B' },
        { op: 'replace', path: 'active', value: false },
      ),
    );
    expect(JSON.stringify(state)).toBe(frozen);
  });

  it('applies all or nothing: a bad later operation throws, and nothing is returned', () => {
    expect(() =>
      applyUserPatch(
        base,
        ops(
          { op: 'replace', path: 'active', value: false },
          { op: 'replace', path: 'active', value: 'maybe' },
        ),
      ),
    ).toThrow(expect.objectContaining({ scimType: 'invalidValue' }));
  });

  it.each<[string, unknown, string]>([
    ['no Operations', { schemas: [PATCH] }, 'invalidSyntax'],
    ['the wrong schema', { schemas: ['x'], Operations: [] }, 'invalidSyntax'],
    [
      '101 operations',
      ops(
        ...Array.from({ length: 101 }, () => ({ op: 'replace', path: 'displayName', value: 'x' })),
      ),
      'tooMany',
    ],
    ['an unknown op', ops({ op: 'move', path: 'active', value: true }), 'invalidSyntax'],
    ['a malformed path', ops({ op: 'replace', path: 'emails[', value: 'x' }), 'invalidPath'],
    ['removing userName', ops({ op: 'remove', path: 'userName' }), 'mutability'],
    ['active as "maybe"', ops({ op: 'replace', path: 'active', value: 'maybe' }), 'invalidValue'],
    [
      'a displayName over 255',
      ops({ op: 'replace', path: 'displayName', value: 'x'.repeat(256) }),
      'invalidValue',
    ],
    // The envelope.
    ['a body that is not an object', 'x', 'invalidSyntax'],
    ['a null body', null, 'invalidSyntax'],
    ['an array body', [], 'invalidSyntax'],
    ['no schemas', { Operations: [{ op: 'remove', path: 'title' }] }, 'invalidSyntax'],
    ['zero operations', ops(), 'invalidSyntax'],
    ['Operations that is not a list', { schemas: [PATCH], Operations: {} }, 'invalidSyntax'],
    ['an operation that is not an object', ops('remove'), 'invalidSyntax'],
    ['an op that is not a string', ops({ op: 1, path: 'active', value: true }), 'invalidSyntax'],
    ['a missing op', ops({ path: 'active', value: true }), 'invalidSyntax'],
    ['a path that is not a string', ops({ op: 'replace', path: 1, value: 'x' }), 'invalidPath'],
    ['an empty path', ops({ op: 'replace', path: '', value: 'x' }), 'invalidPath'],
    [
      'a path of 10 000 characters',
      ops({ op: 'replace', path: 'a'.repeat(10_000), value: 'x' }),
      'invalidPath',
    ],
    // Paths.
    [
      'a path with a space',
      ops({ op: 'replace', path: 'display Name', value: 'x' }),
      'invalidPath',
    ],
    [
      'an unclosed filter',
      ops({ op: 'replace', path: 'emails[type eq "work"', value: 'x' }),
      'invalidPath',
    ],
    [
      'an unterminated quote',
      ops({ op: 'replace', path: 'emails[type eq "work].value', value: 'x' }),
      'invalidPath',
    ],
    [
      'nested filters',
      ops({ op: 'replace', path: 'emails[type eq "a"][x eq "b"]', value: 'x' }),
      'invalidPath',
    ],
    [
      'a filter with or',
      ops({ op: 'replace', path: 'emails[type eq "work" or primary eq true].value', value: 'x' }),
      'invalidPath',
    ],
    ['parentheses', ops({ op: 'replace', path: '(displayName)', value: 'x' }), 'invalidPath'],
    ['a malformed urn', ops({ op: 'replace', path: 'urn:', value: 'x' }), 'invalidPath'],
    [
      'a urn with a filter',
      ops({ op: 'replace', path: `${ENTERPRISE}:manager[value eq "x"]`, value: 'x' }),
      'invalidPath',
    ],
    [
      'a path starting with a digit',
      ops({ op: 'replace', path: '1name', value: 'x' }),
      'invalidPath',
    ],
    [
      'a sub-attribute of active',
      ops({ op: 'replace', path: 'active.value', value: true }),
      'invalidPath',
    ],
    [
      'a filter on userName',
      ops({ op: 'replace', path: 'userName[value eq "x"]', value: 'x' }),
      'invalidPath',
    ],
    ['three levels', ops({ op: 'replace', path: 'name.givenName.x', value: 'x' }), 'invalidPath'],
    [
      'a newline in a filter',
      ops({ op: 'replace', path: 'emails[type\neq "work"].value', value: 'x' }),
      'invalidPath',
    ],
    // Object.prototype's names, as a path segment or a no-path key, in any case.
    ...[
      'constructor',
      'prototype',
      '__proto__',
      'toString',
      'hasOwnProperty',
      'valueOf',
      'CONSTRUCTOR',
      'name.constructor',
      'name.toString',
      'emails[constructor eq "x"].value',
      'emails[type eq "work"].valueOf',
      'prototype.value',
      `${ENTERPRISE}:constructor`,
      'urn:example:constructor:1.0:User:x',
      `${CORE_USER}:hasOwnProperty`,
    ].flatMap((path): [string, unknown, string][] => [
      [`the path ${path}`, ops({ op: 'replace', path, value: 'x' }), 'invalidPath'],
      [`the no-path key ${path}`, ops({ op: 'replace', value: { [path]: 'x' } }), 'invalidPath'],
    ]),
    [
      'a __proto__ key parsed from JSON',
      JSON.parse(
        `{"schemas":["${PATCH}"],"Operations":[{"op":"replace","value":{"__proto__":{"active":false}}}]}`,
      ),
      'invalidPath',
    ],
    [
      'the core-schema object holding a forbidden key',
      ops({ op: 'replace', value: { [CORE_USER]: { valueOf: 'x' } } }),
      'invalidPath',
    ],
    // No path.
    ['remove without a path', ops({ op: 'remove' }), 'noTarget'],
    ['a no-path value that is not an object', ops({ op: 'replace', value: 'x' }), 'invalidValue'],
    ['a no-path value that is a list', ops({ op: 'replace', value: [] }), 'invalidValue'],
    [
      'a no-path value with a malformed key',
      ops({ op: 'replace', value: { 'emails[': 'x' } }),
      'invalidPath',
    ],
    [
      'a no-path value with too many members',
      ops({
        op: 'replace',
        value: Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`x${i}`, 'v'])),
      }),
      'tooMany',
    ],
    ['a no-path userName of null', ops({ op: 'replace', value: { userName: null } }), 'mutability'],
    // Values.
    ['add without a value', ops({ op: 'add', path: 'displayName' }), 'invalidValue'],
    ['removing active', ops({ op: 'remove', path: 'active' }), 'mutability'],
    ['active as a number', ops({ op: 'replace', path: 'active', value: 0 }), 'invalidValue'],
    ['active as null', ops({ op: 'replace', path: 'active', value: null }), 'invalidValue'],
    ['active as "yes"', ops({ op: 'replace', value: { active: 'yes' } }), 'invalidValue'],
    ['an empty userName', ops({ op: 'replace', path: 'userName', value: '' }), 'invalidValue'],
    ['a userName of null', ops({ op: 'replace', path: 'userName', value: null }), 'mutability'],
    [
      'a userName over 255',
      ops({ op: 'replace', path: 'userName', value: 'u'.repeat(256) }),
      'invalidValue',
    ],
    [
      'a number as display name',
      ops({ op: 'replace', path: 'displayName', value: 5 }),
      'invalidValue',
    ],
    [
      'an object as display name',
      ops({ op: 'replace', path: 'displayName', value: { a: 1 } }),
      'invalidValue',
    ],
    [
      'U+0000 in a value',
      ops({ op: 'replace', path: 'displayName', value: `a${String.fromCharCode(0)}` }),
      'invalidValue',
    ],
    [
      'a lone surrogate',
      ops({ op: 'replace', path: 'displayName', value: `a${String.fromCharCode(0xd800)}` }),
      'invalidValue',
    ],
    [
      'an externalId over 255',
      ops({ op: 'replace', path: 'externalId', value: 'e'.repeat(256) }),
      'invalidValue',
    ],
    [
      'a given name over 255',
      ops({ op: 'replace', path: 'name.givenName', value: 'g'.repeat(256) }),
      'invalidValue',
    ],
    [
      'a name that is not an object',
      ops({ op: 'replace', path: 'name', value: 'Al' }),
      'invalidValue',
    ],
    [
      'a name with a number',
      ops({ op: 'replace', value: { name: { givenName: 1 } } }),
      'invalidValue',
    ],
    [
      'an email without @',
      ops({ op: 'replace', path: 'emails[type eq "work"].value', value: 'nope' }),
      'invalidValue',
    ],
    [
      'an email over 320',
      ops({
        op: 'replace',
        path: 'emails[type eq "work"].value',
        value: `${'e'.repeat(310)}@acme.example`,
      }),
      'invalidValue',
    ],
    [
      'emails that are not a list',
      ops({ op: 'replace', path: 'emails', value: 'a@b.c' }),
      'invalidValue',
    ],
    [
      'an email entry without a value',
      ops({ op: 'replace', path: 'emails', value: [{ type: 'work' }] }),
      'invalidValue',
    ],
    [
      'an email entry that is a string',
      ops({ op: 'replace', path: 'emails', value: ['a@b.c'] }),
      'invalidValue',
    ],
    [
      'more than 100 emails',
      ops({
        op: 'replace',
        path: 'emails',
        value: Array.from({ length: 101 }, (_, i) => ({ value: `a${i}@b.c` })),
      }),
      'tooMany',
    ],
  ])('refuses %s', (_n, body, scimType) => {
    expect(() => applyUserPatch(base, body)).toThrow(
      expect.objectContaining({ status: 400, scimType }),
    );
  });

  it('refuses hostile paths quickly', () => {
    const started = performance.now();
    for (const path of [
      `urn:${':'.repeat(100_000)}`,
      `urn:${'a:'.repeat(100_000)}1`,
      `emails[${'('.repeat(100_000)}`,
      `emails[type eq "${'\\"'.repeat(100_000)}"].value`,
      `${'a.'.repeat(100_000)}a`,
    ]) {
      expect(() => applyUserPatch(base, ops({ op: 'replace', path, value: 'x' }))).toThrow(
        expect.objectContaining({ scimType: 'invalidPath' }),
      );
    }
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it('never echoes a value in the error detail', () => {
    try {
      applyUserPatch(base, ops({ op: 'replace', path: 'active', value: 'secret-looking-value' }));
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain('secret-looking-value');
    }
  });
});

describe('scimBoolean (sso-scim.md §12.6)', () => {
  it.each([
    [true, true],
    [false, false],
    ['true', true],
    ['True', true],
    ['TRUE', true],
    ['false', false],
    ['False', false],
    ['fAlSe', false],
  ])('reads %j as %s', (input, expected) => {
    expect(scimBoolean(input)).toBe(expected);
  });

  it.each([0, 1, null, undefined, '', ' true', 'yes', 'on', {}, []])('refuses %j', (input) => {
    expect(() => scimBoolean(input)).toThrow(
      expect.objectContaining({ status: 400, scimType: 'invalidValue' }),
    );
  });
});

describe('SCIM PATCH for Groups (sso-scim.md §12.7)', () => {
  it('adds and removes members, including Entra’s filter path', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'Add', path: 'members', value: [{ value: 'u1' }, { value: 'u2' }] },
          { op: 'Remove', path: 'members[value eq "u3"]' },
        ),
      ),
    ).toEqual({ add: ['u1', 'u2'], remove: ['u3'], replaceMembers: null });
  });

  it('renames, and replaces the whole member list', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'replace', value: { displayName: 'New', externalId: 'x' } },
          { op: 'replace', path: 'members', value: [{ value: 'u9' }] },
        ),
      ),
    ).toEqual({ displayName: 'New', externalId: 'x', add: [], remove: [], replaceMembers: ['u9'] });
  });

  it('refuses more than 1 000 member changes', () => {
    const many = Array.from({ length: 1_001 }, (_, i) => ({ value: `u${i}` }));
    expect(() => applyGroupPatch(ops({ op: 'add', path: 'members', value: many }))).toThrow(
      expect.objectContaining({ scimType: 'tooMany' }),
    );
  });

  it('counts member changes across operations', () => {
    const half = (from: number) =>
      Array.from({ length: 501 }, (_, i) => ({ value: `u${from + i}` }));
    expect(() =>
      applyGroupPatch(
        ops(
          { op: 'add', path: 'members', value: half(0) },
          { op: 'remove', path: 'members', value: half(1_000) },
        ),
      ),
    ).toThrow(expect.objectContaining({ status: 400, scimType: 'tooMany' }));
    expect(
      applyGroupPatch(
        ops({
          op: 'add',
          path: 'members',
          value: Array.from({ length: 1_000 }, (_, i) => ({ value: `u${i}` })),
        }),
      ).add,
    ).toHaveLength(1_000);
  });

  it('handles Okta’s shapes: a no-path rename with the id, and a remove by filter path', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'replace', value: { id: 'g1', displayName: 'Renamed' } },
          { op: 'remove', path: 'members[value eq "u1"]' },
          { op: 'add', path: 'members', value: [{ value: 'u2', display: 'Bob' }] },
        ),
      ),
    ).toEqual({ displayName: 'Renamed', add: ['u2'], remove: ['u1'], replaceMembers: null });
  });

  it('handles Entra’s shapes: a remove with a value list, ops in any case', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'Remove', path: 'members', value: [{ value: 'u1' }, { value: 'u2' }] },
          { op: 'Replace', path: 'displayName', value: 'Entra' },
          { op: 'Add', path: 'externalId', value: 'ext' },
        ),
      ),
    ).toEqual({
      displayName: 'Entra',
      externalId: 'ext',
      add: [],
      remove: ['u1', 'u2'],
      replaceMembers: null,
    });
  });

  it('applies member operations in order, without duplicates', () => {
    expect(
      applyGroupPatch(
        ops(
          {
            op: 'add',
            path: 'members',
            value: [{ value: 'u1' }, { value: 'u1' }, { value: 'u2' }],
          },
          { op: 'remove', path: 'members[value eq "u1"]' },
          { op: 'remove', path: 'members[value eq "u3"]' },
          { op: 'add', path: 'members', value: [{ value: 'u3' }] },
        ),
      ),
    ).toEqual({ add: ['u2', 'u3'], remove: ['u1'], replaceMembers: null });
  });

  it('applies adds and removes after a replace onto the new list', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'add', path: 'members', value: [{ value: 'u0' }] },
          { op: 'replace', path: 'members', value: [{ value: 'u1' }, { value: 'u2' }] },
          { op: 'add', path: 'members', value: [{ value: 'u3' }] },
          { op: 'remove', path: 'members[value eq "u1"]' },
        ),
      ),
    ).toEqual({ add: [], remove: [], replaceMembers: ['u2', 'u3'] });
  });

  it('removes every member without a value, and clears externalId', () => {
    expect(
      applyGroupPatch(ops({ op: 'remove', path: 'members' }, { op: 'remove', path: 'externalId' })),
    ).toEqual({ externalId: null, add: [], remove: [], replaceMembers: [] });
  });

  it('ignores a well-formed attribute it does not store', () => {
    expect(
      applyGroupPatch(
        ops(
          { op: 'replace', path: 'urn:example:ext:1.0:Group:costCenter', value: '7' },
          { op: 'replace', value: { 'urn:example:ext:1.0:Group': { costCenter: '7' } } },
          { op: 'replace', path: 'userName', value: 'x' },
        ),
      ),
    ).toEqual({ add: [], remove: [], replaceMembers: null });
  });

  it.each<[string, unknown, string]>([
    ['no Operations', { schemas: [PATCH] }, 'invalidSyntax'],
    ['the wrong schema', { schemas: ['x'], Operations: [] }, 'invalidSyntax'],
    [
      '101 operations',
      ops(
        ...Array.from({ length: 101 }, () => ({ op: 'replace', path: 'displayName', value: 'x' })),
      ),
      'tooMany',
    ],
    ['an unknown op', ops({ op: 'copy', path: 'members', value: [] }), 'invalidSyntax'],
    ['a malformed path', ops({ op: 'remove', path: 'members[value eq "u1"' }), 'invalidPath'],
    [
      'a filter on another attribute',
      ops({ op: 'remove', path: 'members[display eq "u1"]' }),
      'invalidPath',
    ],
    [
      'a filter with another operator',
      ops({ op: 'remove', path: 'members[value ne "u1"]' }),
      'invalidPath',
    ],
    [
      'a filter with an unterminated quote',
      ops({ op: 'remove', path: 'members[value eq "u1]' }),
      'invalidPath',
    ],
    [
      'add by a filter path',
      ops({ op: 'add', path: 'members[value eq "u1"]', value: [] }),
      'invalidPath',
    ],
    ['removing displayName', ops({ op: 'remove', path: 'displayName' }), 'mutability'],
    [
      'the path constructor',
      ops({ op: 'replace', path: 'constructor', value: 'x' }),
      'invalidPath',
    ],
    ['the path members.valueOf', ops({ op: 'remove', path: 'members.valueOf' }), 'invalidPath'],
    ['the no-path key toString', ops({ op: 'replace', value: { toString: 'x' } }), 'invalidPath'],
    [
      'a newline in a members filter',
      ops({ op: 'remove', path: 'members[value\neq "u1"]' }),
      'invalidPath',
    ],
    [
      'an empty displayName',
      ops({ op: 'replace', path: 'displayName', value: '' }),
      'invalidValue',
    ],
    [
      'a displayName over 255',
      ops({ op: 'replace', path: 'displayName', value: 'x'.repeat(256) }),
      'invalidValue',
    ],
    [
      'members that are not a list',
      ops({ op: 'add', path: 'members', value: { value: 'u1' } }),
      'invalidValue',
    ],
    [
      'a member without a value',
      ops({ op: 'add', path: 'members', value: [{ display: 'x' }] }),
      'invalidValue',
    ],
    [
      'a member value that is a number',
      ops({ op: 'add', path: 'members', value: [{ value: 1 }] }),
      'invalidValue',
    ],
    [
      'an empty member value',
      ops({ op: 'add', path: 'members', value: [{ value: '' }] }),
      'invalidValue',
    ],
    [
      'a member value with U+0000',
      ops({ op: 'add', path: 'members', value: [{ value: `u${String.fromCharCode(0)}` }] }),
      'invalidValue',
    ],
    [
      'a member value over 255',
      ops({ op: 'add', path: 'members', value: [{ value: 'u'.repeat(256) }] }),
      'invalidValue',
    ],
    ['add members without a value', ops({ op: 'add', path: 'members' }), 'invalidValue'],
    ['remove without a path', ops({ op: 'remove' }), 'noTarget'],
    [
      'a no-path value that is not an object',
      ops({ op: 'add', value: [{ value: 'u1' }] }),
      'invalidValue',
    ],
  ])('refuses %s', (_n, body, scimType) => {
    expect(() => applyGroupPatch(body)).toThrow(expect.objectContaining({ status: 400, scimType }));
  });
});
