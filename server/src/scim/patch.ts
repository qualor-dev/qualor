import { isStorableText } from '../audit/canonical';
import type { ScimName } from '../db/schema';
import { ScimError } from './errors';

export type { ScimName };

/**
 * The PATCH engine of sso-scim.md §12.6–§12.7: pure (no database), bounded, and all or nothing
 * (it returns a new state or throws a `ScimError`; the caller applies the result in one
 * transaction). Error details never echo a value from the request.
 */

export const PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const MAX_PATCH_OPERATIONS = 100;
/** sso-scim.md §12.7: member changes of one request, across its operations. */
export const MAX_MEMBER_CHANGES = 1_000;
/** Bounds on what one operation may carry (the body itself is at most 1 MiB, §12.1). */
const MAX_PATH_LENGTH = 512;
const MAX_OBJECT_MEMBERS = 100;
const MAX_EMAILS = 100;
const MAX_TEXT = 255;
const MAX_EMAIL = 320;

const CORE_SCHEMA = {
  User: 'urn:ietf:params:scim:schemas:core:2.0:user',
  Group: 'urn:ietf:params:scim:schemas:core:2.0:group',
} as const;
type Resource = keyof typeof CORE_SCHEMA;

export interface UserState {
  userName: string;
  externalId: string | null;
  displayName: string | null;
  name: ScimName;
  email: string | null;
  active: boolean;
}

/**
 * What a Group PATCH asks for. `replaceMembers` is the whole new member list when an operation
 * replaced it (later adds and removes already applied to it; `add` and `remove` are then empty);
 * otherwise null, and `add` and `remove` are disjoint, in the order first named.
 */
export interface GroupPatchResult {
  displayName?: string;
  externalId?: string | null;
  add: string[];
  remove: string[];
  replaceMembers: string[] | null;
}

type Op = 'add' | 'replace' | 'remove';

interface Operation {
  op: Op;
  path: string | undefined;
  /** `undefined` when the operation has no `value` member. */
  value: unknown;
}

// ─── Errors ─────────────────────────────────────────────────────────────────

const invalidSyntax = (detail: string) => new ScimError(400, 'invalidSyntax', detail);
const invalidPath = () =>
  new ScimError(400, 'invalidPath', 'An operation names a path this server cannot read');
const invalidValue = (detail: string) => new ScimError(400, 'invalidValue', detail);
const mutability = (detail: string) => new ScimError(400, 'mutability', detail);
const tooMany = (detail: string) => new ScimError(400, 'tooMany', detail);

// ─── Reading JSON ───────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A member by name, ignoring case (SCIM attribute names are case-insensitive, RFC 7643 §2.1). */
function member(record: Record<string, unknown>, name: string): unknown {
  const lower = name.toLowerCase();
  for (const key of Object.keys(record)) {
    if (key.toLowerCase() === lower) return record[key];
  }
  return undefined;
}

/** Booleans are JSON `true`/`false` or the strings `"true"`/`"false"` in any case (Entra). */
export function scimBoolean(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    const lower = v.toLowerCase();
    if (lower === 'true') return true;
    if (lower === 'false') return false;
  }
  throw invalidValue('A boolean must be true or false');
}

function text(v: unknown, max: number, what: string): string {
  if (typeof v !== 'string' || !isStorableText(v)) {
    throw invalidValue(`${what} must be text without U+0000 or lone surrogates`);
  }
  if ([...v].length > max) throw invalidValue(`${what} is longer than ${max} characters`);
  return v;
}

/** An optional attribute: `null` or `""` clears it. */
function optionalText(v: unknown, max: number, what: string): string | null {
  if (v === null || v === '') return null;
  return text(v, max, what);
}

function email(v: unknown): string | null {
  const value = optionalText(v, MAX_EMAIL, 'An email');
  if (value !== null && !value.includes('@')) throw invalidValue('An email needs an @');
  return value;
}

function readOperations(body: unknown): Operation[] {
  if (!isRecord(body)) throw invalidSyntax('The body must be a PatchOp message');
  const schemas = member(body, 'schemas');
  if (!Array.isArray(schemas) || !schemas.includes(PATCH_OP_SCHEMA)) {
    throw invalidSyntax(`schemas must name ${PATCH_OP_SCHEMA}`);
  }
  const list = member(body, 'Operations');
  if (!Array.isArray(list) || list.length === 0) {
    throw invalidSyntax('Operations must list 1 to 100 operations');
  }
  if (list.length > MAX_PATCH_OPERATIONS) {
    throw tooMany(`At most ${MAX_PATCH_OPERATIONS} operations in one request`);
  }
  return list.map((raw): Operation => {
    if (!isRecord(raw)) throw invalidSyntax('An operation must be an object');
    const opText = member(raw, 'op');
    const op = typeof opText === 'string' ? opText.toLowerCase() : null;
    if (op !== 'add' && op !== 'replace' && op !== 'remove') {
      throw invalidSyntax('op must be add, replace or remove');
    }
    const path = member(raw, 'path');
    if (path !== undefined && (typeof path !== 'string' || path === '')) throw invalidPath();
    return { op, path, value: member(raw, 'value') };
  });
}

// ─── Paths ──────────────────────────────────────────────────────────────────

interface Path {
  /** Lower case. */
  attr: string;
  filter: { attr: string; op: string; value: unknown } | null;
  sub: string | null;
}

/** A well-formed path outside the core schema (an extension attribute): ignored. */
const URN_PATH = /^urn:[A-Za-z0-9:.-]+:[A-Za-z][A-Za-z0-9.]*$/;
/** RFC 7644 §3.5.2's path, with at most one comparison in a value filter. Linear. */
const PLAIN_PATH =
  /^([A-Za-z][\w-]*)(?:\[[ \t]*([A-Za-z][\w-]*)[ \t]+([A-Za-z]{2})[ \t]+("(?:[^"\\]|\\.)*"|true|false|null|-?\d{1,20}(?:\.\d{1,20})?)[ \t]*\])?(?:\.([A-Za-z][\w-]*))?$/i;
/** Names of `Object.prototype` members: never an attribute name, in any segment, in any case. */
const FORBIDDEN_NAMES: ReadonlySet<string> = new Set([
  'constructor',
  'prototype',
  '__proto__',
  'tostring',
  'hasownproperty',
  'valueof',
]);

function checkName(name: string): string {
  const lower = name.toLowerCase();
  if (FORBIDDEN_NAMES.has(lower)) throw invalidPath();
  return lower;
}
const FILTER_OPS: ReadonlySet<string> = new Set([
  'eq',
  'ne',
  'co',
  'sw',
  'ew',
  'gt',
  'lt',
  'ge',
  'le',
]);

/** The parsed path, or null for a well-formed extension path; malformed is `invalidPath`. */
function parsePath(path: string, resource: Resource): Path | null {
  if (path.length > MAX_PATH_LENGTH) throw invalidPath();
  let plain = path;
  const core = `${CORE_SCHEMA[resource]}:`;
  if (path.toLowerCase().startsWith(core)) {
    plain = path.slice(core.length);
  } else if (path.toLowerCase().startsWith('urn:')) {
    if (!URN_PATH.test(path)) throw invalidPath();
    for (const segment of path.split(/[:.]/)) checkName(segment);
    return null;
  }
  const m = PLAIN_PATH.exec(plain);
  const attr = m?.[1];
  if (!m || attr === undefined) throw invalidPath();
  const [, , filterAttr, filterOp, filterValue, sub] = m;
  let filter: Path['filter'] = null;
  if (filterAttr !== undefined && filterOp !== undefined && filterValue !== undefined) {
    const op = filterOp.toLowerCase();
    if (!FILTER_OPS.has(op)) throw invalidPath();
    let value: unknown;
    try {
      value = JSON.parse(filterValue.startsWith('"') ? filterValue : filterValue.toLowerCase());
    } catch {
      throw invalidPath();
    }
    if (typeof value === 'string' && !isStorableText(value)) throw invalidPath();
    filter = { attr: checkName(filterAttr), op, value };
  }
  return { attr: checkName(attr), filter, sub: sub === undefined ? null : checkName(sub) };
}

const isPlain = (p: Path) => p.filter === null && p.sub === null;

function filterIs(p: Path, attr: string, value: string | boolean): boolean {
  if (p.filter === null || p.filter.attr !== attr || p.filter.op !== 'eq') return false;
  const v = p.filter.value;
  if (typeof value === 'boolean') {
    // `primary eq "True"`: a string boolean, read as `scimBoolean` reads values (Entra's form).
    if (typeof v === 'boolean') return v === value;
    if (typeof v !== 'string') return false;
    const lower = v.toLowerCase();
    return (lower === 'true' || lower === 'false') && scimBoolean(v) === value;
  }
  return typeof v === 'string' && v.toLowerCase() === value;
}

/** Applies a no-path operation's value object: each member as a path (spec §12.6). */
function eachMember(
  op: Operation,
  resource: Resource,
  apply: (path: string, value: unknown) => void,
): void {
  if (op.op === 'remove') {
    throw new ScimError(400, 'noTarget', 'A remove operation needs a path');
  }
  const value = op.value;
  if (!isRecord(value)) throw invalidValue('Without a path, the value must be an object');
  const visit = (record: Record<string, unknown>, nested: boolean) => {
    const keys = Object.keys(record);
    if (keys.length > MAX_OBJECT_MEMBERS) {
      throw tooMany(`At most ${MAX_OBJECT_MEMBERS} attributes in one value`);
    }
    for (const key of keys) {
      const v = record[key];
      // The core schema's own URN as a key: its members are core attributes (one level).
      if (!nested && key.toLowerCase() === CORE_SCHEMA[resource] && isRecord(v)) visit(v, true);
      else apply(key, v);
    }
  };
  visit(value, false);
}

// ─── Users ──────────────────────────────────────────────────────────────────

const NAME_MEMBERS = {
  givenname: 'givenName',
  familyname: 'familyName',
  formatted: 'formatted',
} as const;
type NameMember = (typeof NAME_MEMBERS)[keyof typeof NAME_MEMBERS];

function nameMember(sub: string): NameMember | null {
  return Object.hasOwn(NAME_MEMBERS, sub) ? NAME_MEMBERS[sub as keyof typeof NAME_MEMBERS] : null;
}

type UserTarget =
  | { kind: 'active' | 'userName' | 'displayName' | 'externalId' | 'name' | 'emails' | 'email' }
  | { kind: 'nameMember'; member: NameMember }
  | { kind: 'ignored' };

const IGNORED: UserTarget = { kind: 'ignored' };

/** spec §12.6's paths; other well-formed paths are attributes Qualor does not store. */
function userTarget(path: string): UserTarget {
  const p = parsePath(path, 'User');
  if (p === null) return IGNORED;
  switch (p.attr) {
    case 'active':
    case 'username':
    case 'displayname':
    case 'externalid': {
      // These decide who someone is and whether they may sign in: never silently skipped.
      if (!isPlain(p)) throw invalidPath();
      const kinds = {
        active: 'active',
        username: 'userName',
        displayname: 'displayName',
        externalid: 'externalId',
      } as const;
      return { kind: kinds[p.attr] };
    }
    case 'name': {
      if (p.filter !== null) throw invalidPath();
      if (p.sub === null) return { kind: 'name' };
      const m = nameMember(p.sub);
      return m === null ? IGNORED : { kind: 'nameMember', member: m };
    }
    case 'emails':
      if (isPlain(p)) return { kind: 'emails' };
      if (p.sub === 'value' && (filterIs(p, 'type', 'work') || filterIs(p, 'primary', true))) {
        return { kind: 'email' };
      }
      return IGNORED;
    default:
      return IGNORED;
  }
}

/** spec §12.4: the `primary` email, else the first `work` one, else the first. */
function pickEmail(v: unknown): string | null {
  if (v === null) return null;
  if (!Array.isArray(v)) throw invalidValue('emails must be a list');
  if (v.length > MAX_EMAILS) throw tooMany(`At most ${MAX_EMAILS} emails`);
  const entries = v.map((entry) => {
    if (!isRecord(entry)) throw invalidValue('An email must be an object with a value');
    const value = email(member(entry, 'value'));
    if (value === null) throw invalidValue('An email must be an object with a value');
    const primary = member(entry, 'primary');
    const type = member(entry, 'type');
    return {
      value,
      primary: primary === undefined || primary === null ? false : scimBoolean(primary),
      work: typeof type === 'string' && type.toLowerCase() === 'work',
    };
  });
  return (
    (entries.find((e) => e.primary) ?? entries.find((e) => e.work) ?? entries[0])?.value ?? null
  );
}

function withName(name: ScimName, key: NameMember, value: string | null): ScimName {
  const next: ScimName = {};
  for (const k of Object.values(NAME_MEMBERS)) {
    const v = k === key ? value : name[k];
    if (v !== null && v !== undefined) next[k] = v;
  }
  return next;
}

function applyUserValue(state: UserState, op: Op, target: UserTarget, value: unknown): UserState {
  const remove = op === 'remove';
  const need = () => {
    if (value === undefined) throw invalidValue(`An ${op} operation needs a value`);
    return value;
  };
  switch (target.kind) {
    case 'ignored':
      return state;
    case 'active':
      if (remove) throw mutability('active cannot be removed');
      return { ...state, active: scimBoolean(need()) };
    case 'userName': {
      if (remove || need() === null) throw mutability('userName is required');
      const userName = text(value, MAX_TEXT, 'userName');
      if (userName === '') throw invalidValue('userName cannot be empty');
      return { ...state, userName };
    }
    case 'displayName':
      return {
        ...state,
        displayName: remove ? null : optionalText(need(), MAX_TEXT, 'displayName'),
      };
    case 'externalId':
      return { ...state, externalId: remove ? null : optionalText(need(), MAX_TEXT, 'externalId') };
    case 'nameMember':
      return {
        ...state,
        name: withName(
          state.name,
          target.member,
          remove ? null : optionalText(need(), MAX_TEXT, target.member),
        ),
      };
    case 'name': {
      if (remove || need() === null) return { ...state, name: {} };
      if (!isRecord(value)) throw invalidValue('name must be an object');
      if (Object.keys(value).length > MAX_OBJECT_MEMBERS) {
        throw tooMany(`At most ${MAX_OBJECT_MEMBERS} attributes in one value`);
      }
      // A replace of a complex attribute sets the sub-attributes given (RFC 7644 §3.5.2.3).
      let name = state.name;
      for (const key of Object.values(NAME_MEMBERS)) {
        const v = member(value, key);
        if (v !== undefined) name = withName(name, key, optionalText(v, MAX_TEXT, key));
      }
      return { ...state, name };
    }
    case 'emails':
      return { ...state, email: remove ? null : pickEmail(need()) };
    case 'email':
      return { ...state, email: remove ? null : email(need()) };
  }
}

/** spec §12.6: the new state after the operations, in order; throws a `ScimError`, changing nothing. */
export function applyUserPatch(state: UserState, body: unknown): UserState {
  let next: UserState = { ...state, name: { ...state.name } };
  for (const op of readOperations(body)) {
    if (op.path !== undefined) {
      next = applyUserValue(next, op.op, userTarget(op.path), op.value);
    } else {
      eachMember(op, 'User', (path, value) => {
        next = applyUserValue(next, op.op, userTarget(path), value);
      });
    }
  }
  return next;
}

// ─── Groups ─────────────────────────────────────────────────────────────────

type GroupTarget =
  | { kind: 'displayName' | 'externalId' | 'members' }
  | { kind: 'member'; id: string }
  | { kind: 'ignored' };

function memberId(v: unknown): string {
  const id = text(v, MAX_TEXT, 'A member value');
  if (id === '') throw invalidValue('A member value cannot be empty');
  return id;
}

function groupTarget(path: string, op: Op): GroupTarget {
  const p = parsePath(path, 'Group');
  if (p === null) return { kind: 'ignored' };
  switch (p.attr) {
    case 'displayname':
    case 'externalid':
      if (!isPlain(p)) throw invalidPath();
      return { kind: p.attr === 'displayname' ? 'displayName' : 'externalId' };
    case 'members':
      // Membership decides access: a form this server cannot apply is refused, never skipped.
      if (isPlain(p)) return { kind: 'members' };
      if (
        op === 'remove' &&
        p.sub === null &&
        p.filter?.attr === 'value' &&
        p.filter.op === 'eq' &&
        typeof p.filter.value === 'string'
      ) {
        return { kind: 'member', id: memberId(p.filter.value) };
      }
      throw invalidPath();
    default:
      return { kind: 'ignored' };
  }
}

/** spec §12.7: what the operations ask for, in order; throws a `ScimError`. */
export function applyGroupPatch(body: unknown): GroupPatchResult {
  const operations = readOperations(body);
  let displayName: string | undefined;
  let externalId: string | null | undefined;
  const add = new Set<string>();
  const remove = new Set<string>();
  let replace: Set<string> | null = null;
  let changes = 0;

  const count = (n: number) => {
    changes += n;
    if (changes > MAX_MEMBER_CHANGES) {
      throw tooMany(`At most ${MAX_MEMBER_CHANGES} member changes in one request`);
    }
  };
  const ids = (v: unknown): string[] => {
    if (!Array.isArray(v)) throw invalidValue('members must be a list of { value }');
    count(v.length);
    return v.map((entry) => {
      if (!isRecord(entry)) throw invalidValue('A member must be an object with a value');
      return memberId(member(entry, 'value'));
    });
  };
  const adds = (list: string[]) => {
    for (const id of list) {
      if (replace) replace.add(id);
      else {
        remove.delete(id);
        add.add(id);
      }
    }
  };
  const removes = (list: string[]) => {
    for (const id of list) {
      if (replace) replace.delete(id);
      else {
        add.delete(id);
        remove.add(id);
      }
    }
  };

  const apply = (op: Op, target: GroupTarget, value: unknown) => {
    const need = () => {
      if (value === undefined) throw invalidValue(`An ${op} operation needs a value`);
      return value;
    };
    switch (target.kind) {
      case 'ignored':
        return;
      case 'displayName': {
        if (op === 'remove' || need() === null) throw mutability('displayName is required');
        const name = text(value, MAX_TEXT, 'displayName');
        if (name === '') throw invalidValue('displayName cannot be empty');
        displayName = name;
        return;
      }
      case 'externalId':
        externalId = op === 'remove' ? null : optionalText(need(), MAX_TEXT, 'externalId');
        return;
      case 'member':
        count(1);
        removes([target.id]);
        return;
      case 'members':
        if (op === 'add') adds(ids(need()));
        else if (op === 'remove') {
          if (value === undefined || value === null) {
            // Every member goes.
            replace = new Set();
            add.clear();
            remove.clear();
          } else removes(ids(value));
        } else {
          const list = need() === null ? [] : ids(value);
          replace = new Set(list);
          add.clear();
          remove.clear();
        }
        return;
    }
  };

  for (const op of operations) {
    if (op.path !== undefined) apply(op.op, groupTarget(op.path, op.op), op.value);
    else eachMember(op, 'Group', (path, value) => apply(op.op, groupTarget(path, op.op), value));
  }
  const result: GroupPatchResult = {
    add: [...add],
    remove: [...remove],
    replaceMembers: replace === null ? null : [...(replace as Set<string>)],
  };
  if (displayName !== undefined) result.displayName = displayName;
  if (externalId !== undefined) result.externalId = externalId;
  return result;
}
