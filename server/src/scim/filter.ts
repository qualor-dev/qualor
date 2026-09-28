import { isStorableText } from '../audit/canonical';
import { ScimError } from './errors';

export type ScimFilterAttribute = 'userName' | 'externalId' | 'emails.value' | 'id' | 'displayName';

export type ScimFilter = { attribute: ScimFilterAttribute; value: string } | null;

/** Keys in lower case: the lookup lowercases the whole attribute, the work-email form included. */
const USER_ATTRS: ReadonlyMap<string, ScimFilterAttribute> = new Map([
  ['username', 'userName'],
  ['externalid', 'externalId'],
  ['emails.value', 'emails.value'],
  ['emails[type eq "work"].value', 'emails.value'],
  ['id', 'id'],
]);
const GROUP_ATTRS: ReadonlyMap<string, ScimFilterAttribute> = new Map([
  ['displayname', 'displayName'],
  ['externalid', 'externalId'],
  ['id', 'id'],
]);

/** 512 characters, each at most a 6-character `\uXXXX` escape, the attribute and the operator. */
const MAX_FILTER_LENGTH = 4_096;
export const MAX_FILTER_VALUE_LENGTH = 512;
/**
 * One comparison: `<attribute> eq "<JSON string>"`, separated by spaces or tabs only. Linear: no
 * nested quantifiers.
 */
const SHAPE =
  /^[ \t]*(emails\[type eq "work"\]\.value|[A-Za-z][A-Za-z0-9.]*)[ \t]+eq[ \t]+("(?:[^"\\]|\\.)*")[ \t]*$/i;
const BLANK = /^[ \t]*$/;

/**
 * one `eq` comparison on a listed attribute; anything else is invalidFilter. `raw` is the
 * query parameter as parsed: a repeated parameter (a list) is refused like any malformed filter.
 */
export function parseScimFilter(raw: unknown, resource: 'User' | 'Group'): ScimFilter {
  if (raw === undefined || (typeof raw === 'string' && BLANK.test(raw))) return null;
  // The detail never echoes the filter: it may hold anything the client sent.
  const bad = () =>
    new ScimError(
      400,
      'invalidFilter',
      'Only `<attribute> eq "<value>"` on the attributes this server lists is supported',
    );
  if (typeof raw !== 'string' || raw.length > MAX_FILTER_LENGTH) throw bad();
  const m = SHAPE.exec(raw);
  const attrText = m?.[1];
  const quoted = m?.[2];
  if (attrText === undefined || quoted === undefined) throw bad();
  const attribute = (resource === 'User' ? USER_ATTRS : GROUP_ATTRS).get(attrText.toLowerCase());
  if (!attribute) throw bad();
  let value: unknown;
  try {
    value = JSON.parse(quoted);
  } catch {
    throw bad();
  }
  if (
    typeof value !== 'string' ||
    [...value].length > MAX_FILTER_VALUE_LENGTH ||
    !isStorableText(value)
  ) {
    throw bad();
  }
  return { attribute, value };
}
