import type { ScimName } from '../db/schema';
import { ScimError } from './errors';

/** The JSON of sso-scim.md §12.1, §12.4 and §12.7 (RFC 7643, RFC 7644). */

export const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
export const LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SPC_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
const RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
const SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';
/** spec §12.5: at most 100 resources a page. */
export const MAX_RESULTS = 100;

/** `<QUALOR_PUBLIC_URL>/api/v0/ee/scim/v2`; without a public URL a SCIM answer cannot name itself. */
export function scimBaseUrl(publicUrl: string | null): string {
  if (publicUrl === null) throw new ScimError(500, null, 'Set QUALOR_PUBLIC_URL');
  return `${publicUrl.replace(/\/+$/, '')}/api/v0/ee/scim/v2`;
}

export interface ScimMeta {
  resourceType: 'User' | 'Group';
  created: string;
  lastModified: string;
  location: string;
}

export interface ScimUserResource {
  schemas: [string];
  id: string;
  externalId?: string;
  userName: string;
  name: ScimName;
  displayName?: string;
  emails: { value: string; type: 'work'; primary: true }[];
  active: boolean;
  meta: ScimMeta;
}

export interface ScimGroupResource {
  schemas: [string];
  id: string;
  externalId?: string;
  displayName: string;
  members?: { value: string; display?: string }[];
  meta: ScimMeta;
}

export interface ListResponse<R> {
  schemas: [string];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: R[];
}

const later = (a: Date, b: Date) => (a.getTime() >= b.getTime() ? a : b);

/** A SCIM User: the identity's SCIM record and the user's profile (spec §12.4). */
export function userResource(
  identity: {
    id: string;
    scimUserName: string | null;
    scimExternalId: string | null;
    scimName: ScimName | null;
    createdAt: Date;
    updatedAt: Date;
  },
  user: {
    email: string | null;
    displayName: string | null;
    active: boolean;
    updatedAt: Date;
  },
  baseUrl: string,
): ScimUserResource {
  return {
    schemas: [USER_SCHEMA],
    id: identity.id,
    ...(identity.scimExternalId === null ? {} : { externalId: identity.scimExternalId }),
    userName: identity.scimUserName ?? '',
    name: { ...identity.scimName },
    ...(user.displayName === null ? {} : { displayName: user.displayName }),
    emails: user.email === null ? [] : [{ value: user.email, type: 'work', primary: true }],
    active: user.active,
    meta: {
      resourceType: 'User',
      created: identity.createdAt.toISOString(),
      lastModified: later(identity.updatedAt, user.updatedAt).toISOString(),
      location: `${baseUrl}/Users/${identity.id}`,
    },
  };
}

/** A SCIM Group (spec §12.7); `members` null leaves the attribute out (`excludedAttributes`). */
export function groupResource(
  group: {
    id: string;
    displayName: string;
    externalId: string | null;
    createdAt: Date;
    updatedAt: Date;
  },
  members: { value: string; display: string | null }[] | null,
  baseUrl: string,
): ScimGroupResource {
  return {
    schemas: [GROUP_SCHEMA],
    id: group.id,
    ...(group.externalId === null ? {} : { externalId: group.externalId }),
    displayName: group.displayName,
    ...(members === null
      ? {}
      : {
          members: members.map((m) => ({
            value: m.value,
            ...(m.display === null ? {} : { display: m.display }),
          })),
        }),
    meta: {
      resourceType: 'Group',
      created: group.createdAt.toISOString(),
      lastModified: group.updatedAt.toISOString(),
      location: `${baseUrl}/Groups/${group.id}`,
    },
  };
}

export function listResponse<R>(
  resources: R[],
  total: number,
  startIndex: number,
): ListResponse<R> {
  return {
    schemas: [LIST_RESPONSE_SCHEMA],
    totalResults: total,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

/** Attributes every projection keeps (RFC 7644 §3.9: `returned: always`). */
const ALWAYS: ReadonlySet<string> = new Set(['id', 'schemas', 'meta']);

/**
 * The top-level attribute a name in `attributes=`/`excludedAttributes=` refers to, lower case:
 * `name.givenName` is `name`, and the core schema's URN prefix is dropped.
 */
function topLevel(name: string): string {
  let n = name.trim().toLowerCase();
  for (const urn of [USER_SCHEMA, GROUP_SCHEMA]) {
    if (n.startsWith(`${urn.toLowerCase()}:`)) n = n.slice(urn.length + 1);
  }
  return n.split('.', 1)[0] ?? '';
}

/**
 * spec §12.5: `attributes=` keeps `id`, `schemas`, `meta` and the listed ones; `excluded` names
 * attributes to leave out (only `members` is honoured; others are ignored).
 */
export function project<R extends object>(
  resource: R,
  attributes: readonly string[] | null,
  excluded: readonly string[] = [],
): Partial<R> {
  const keep = attributes === null ? null : new Set(attributes.map(topLevel));
  const drop = excluded.some((a) => topLevel(a) === 'members');
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(resource)) {
    const lower = key.toLowerCase();
    if (
      ALWAYS.has(lower) ||
      ((keep === null || keep.has(lower)) && !(drop && lower === 'members'))
    ) {
      out[key] = value;
    }
  }
  return out as Partial<R>;
}

/** Whether a projection shows `members`: a Group's members are then not read at all. */
export function showsMembers(
  attributes: readonly string[] | null,
  excluded: readonly string[],
): boolean {
  if (excluded.some((a) => topLevel(a) === 'members')) return false;
  return attributes === null || attributes.some((a) => topLevel(a) === 'members');
}

// ─── Discovery (RFC 7644 §4) ────────────────────────────────────────────────

export function SERVICE_PROVIDER_CONFIG(baseUrl: string) {
  return {
    schemas: [SPC_SCHEMA],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_RESULTS },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'Bearer token',
        description: 'A SCIM token of the connection (qlr_scim_…), sent as a Bearer token',
        primary: true,
      },
    ],
    meta: { resourceType: 'ServiceProviderConfig', location: `${baseUrl}/ServiceProviderConfig` },
  };
}

export function RESOURCE_TYPES(baseUrl: string) {
  const type = (name: 'User' | 'Group', endpoint: string, schema: string) => ({
    schemas: [RESOURCE_TYPE_SCHEMA],
    id: name,
    name,
    endpoint,
    schema,
    meta: { resourceType: 'ResourceType', location: `${baseUrl}/ResourceTypes/${name}` },
  });
  const resources = [type('User', '/Users', USER_SCHEMA), type('Group', '/Groups', GROUP_SCHEMA)];
  return listResponse(resources, resources.length, 1);
}

const attr = (
  name: string,
  more: {
    type?: string;
    required?: boolean;
    mutability?: string;
    uniqueness?: string;
    multiValued?: boolean;
    caseExact?: boolean;
    subAttributes?: object[];
  } = {},
) => ({
  name,
  type: more.type ?? 'string',
  multiValued: more.multiValued ?? false,
  required: more.required ?? false,
  caseExact: more.caseExact ?? false,
  mutability: more.mutability ?? 'readWrite',
  returned: 'default',
  uniqueness: more.uniqueness ?? 'none',
  ...(more.subAttributes ? { subAttributes: more.subAttributes } : {}),
});

const userSchema = {
  schemas: [SCHEMA_SCHEMA],
  id: USER_SCHEMA,
  name: 'User',
  description: 'User Account',
  attributes: [
    attr('userName', { required: true, uniqueness: 'server' }),
    attr('externalId', { caseExact: true }),
    attr('name', {
      type: 'complex',
      subAttributes: [attr('givenName'), attr('familyName'), attr('formatted')],
    }),
    attr('displayName'),
    attr('emails', {
      type: 'complex',
      multiValued: true,
      subAttributes: [attr('value'), attr('type'), attr('primary', { type: 'boolean' })],
    }),
    attr('active', { type: 'boolean' }),
  ],
  meta: { resourceType: 'Schema' },
};

const groupSchema = {
  schemas: [SCHEMA_SCHEMA],
  id: GROUP_SCHEMA,
  name: 'Group',
  description: 'Group',
  attributes: [
    attr('displayName', { required: true, uniqueness: 'server' }),
    attr('externalId', { caseExact: true }),
    attr('members', {
      type: 'complex',
      multiValued: true,
      subAttributes: [
        attr('value', { mutability: 'immutable' }),
        attr('display', { mutability: 'readOnly' }),
      ],
    }),
  ],
  meta: { resourceType: 'Schema' },
};

export const SCHEMAS = listResponse([userSchema, groupSchema], 2, 1);
