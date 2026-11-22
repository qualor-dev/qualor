import { createHmac } from 'node:crypto';

export type RedactionTable = {
  secrets: string[];
  emails: string[];
  names: string[];
  tenantIds: string[];
  hosts: string[];
  orgs: string[];
  /** The salt of the synthetic ids (`AZURE_PROBE_ID_SALT`); without it GUIDs stay as they are. */
  idSalt?: string;
};

/** The kinds of listed values a table holds (every field but the salt). */
export const LISTED_KINDS = ['secrets', 'emails', 'names', 'tenantIds', 'hosts', 'orgs'] as const;

// ---------------------------------------------------------------------------------------------
// Synthetic ids. Every GUID in a recording names something of the bench (an organisation, host,
// project, repository, identity, subscription, plan…) unless it is a Microsoft constant. Each one
// becomes a synthetic GUID derived from HMAC-SHA256 with the operator's salt, so the same real id
// gives the same synthetic id in every file (the fake server can follow references across files).
// The salt comes from the environment and is never committed: with a known salt anyone could test
// whether a given real id is in a recording.
/** The last group of every synthetic GUID starts with this; mapping one again keeps it. */
export const SYNTHETIC_MARK = 'fa6e0000';

/**
 * Microsoft constants, the same in every organisation and collection: they stay as they are.
 * Sources: the facts files (resource app, area, location and namespace ids), the SDK
 * (ServiceInstanceTypes.TFS), and `GET _apis/policy/types`, which lists the same type ids on the
 * bench Server and in the Services organisation (recordings `7-policy-types.json`).
 */
export const PUBLIC_GUIDS: ReadonlySet<string> = new Set([
  '00000000-0000-0000-0000-000000000000',
  '499b84ac-1321-427f-aa17-267ca6975798', // Azure DevOps resource (Entra application id)
  '79134c72-4a58-4b42-976c-04e7115f32bf', // organisation resource area
  '4e080c62-fa21-4fbc-8fef-2a10a2b38049', // git resource area
  '00d9565f-ed9c-4a06-9a50-00e7896ccab4', // connectionData location
  'c4c5a7e6-e9f3-4730-a92b-84baacff694b', // FileDiffs location
  '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87', // Git Repositories security namespace
  'cb594ebe-87dd-4fc9-ac2c-6a10a4c92046', // ServiceHooks security namespace
  '00025394-6065-48ca-87d9-7f5672854ef7', // ServiceInstanceTypes.TFS (locationServiceData.serviceOwner)
  // Policy types
  '001a79cf-fda1-4c4e-9e7c-bac40ee5ead8', // Path Length restriction
  '67ed70bd-2a6b-4006-af44-be590463f46d', // Proof Of Presence
  'db2b9b4c-180d-4529-9701-01541d19f36b', // Reserved names restriction
  'fa4e907d-c16b-4a4c-9dfa-4916e5d171ab', // Require a merge strategy
  'c6a1889d-b943-4856-b76f-9e46bb6b0df2', // Comment requirements
  'cbdc66da-9728-4af8-aada-9a5a32e4a226', // Status
  '7ed39669-655c-494e-b4a0-a08b4da0fcce', // Git repository settings
  '0609b952-1397-4640-95ec-e00a01b2c241', // Build
  '2e26e725-8201-4edd-8bf5-978563c34a80', // File size restriction
  '51c78909-e838-41a2-9496-c647091e3c61', // File name restriction
  '77ed4bd3-b063-4689-934a-175e4d0a78d7', // Commit author email validation
  'fd2167ab-b0be-447a-8ec8-39368250530e', // Required reviewers
  'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd', // Minimum number of reviewers
  '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e', // Work item linking
  '0517f88d-4ec5-4343-9d26-9930ebd53069', // GitRepositorySettingsPolicyName
  'ec003f37-8db0-4e10-992a-a2895045752c', // Secrets scanning restriction (Services)
  '90f9629b-664b-4804-a560-dd79b0c628f8', // Secrets scanning restriction (Services)
  '6b227907-7d27-46ea-841a-7f6fe96eef5c', // Automatic Copilot code review (Services)
]);

/** Azure DevOps first-party service identities (`00000002-…` is the build service). */
const SERVICE_IDENTITY = /^[0-9a-f]{8}-0000-8888-8000-000000000000$/;

export function isPublicGuid(guid: string): boolean {
  const g = guid.toLowerCase();
  return PUBLIC_GUIDS.has(g) || SERVICE_IDENTITY.test(g);
}

export function isSyntheticGuid(guid: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/.test(guid.toLowerCase())
    ? guid.toLowerCase().slice(24, 32) === SYNTHETIC_MARK
    : false;
}

/** The synthetic GUID for `guid` (8-4-4-4-12); constants and synthetic GUIDs come back unchanged. */
export function syntheticGuid(guid: string, salt: string): string {
  if (isPublicGuid(guid) || isSyntheticGuid(guid)) return guid;
  if (salt.length === 0) throw new Error('the synthetic-id salt is empty');
  const h = createHmac('sha256', salt).update(guid.toLowerCase()).digest('hex');
  const fake = `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(12, 15)}-8${h.slice(15, 18)}-${SYNTHETIC_MARK}${h.slice(18, 22)}`;
  return /[A-F]/.test(guid) && !/[a-f]/.test(guid) ? fake.toUpperCase() : fake;
}

// A hex run before the first dash may be longer than 8: `A<guid>` (an account id after `A`)
// or `%2f<guid>` (an encoded slash). The GUID is the last 8 of it; the rest stays.
const GUID_IN_TEXT =
  /(?<![0-9a-fA-F])([0-9a-fA-F]*)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?![0-9a-fA-F])/g;
/** A GUID without dashes (thread `UniqueID` values). */
const GUID_N = /(?<![0-9A-Za-z])[0-9a-fA-F]{32}(?![0-9A-Za-z])/g;
/** Subject descriptors: `<kind>.<base64url payload>`; the payload of `aad.`/`aadsp.` is a GUID. */
const DESCRIPTOR =
  /(?<![0-9A-Za-z])(aad|aadsp|aadgp|svc|vss|vssgp|msa|imp|s2s|bnd|cuid|ad|aadup)\.([A-Za-z0-9_-]{8,})(={0,2})/g;

function guidsIn(text: string, salt: string): string {
  return text
    .replace(GUID_IN_TEXT, (_m, pre: string, g: string) => pre + syntheticGuid(g, salt))
    .replace(GUID_N, (n: string) => {
      const dashed = `${n.slice(0, 8)}-${n.slice(8, 12)}-${n.slice(12, 16)}-${n.slice(16, 20)}-${n.slice(20)}`;
      return syntheticGuid(dashed, salt).replace(/-/g, '');
    });
}

/** `text` with every non-constant GUID, plain, without dashes or inside a descriptor, made synthetic. */
export function syntheticIds(text: string, salt: string): string {
  const withDescriptors = text.replace(
    DESCRIPTOR,
    (whole: string, kind: string, payload: string, pad: string) => {
      const raw = Buffer.from(payload, 'base64url');
      if (raw.toString('base64url') !== payload) return whole;
      const decoded = raw.toString('utf8');
      if (!/^[\x20-\x7e]+$/.test(decoded)) return whole;
      const mapped = guidsIn(decoded, salt).replace(WINDOWS_SID, 'S-1-5-21-0-0-0');
      if (mapped === decoded) return whole;
      const encoded = Buffer.from(mapped, 'utf8').toString('base64url');
      return `${kind}.${encoded}${pad ? '='.repeat((4 - (encoded.length % 4)) % 4) : ''}`;
    },
  );
  return guidsIn(withDescriptors, salt);
}

/** A copy of `value` with `syntheticIds` applied to every string and key (for existing recordings). */
export function withSyntheticIds(value: unknown, salt: string): unknown {
  if (typeof value === 'string') return syntheticIds(value, salt);
  if (Array.isArray(value)) return value.map((v) => withSyntheticIds(v, salt));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[syntheticIds(k, salt)] = withSyntheticIds(v, salt);
    }
    return out;
  }
  return value;
}

const JWT = /eyJ[\w-]+\.[\w-]+\.[\w-]+/g;
const AZDO_PAT = /[A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4}/g;
// Session-token PATs of the bench are hundreds of characters; 40-hex git SHAs and
// GUIDs (dashes) stay below this; any longer run, hex or not, is a secret.
const LONG_RUN = /[A-Za-z0-9]{52,}/g;

// Machine values no table can list ahead of time: a build agent's private address and host name,
// a Windows machine name, the machine part of a Windows SID (and the SID in a base64 descriptor).
const PRIVATE_IPV4 =
  /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b(?!\.\d)/g;
const AWS_HOST = /\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}(?:\.[a-z0-9-]+)*/gi;
const WINDOWS_HOST = /\bEC2AMAZ-[A-Z0-9]+\b/gi;
const WINDOWS_SID = /\bS-1-5-21-\d+-\d+-\d+/g;
const SID_BASE64 = /Uy0xLTUtMjEt[A-Za-z0-9+/=_-]*/g;

function machineValues(text: string): string {
  return text
    .replace(PRIVATE_IPV4, '192.0.2.1')
    .replace(AWS_HOST, 'agent.example.invalid')
    .replace(WINDOWS_HOST, 'host.example.invalid')
    .replace(WINDOWS_SID, 'S-1-5-21-0-0-0')
    .replace(SID_BASE64, '<sid>');
}

function replaceAll(text: string, values: string[], placeholder: string): string {
  let out = text;
  for (const v of [...values].filter((x) => x.length > 0).sort((a, b) => b.length - a.length)) {
    out = out.split(v).join(placeholder);
  }
  return out;
}

function redactString(text: string, known: RedactionTable): string {
  let out = replaceAll(text, known.secrets, '<secret>');
  out = replaceAll(out, known.emails, 'user@example.invalid');
  out = replaceAll(out, known.hosts, 'ado.example.invalid');
  out = replaceAll(out, known.tenantIds, '00000000-0000-0000-0000-00000000000t');
  out = replaceAll(out, known.names, 'Probe User');
  out = replaceAll(out, known.orgs, 'probe-org');
  out = machineValues(out);
  out = out.replace(JWT, '<secret>').replace(AZDO_PAT, '<secret>').replace(LONG_RUN, '<secret>');
  return known.idSalt ? syntheticIds(out, known.idSalt) : out;
}

/**
 * Copy of `value` with every listed or recognisable secret and personal value replaced, and its
 * GUIDs made synthetic when the table has a salt.
 */
export function redact(value: unknown, known: RedactionTable): unknown {
  if (typeof value === 'string') return redactString(value, known);
  if (Array.isArray(value)) return value.map((v) => redact(v, known));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[redactString(k, known)] = redact(v, known);
    return out;
  }
  return value;
}
