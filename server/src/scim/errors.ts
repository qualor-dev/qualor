/** RFC 7644 §3.12 `scimType` values Qualor answers with (sso-scim.md §12). */
export type ScimType =
  | 'invalidFilter'
  | 'uniqueness'
  | 'mutability'
  | 'invalidSyntax'
  | 'invalidValue'
  | 'invalidPath'
  | 'noTarget'
  | 'tooMany';

export type ScimStatus = 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 500 | 503;

export const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
/** sso-scim.md §12.1: every answer under `/scim/v2`. */
export const SCIM_CONTENT_TYPE = 'application/scim+json; charset=utf-8';

/** A SCIM error answer (RFC 7644 §3.12). `detail` never holds a token or a request's value. */
export class ScimError extends Error {
  readonly detail: string;

  constructor(
    readonly status: ScimStatus,
    readonly scimType: ScimType | null,
    detail: string,
  ) {
    super(detail);
    this.name = 'ScimError';
    this.detail = detail;
  }
}

export interface ScimErrorBody {
  schemas: [string];
  status: string;
  scimType?: ScimType;
  detail: string;
}

export function scimErrorBody(e: ScimError): ScimErrorBody {
  return {
    schemas: [SCIM_ERROR_SCHEMA],
    status: String(e.status),
    ...(e.scimType === null ? {} : { scimType: e.scimType }),
    detail: e.detail,
  };
}
