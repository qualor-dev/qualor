/**
 * What the server accepts as an id (`z.uuid()` of zod 4: RFC 9562 versions 1–8 with the RFC
 * variant, plus the nil and max UUIDs). Anything else would be a 422 or a 404, so the UI does not
 * send it.
 */
const UUID =
  /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}
