const ENTERPRISE_ONLY = ['sso.multi', 'audit-log.stream', 'scim'];

/** The plan a key's features make (docs/guide/enterprise.md "What a licence adds"). */
export function licensePlan(features: readonly string[]): 'Business' | 'Enterprise' {
  return ENTERPRISE_ONLY.some((f) => features.includes(f)) ? 'Enterprise' : 'Business';
}
