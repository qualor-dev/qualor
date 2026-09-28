const MAX = 64;

/**
 * sso-scim.md §8.4: a Qualor username from the IdP's claims (the `username` claim, else the
 * email's local part, else `user`), reduced to USERNAME_PATTERN. Only the base: it is never
 * matched against existing users, and a taken name gets `withSuffix`.
 */
export function deriveUsername(claims: { username: string | null; email: string | null }): string {
  // An empty or blank claim counts as absent (an IdP sending preferred_username: "").
  const given = (value: string | null) => (value !== null && value.trim() !== '' ? value : null);
  const email = given(claims.email);
  const raw = given(claims.username) ?? (email ? (email.split('@', 1)[0] ?? '') : '');
  const cleaned = raw
    .replace(/[^A-Za-z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, MAX)
    .replace(/[.-]+$/g, '');
  return cleaned.length > 0 ? cleaned : 'user';
}

/** `base-n`, the base cut so the whole stays within 64 characters, then trimmed of `.` and `-`. */
export function withSuffix(base: string, n: number): string {
  const suffix = `-${n}`;
  const cut = base.slice(0, MAX - suffix.length).replace(/[.-]+$/g, '');
  return (cut.length > 0 ? cut : 'user') + suffix;
}
