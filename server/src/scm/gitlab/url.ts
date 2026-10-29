/**
 * Which GitLab a normalised base URL is: `gitlab.com` (https://gitlab.com, GitLab's own cloud) or a
 * `self-managed` instance (any other host).
 */
export function gitlabHostKind(baseUrl: string): 'gitlab.com' | 'self-managed' {
  try {
    const url = new URL(baseUrl);
    return url.protocol === 'https:' && url.hostname === 'gitlab.com' && url.pathname === '/'
      ? 'gitlab.com'
      : 'self-managed';
  } catch {
    return 'self-managed';
  }
}
