/**
 * Only absolute http(s) links leave the app (plan 1F ruling Y5); anything else (`javascript:`,
 * `data:`, relative or protocol-relative) is not a link. Callers render the result with
 * `target="_blank" rel="noopener noreferrer"`.
 */
export function safeHelpUri(uri: string | null | undefined): string | null {
  if (!uri) return null;
  try {
    const url = new URL(uri);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}
