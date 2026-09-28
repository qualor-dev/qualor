// server/test/urls.ts (no vitest import: global setup runs outside the test runtime)
export const TEMPLATE_DATABASE = 'qualor_template';

export function databaseUrl(serverUrl: string, database: string): string {
  const url = new URL(serverUrl);
  url.pathname = `/${database}`;
  return url.toString();
}
