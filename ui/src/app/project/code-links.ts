/** A file page link (spec §4.1): path and branch as query params, the line as `#L<n>`. */
export interface CodeFileLink {
  commands: unknown[];
  queryParams: { branch: string; path: string };
  fragment: string | undefined;
}

export function codeFileLink(
  projectId: string,
  branchId: string,
  path: string,
  line?: number | null,
): CodeFileLink {
  return {
    commands: ['/projects', projectId, 'code', 'file'],
    queryParams: { branch: branchId, path },
    fragment: line ? `L${line}` : undefined,
  };
}
