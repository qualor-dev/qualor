export const ORGANIZATION_KEY_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/;
export const PROJECT_KEY_PATTERN = /^[A-Za-z0-9._/:-]{1,255}$/;
export const USERNAME_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/**
 * scm.md §2.2: a GitLab project as `scm_project_ref` holds it: its numeric id, or its full path
 * (namespace and project, `/`-separated segments of GitLab's path characters, none of them `.` or
 * `..`).
 */
export const SCM_PROJECT_REF_PATTERN =
  /^(?!(?:.*\/)?\.{1,2}(?:\/|$))(?:[0-9]{1,20}|[A-Za-z0-9_.][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_.][A-Za-z0-9_.-]*)+)$/;
/** A Jira issue key: the Jira project's key, a dash and the issue's number (`QUAL-1`). */
export const JIRA_ISSUE_KEY_PATTERN = /^[A-Za-z][A-Za-z0-9_]*-[0-9]+$/;
