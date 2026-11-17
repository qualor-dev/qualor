import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { JiraDeployment, JiraStatusCategory } from '../src/db/schema';
import { TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from './tls';

/**
 * A local fake of the Jira REST v2 endpoints Qualor uses (spec §6.7), for tests: nothing in
 * `pnpm test` contacts a real Jira. One fake is one deployment, Cloud (Basic `email:token`, over
 * https with the test CA when `https` is set) or Data Center (Bearer token, under an optional
 * context path). Answers are built from the recorded shapes in `jira-shapes/` (see its README for
 * where each comes from) with the fake's own ids and values laid over them.
 *
 * It checks what a real Jira checks where Qualor depends on it:
 * - the `Authorization` header of its deployment (else 401);
 * - createmeta pages (`startAt`, `maxResults`; Cloud names the items `issueTypes` or `fields`,
 *   Data Center `values`);
 * - a create refuses fields that are not on the issue type's screen and required fields without a
 *   default that are missing, with Jira's 400 bodies; a bulk refuses those elements and creates the
 *   others (201), answers 400 when none is created, and refuses more than 50 elements;
 * - search reads only `id in (…)` and `labels in (…)`; an unknown id fails the query with 400 on
 *   Cloud, and on Data Center too unless the request says `validateQuery: "warn"`; Cloud pages by
 *   `nextPageToken`, Data Center by `startAt`; issues made within the `searchLag` window are not
 *   found yet (Cloud's search is eventually consistent);
 * - keys `<KEY>-1`, `<KEY>-2`… per project, ids from 10001 across the fake, a new issue in "To Do".
 */

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'jira-shapes');

/** A recorded Jira answer (`jira-shapes/<name>.json`). */
export function jiraShape<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(path.join(SHAPES, `${name}.json`), 'utf8')) as T;
}

export interface FakeJiraRequest {
  method: string;
  /** As received: the context path included, still percent-encoded, without the query. */
  path: string;
  query: string;
  headers: IncomingHttpHeaders;
  body: string;
}

export interface JiraInjectedAnswer {
  /** Default 200. */
  status?: number;
  headers?: Record<string, string>;
  /** A string is sent as it is (an HTML page); anything else as JSON. */
  body?: unknown;
  /** Never answer (the client's deadline must fire). */
  hang?: boolean;
  /** Reset the connection without an answer. */
  reset?: boolean;
  /** Make the create as the fake normally would, then hang or reset instead of answering. */
  afterCreate?: 'hang' | 'reset';
  /** After `before`, answer as the fake normally would. */
  passThrough?: boolean;
  /** Runs before the answer (a test's change in the middle of a job). */
  before?: () => Promise<void>;
}

export interface FakeJiraField {
  fieldId: string;
  name: string;
  required: boolean;
  hasDefaultValue?: boolean;
  allowedValues?: { id: string; name: string }[];
}

export interface FakeJiraIssueType {
  id: string;
  name: string;
  subtask?: boolean;
  /** The create screen: a create may set these fields and no others. */
  fields: FakeJiraField[];
}

export interface FakeJiraIssue {
  id: string;
  key: string;
  /** The fields the create sent. */
  fields: Record<string, unknown>;
  status: { name: string; category: JiraStatusCategory };
  /** The comments' bodies, oldest first. */
  comments: string[];
  /** The fake's clock when the issue was made. */
  createdAt: number;
}

export interface FakeJira {
  /** The origin (no context path, no trailing slash). */
  readonly url: string;
  readonly token: string;
  readonly email: string;
  readonly deployment: JiraDeployment;
  readonly requests: FakeJiraRequest[];
  /** A project, with {@link defaultIssueTypes} unless it names its own. */
  addProject(p: { id: string; key: string; name: string; issueTypes?: FakeJiraIssueType[] }): void;
  /** Every issue, in the order made (deleted ones gone). */
  issues(): FakeJiraIssue[];
  /** The issue that has this key now. */
  issue(key: string): FakeJiraIssue | undefined;
  /** A status change made in Jira. */
  setStatus(key: string, name: string, category: JiraStatusCategory): void;
  /** The issue moved to another project: a new key, the same id. */
  moveIssue(key: string, newKey: string): void;
  deleteIssue(key: string): void;
  /** From now on, an issue is found by search only this many milliseconds after it was made. */
  searchLag(ms: number): void;
  /**
   * The next create (bulk or single) refuses the elements at these indexes with these field
   * errors (default: Components is required), as Jira refuses an element it cannot create.
   */
  rejectElements(indexes: number[], errors?: Record<string, string>): void;
  /** The next matching requests (`path` tested against the path as received) get these answers. */
  inject(method: string, path: RegExp, ...answers: JiraInjectedAnswer[]): void;
  /** Forgets the recorded requests (not the state). */
  clearRequests(): void;
  close(): Promise<void>;
}

const PRIORITIES = [
  { id: '1', name: 'Highest' },
  { id: '2', name: 'High' },
  { id: '3', name: 'Medium' },
  { id: '4', name: 'Low' },
  { id: '5', name: 'Lowest' },
];

/**
 * The issue types a project gets unless it names its own: `Bug` (what Qualor can create), `Story`
 * (a required custom field Qualor cannot fill) and `Sub-task` (never offered).
 */
export function defaultIssueTypes(): FakeJiraIssueType[] {
  const screen = (): FakeJiraField[] => [
    { fieldId: 'project', name: 'Project', required: true },
    { fieldId: 'issuetype', name: 'Issue Type', required: true },
    { fieldId: 'summary', name: 'Summary', required: true },
    // Jira fills the reporter with the credential's user.
    { fieldId: 'reporter', name: 'Reporter', required: true, hasDefaultValue: true },
    { fieldId: 'description', name: 'Description', required: false },
    { fieldId: 'labels', name: 'Labels', required: false },
    {
      fieldId: 'priority',
      name: 'Priority',
      required: false,
      hasDefaultValue: true,
      allowedValues: PRIORITIES,
    },
  ];
  return [
    { id: '10001', name: 'Bug', fields: screen() },
    {
      id: '10002',
      name: 'Story',
      fields: [...screen(), { fieldId: 'customfield_10010', name: 'Components', required: true }],
    },
    {
      id: '10003',
      name: 'Sub-task',
      subtask: true,
      fields: [...screen(), { fieldId: 'parent', name: 'Parent', required: true }],
    },
  ];
}

const CATEGORIES: Record<JiraStatusCategory, { id: number; colorName: string; name: string }> = {
  new: { id: 2, colorName: 'blue-gray', name: 'To Do' },
  indeterminate: { id: 4, colorName: 'yellow', name: 'In Progress' },
  done: { id: 3, colorName: 'green', name: 'Done' },
};

/** The `schema` of the system fields the default screens have; any other is a text field. */
const FIELD_SCHEMAS: Record<string, Record<string, unknown>> = {
  project: { type: 'project', system: 'project' },
  issuetype: { type: 'issuetype', system: 'issuetype' },
  summary: { type: 'string', system: 'summary' },
  reporter: { type: 'user', system: 'reporter' },
  description: { type: 'string', system: 'description' },
  labels: { type: 'array', items: 'string', system: 'labels' },
  priority: { type: 'priority', system: 'priority' },
  parent: { type: 'issuelink', system: 'parent' },
};

interface FakeProject {
  id: string;
  key: string;
  name: string;
  issueTypes: FakeJiraIssueType[];
}

interface Injection {
  method: string;
  path: RegExp;
  answers: JiraInjectedAnswer[];
}

interface Reply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

const ERROR_SHAPE = jiraShape('error');

/** Jira's ErrorCollection. */
const refusal = (
  status: number,
  errorMessages: string[],
  errors: Record<string, string> = {},
): Reply => ({
  status,
  body: { ...ERROR_SHAPE, errorMessages, errors },
});

const NOT_FOUND = refusal(404, ['Issue does not exist or you do not have permission to see it.']);
const BULK_MAX = 50;
/** Search page size unless `searchPageSize` says otherwise (the client asks for 100). */
const SEARCH_PAGE_DEFAULT = 100;
const DEFAULT_REJECTION = { customfield_10010: 'Components is required.' };

/** The values of `<field> in (…)`: bare words or JQL strings. Null when it is not that form. */
function parseJql(jql: string): { field: 'id' | 'labels'; values: string[] } | null {
  const match = /^\s*(id|labels)\s+in\s*\((.*)\)\s*$/is.exec(jql);
  if (!match) return null;
  const values: string[] = [];
  const list = match[2] ?? '';
  const token = /\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,"()]+))\s*(,|$)/y;
  let at = 0;
  while (at < list.length) {
    token.lastIndex = at;
    const t = token.exec(list);
    if (!t) return null;
    values.push(t[1] !== undefined ? t[1].replace(/\\(.)/g, '$1') : (t[2] ?? ''));
    at = token.lastIndex;
    if (t[3] === '') break;
  }
  return { field: (match[1] ?? '').toLowerCase() as 'id' | 'labels', values };
}

/** A whole number from a query or body value, else `fallback`. */
function count(value: unknown, fallback: number): number {
  const n = typeof value === 'string' && value !== '' ? Number(value) : value;
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 ? n : fallback;
}

export async function createFakeJira(options: {
  deployment: JiraDeployment;
  token?: string;
  email?: string;
  contextPath?: string;
  https?: boolean;
  port?: number;
  now?: () => number;
  searchPageSize?: number;
  debugRoutes?: boolean;
}): Promise<FakeJira> {
  const { deployment } = options;
  const cloud = deployment === 'cloud';
  const token = options.token ?? randomBytes(24).toString('base64url');
  const email = options.email ?? 'qualor@example.com';
  const contextPath = options.contextPath
    ? `/${options.contextPath.replace(/^\/+|\/+$/g, '')}`
    : '';
  const now = options.now ?? Date.now;
  const expectedAuth = cloud
    ? `Basic ${Buffer.from(`${email}:${token}`).toString('base64')}`
    : `Bearer ${token}`;
  const suffix = cloud ? 'cloud' : 'dc';
  const myselfShape = jiraShape(`myself.${suffix}`);
  const projectShape = cloud
    ? jiraShape<{ values: Record<string, unknown>[] }>('project-search.cloud').values[0]!
    : jiraShape<Record<string, unknown>[]>('project.dc')[0]!;
  const typePage = jiraShape<Record<string, unknown>>(`createmeta-issuetypes.${suffix}`);
  const fieldPage = jiraShape<Record<string, unknown>>(`createmeta-fields.${suffix}`);
  const itemsKey = (kind: 'issueTypes' | 'fields') => (cloud ? kind : 'values');
  const typeShape = (typePage[itemsKey('issueTypes')] as Record<string, unknown>[])[0]!;
  const fieldShapes = fieldPage[itemsKey('fields')] as Record<string, unknown>[];
  const fieldShape = fieldShapes[0]!;
  const optionShape = (
    fieldShapes.find((f) => Array.isArray(f['allowedValues']))!['allowedValues'] as Record<
      string,
      unknown
    >[]
  )[0]!;
  const projectPageShape = jiraShape('project-search.cloud');
  const createdShape = jiraShape('issue-created');
  const bulkShape = jiraShape('bulk-partial');
  const searchShape = jiraShape<{ issues: Record<string, unknown>[] }>(
    cloud ? 'search-jql.cloud' : 'search.dc',
  );
  const issueShape = searchShape.issues[0]!;
  const statusShape = (issueShape['fields'] as { status: Record<string, unknown> }).status;
  const commentShape = jiraShape('comment');

  const projects = new Map<string, FakeProject>();
  const issues: FakeJiraIssue[] = [];
  const requests: FakeJiraRequest[] = [];
  const injections: Injection[] = [];
  const counters = new Map<string, number>();
  let nextId = 10_001;
  let nextCommentId = 10_100;
  let lag = 0;
  let rejection: { indexes: Set<number>; errors: Record<string, string> } | null = null;
  let base = '';

  const issueByKey = (key: string): FakeJiraIssue => {
    const issue = issues.find((i) => i.key === key);
    if (!issue) throw new Error(`fake Jira: no issue ${key}`);
    return issue;
  };
  const projectOf = (ref: unknown): FakeProject | undefined =>
    [...projects.values()].find((p) => p.key === ref || p.id === ref);
  const self = (rest: string) => `${base}/rest/api/2/${rest}`;

  const statusJson = (status: FakeJiraIssue['status']) => ({
    ...statusShape,
    name: status.name,
    statusCategory: {
      ...(statusShape['statusCategory'] as Record<string, unknown>),
      ...CATEGORIES[status.category],
      key: status.category,
      self: self(`statuscategory/${CATEGORIES[status.category].id}`),
    },
  });
  const issueJson = (issue: FakeJiraIssue) => ({
    ...issueShape,
    id: issue.id,
    key: issue.key,
    self: self(`issue/${issue.id}`),
    fields: { status: statusJson(issue.status), labels: issue.fields['labels'] ?? [] },
  });
  const projectJson = (p: FakeProject) => ({
    ...projectShape,
    id: p.id,
    key: p.key,
    name: p.name,
    self: self(`project/${p.id}`),
  });
  const typeJson = (t: FakeJiraIssueType) => ({
    ...typeShape,
    id: t.id,
    name: t.name,
    description: '',
    subtask: t.subtask === true,
    self: self(`issuetype/${t.id}`),
    ...('untranslatedName' in typeShape ? { untranslatedName: t.name } : {}),
    ...('hierarchyLevel' in typeShape ? { hierarchyLevel: t.subtask === true ? -1 : 0 } : {}),
  });
  const fieldJson = (f: FakeJiraField) => {
    const json: Record<string, unknown> = {
      ...fieldShape,
      required: f.required,
      schema: FIELD_SCHEMAS[f.fieldId] ?? {
        type: 'string',
        custom: 'com.atlassian.jira.plugin.system.customfieldtypes:textfield',
      },
      name: f.name,
      fieldId: f.fieldId,
      hasDefaultValue: f.hasDefaultValue === true,
      ...('key' in fieldShape ? { key: f.fieldId } : {}),
    };
    if (f.allowedValues) {
      json['allowedValues'] = f.allowedValues.map((v) => ({
        ...optionShape,
        id: v.id,
        name: v.name,
        self: self(`${f.fieldId}/${v.id}`),
      }));
    }
    return json;
  };

  /** One page of a createmeta listing, in the deployment's envelope. */
  const createmetaPage = (
    shape: Record<string, unknown>,
    kind: 'issueTypes' | 'fields',
    all: unknown[],
    params: URLSearchParams,
  ): Reply => {
    const startAt = count(params.get('startAt'), 0);
    const maxResults = Math.min(count(params.get('maxResults'), 50), 200);
    const page = all.slice(startAt, startAt + maxResults);
    return {
      status: 200,
      body: {
        ...shape,
        maxResults,
        startAt,
        total: all.length,
        ...(cloud ? {} : { isLast: startAt + page.length >= all.length }),
        [itemsKey(kind)]: page,
      },
    };
  };

  /** Jira's checks of one element of a create; the field errors, or the issue's place. */
  const checked = (
    fields: unknown,
  ):
    | { errors: Record<string, string>; errorMessages: string[] }
    | { project: FakeProject; fields: Record<string, unknown> } => {
    if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
      return { errors: {}, errorMessages: ['The issue must have fields.'] };
    }
    const given = fields as Record<string, unknown>;
    const projectRef = given['project'] as { id?: unknown; key?: unknown } | undefined;
    const project = projectOf(projectRef?.id) ?? projectOf(projectRef?.key);
    if (!project) return { errors: { project: 'valid project is required' }, errorMessages: [] };
    const typeRef = given['issuetype'] as { id?: unknown; name?: unknown } | undefined;
    const type = project.issueTypes.find((t) => t.id === typeRef?.id || t.name === typeRef?.name);
    if (!type) return { errors: { issuetype: 'valid issue type is required' }, errorMessages: [] };
    const errors: Record<string, string> = {};
    const onScreen = new Set(type.fields.map((f) => f.fieldId));
    for (const id of Object.keys(given)) {
      if (!onScreen.has(id)) {
        errors[id] =
          `Field '${id}' cannot be set. It is not on the appropriate screen, or unknown.`;
      }
    }
    for (const f of type.fields) {
      const value = given[f.fieldId];
      const empty =
        value === undefined ||
        value === null ||
        value === '' ||
        (Array.isArray(value) && value.length === 0);
      if (f.required && f.hasDefaultValue !== true && empty) {
        errors[f.fieldId] = `${f.name} is required.`;
      }
    }
    return Object.keys(errors).length > 0
      ? { errors, errorMessages: [] }
      : { project, fields: given };
  };

  /** Creates the issue, or answers why not: the next create's armed rejection first. */
  const createOne = (
    fields: unknown,
    index: number,
    armed: typeof rejection,
  ): FakeJiraIssue | { errors: Record<string, string>; errorMessages: string[] } => {
    if (armed?.indexes.has(index)) return { errors: armed.errors, errorMessages: [] };
    const result = checked(fields);
    if (!('project' in result)) return result;
    const n = (counters.get(result.project.key) ?? 0) + 1;
    counters.set(result.project.key, n);
    const issue: FakeJiraIssue = {
      id: String(nextId++),
      key: `${result.project.key}-${n}`,
      fields: result.fields,
      status: { name: 'To Do', category: 'new' },
      comments: [],
      createdAt: now(),
    };
    issues.push(issue);
    return issue;
  };
  const createdJson = (issue: FakeJiraIssue) => ({
    ...createdShape,
    id: issue.id,
    key: issue.key,
    self: self(`issue/${issue.id}`),
  });
  /** The next create's rejection, used up by it. */
  const takeRejection = () => {
    const armed = rejection;
    rejection = null;
    return armed;
  };

  const search = (json: Record<string, unknown>): Reply => {
    const jql = typeof json['jql'] === 'string' ? json['jql'] : '';
    const parsed = parseJql(jql);
    if (!parsed) {
      return refusal(400, [
        'Error in the JQL Query: the fake Jira reads only "id in (…)" and "labels in (…)".',
      ]);
    }
    let matches: FakeJiraIssue[];
    const warnings: string[] = [];
    if (parsed.field === 'id') {
      const unknown = parsed.values.filter((v) => !issues.some((i) => i.id === v));
      const texts = unknown.map((v) => `An issue with key '${v}' does not exist for field 'id'.`);
      if (texts.length > 0 && (cloud || json['validateQuery'] !== 'warn')) {
        return refusal(400, texts);
      }
      warnings.push(...texts);
      matches = issues.filter((i) => parsed.values.includes(i.id));
    } else {
      matches = issues.filter((i) => {
        const labels = i.fields['labels'];
        return Array.isArray(labels) && labels.some((l) => parsed.values.includes(String(l)));
      });
    }
    const visible = matches.filter((i) => now() - i.createdAt >= lag);
    const size = Math.max(
      1,
      Math.min(count(json['maxResults'], 50), options.searchPageSize ?? SEARCH_PAGE_DEFAULT),
    );
    if (cloud) {
      let offset = 0;
      if (json['nextPageToken'] !== undefined) {
        const decoded = Number(Buffer.from(String(json['nextPageToken']), 'base64url').toString());
        if (!Number.isInteger(decoded) || decoded < 0) {
          return refusal(400, ['Invalid nextPageToken.']);
        }
        offset = decoded;
      }
      const page = visible.slice(offset, offset + size);
      const more = offset + page.length < visible.length;
      const rest: Record<string, unknown> = { ...searchShape };
      delete rest['nextPageToken'];
      return {
        status: 200,
        body: {
          ...rest,
          issues: page.map(issueJson),
          ...(more
            ? { nextPageToken: Buffer.from(String(offset + page.length)).toString('base64url') }
            : {}),
          isLast: !more,
        },
      };
    }
    const startAt = count(json['startAt'], 0);
    return {
      status: 200,
      body: {
        ...searchShape,
        startAt,
        maxResults: size,
        total: visible.length,
        issues: visible.slice(startAt, startAt + size).map(issueJson),
        ...(warnings.length > 0 ? { warningMessages: warnings } : {}),
      },
    };
  };

  /** The fake's answer to a request under the context path, as Jira would give it. */
  const route = (
    method: string,
    pathname: string,
    query: string,
    headers: IncomingHttpHeaders,
    body: string,
  ): Reply => {
    if (!pathname.startsWith(`${contextPath}/rest/`)) return refusal(404, ['Not found.']);
    const apiPath = pathname.slice(contextPath.length);
    if (headers.authorization !== expectedAuth) {
      return refusal(401, [
        'You are not authenticated. Authentication required to perform this operation.',
      ]);
    }
    const params = new URLSearchParams(query);
    let json: Record<string, unknown> = {};
    if (body !== '') {
      try {
        json = JSON.parse(body) as Record<string, unknown>;
      } catch {
        return refusal(400, ['Unexpected character in the request body.']);
      }
    }
    const segments = apiPath.split('/').slice(1).map(decodeURIComponent);
    const [, , , resource, ...rest] = segments; // rest, api, 2, …
    if (method === 'GET' && apiPath === '/rest/api/2/myself') {
      return { status: 200, body: { ...myselfShape, emailAddress: email } };
    }
    if (method === 'GET' && apiPath === '/rest/api/2/project' && !cloud) {
      return { status: 200, body: [...projects.values()].map(projectJson) };
    }
    if (method === 'GET' && apiPath === '/rest/api/2/project/search' && cloud) {
      const wanted = (params.get('query') ?? '').toLowerCase();
      const all = [...projects.values()].filter(
        (p) => p.key.toLowerCase().includes(wanted) || p.name.toLowerCase().includes(wanted),
      );
      const startAt = count(params.get('startAt'), 0);
      const maxResults = Math.min(count(params.get('maxResults'), 50), 100);
      const page = all.slice(startAt, startAt + maxResults);
      return {
        status: 200,
        body: {
          ...projectPageShape,
          self: self(`project/search?${query}`),
          maxResults,
          startAt,
          total: all.length,
          isLast: startAt + page.length >= all.length,
          values: page.map(projectJson),
        },
      };
    }
    if (
      method === 'GET' &&
      resource === 'issue' &&
      rest[0] === 'createmeta' &&
      rest[2] === 'issuetypes'
    ) {
      const project = projectOf(rest[1]);
      if (!project) return refusal(404, [`No project could be found with key '${rest[1]}'.`]);
      if (rest.length === 3) {
        return createmetaPage(typePage, 'issueTypes', project.issueTypes.map(typeJson), params);
      }
      const type = project.issueTypes.find((t) => t.id === rest[3]);
      if (!type || rest.length !== 4) {
        return refusal(404, [`The issue type with id '${rest[3]}' does not exist.`]);
      }
      return createmetaPage(fieldPage, 'fields', type.fields.map(fieldJson), params);
    }
    if (method === 'POST' && apiPath === '/rest/api/2/issue') {
      const made = createOne(json['fields'], 0, takeRejection());
      if (!('id' in made)) return refusal(400, made.errorMessages, made.errors);
      return { status: 201, body: createdJson(made) };
    }
    if (method === 'POST' && apiPath === '/rest/api/2/issue/bulk') {
      const updates = json['issueUpdates'];
      if (!Array.isArray(updates)) return refusal(400, ['The request has no issueUpdates.']);
      if (updates.length > BULK_MAX) {
        return refusal(400, [`At most ${BULK_MAX} issues can be created in one request.`]);
      }
      const armed = takeRejection();
      const created: FakeJiraIssue[] = [];
      const errors: unknown[] = [];
      updates.forEach((update: unknown, i) => {
        const made = createOne((update as { fields?: unknown } | null)?.fields, i, armed);
        if ('id' in made) created.push(made);
        else {
          errors.push({
            status: 400,
            elementErrors: { errorMessages: made.errorMessages, errors: made.errors },
            failedElementNumber: i,
          });
        }
      });
      return {
        status: created.length === 0 && errors.length > 0 ? 400 : 201,
        body: { ...bulkShape, issues: created.map(createdJson), errors },
      };
    }
    if (
      method === 'POST' &&
      apiPath === (cloud ? '/rest/api/2/search/jql' : '/rest/api/2/search')
    ) {
      return search(json);
    }
    if (method === 'POST' && resource === 'issue' && rest.length === 2 && rest[1] === 'comment') {
      const issue = issues.find((i) => i.id === rest[0] || i.key === rest[0]);
      if (!issue) return NOT_FOUND;
      if (typeof json['body'] !== 'string' || json['body'].trim() === '') {
        return refusal(400, [], { comment: 'Comment body can not be empty!' });
      }
      issue.comments.push(json['body']);
      const id = String(nextCommentId++);
      return {
        status: 201,
        body: {
          ...commentShape,
          id,
          body: json['body'],
          self: self(`issue/${issue.id}/comment/${id}`),
        },
      };
    }
    return refusal(404, ['Not found.']);
  };

  /** `GET /__fake/issues` and `POST /__fake/issues/:key/status` (`{ name, category }`). */
  const debug = (method: string, pathname: string, body: string): Reply => {
    if (method === 'GET' && pathname === '/__fake/issues') return { status: 200, body: issues };
    const status = /^\/__fake\/issues\/([^/]+)\/status$/.exec(pathname);
    if (method === 'POST' && status) {
      const issue = issues.find((i) => i.key === decodeURIComponent(status[1] ?? ''));
      if (!issue) return NOT_FOUND;
      let wanted: { name?: unknown; category?: unknown };
      try {
        wanted = JSON.parse(body) as typeof wanted;
      } catch {
        return refusal(400, ['Not JSON.']);
      }
      if (typeof wanted.name !== 'string' || !Object.hasOwn(CATEGORIES, String(wanted.category))) {
        return refusal(400, ['A status needs a name and a category.']);
      }
      issue.status = { name: wanted.name, category: wanted.category as JiraStatusCategory };
      return { status: 204 };
    }
    return refusal(404, ['Not found.']);
  };

  const send = (res: ServerResponse, reply: Reply): void => {
    const text =
      reply.body === undefined
        ? ''
        : typeof reply.body === 'string'
          ? reply.body
          : JSON.stringify(reply.body);
    res.writeHead(reply.status, {
      ...(reply.body === undefined ? {} : { 'content-type': 'application/json;charset=UTF-8' }),
      ...reply.headers,
    });
    res.end(text);
  };
  const reset = (req: IncomingMessage): void => {
    try {
      req.socket.resetAndDestroy();
    } catch {
      req.socket.destroy();
    }
  };

  const dispatch = async (
    req: IncomingMessage,
    res: ServerResponse,
    body: string,
  ): Promise<void> => {
    const method = req.method ?? '';
    const [pathname = '/', query = ''] = (req.url ?? '/').split(/\?(.*)/s) as [string, string?];
    if (options.debugRoutes === true && pathname.startsWith('/__fake/')) {
      send(res, debug(method, pathname, body));
      return;
    }
    requests.push({ method, path: pathname, query, headers: req.headers, body });
    const answer = injections
      .find((i) => i.method === method && i.path.test(pathname) && i.answers.length > 0)
      ?.answers.shift();
    if (answer) {
      await answer.before?.();
      if (answer.hang) return;
      if (answer.reset) {
        reset(req);
        return;
      }
      if (answer.afterCreate) {
        route(method, pathname, query, req.headers, body);
        if (answer.afterCreate === 'reset') reset(req);
        return;
      }
      if (!answer.passThrough) {
        const status = answer.status ?? 200;
        // A refusal without a body of its own gets Jira's ErrorCollection.
        const reply =
          answer.body === undefined && status >= 400
            ? refusal(status, [`HTTP ${status}`])
            : { status, body: answer.body };
        send(res, { ...reply, ...(answer.headers ? { headers: answer.headers } : {}) });
        return;
      }
    }
    send(res, route(method, pathname, query, req.headers, body));
  };

  const onRequest = (req: IncomingMessage, res: ServerResponse): void => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      dispatch(req, res, Buffer.concat(chunks).toString('utf8')).catch(() => {
        if (!res.headersSent) send(res, refusal(500, ['The fake Jira failed.']));
      });
    });
  };
  const server: Server = options.https
    ? createHttpsServer({ key: TEST_SERVER_KEY_PEM, cert: TEST_SERVER_CERT_PEM }, onRequest)
    : createServer(onRequest);
  await new Promise<void>((resolve) => server.listen(options.port ?? 0, '127.0.0.1', resolve));
  const url = `${options.https ? 'https' : 'http'}://127.0.0.1:${(server.address() as AddressInfo).port}`;
  base = `${url}${contextPath}`;

  return {
    url,
    token,
    email,
    deployment,
    requests,
    addProject(p) {
      projects.set(p.key, { ...p, issueTypes: p.issueTypes ?? defaultIssueTypes() });
    },
    issues: () => [...issues],
    issue: (key) => issues.find((i) => i.key === key),
    setStatus(key, name, category) {
      issueByKey(key).status = { name, category };
    },
    moveIssue(key, newKey) {
      issueByKey(key).key = newKey;
    },
    deleteIssue(key) {
      issues.splice(issues.indexOf(issueByKey(key)), 1);
    },
    searchLag(ms) {
      lag = ms;
    },
    rejectElements(indexes, errors) {
      rejection = { indexes: new Set(indexes), errors: errors ?? DEFAULT_REJECTION };
    },
    inject(method, pathPattern, ...answers) {
      injections.push({ method, path: pathPattern, answers: [...answers] });
    },
    clearRequests() {
      requests.length = 0;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
