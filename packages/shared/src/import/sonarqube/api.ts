import { z } from 'zod';

/* eslint-disable no-control-regex -- control characters are exactly what is removed */
const CONTROLS = /[\u0000-\u001f\u007f]/g;
const CONTROLS_BUT_LAYOUT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
/* eslint-enable no-control-regex */

/**
 * Spec §5.4: NUL, the other C0 controls and DEL removed from a string SonarQube sent. Multi-line
 * text (issue messages, comments) keeps tab, line feed and carriage return.
 */
export function stripControls(s: string, multiline = false): string {
  return s.replace(multiline ? CONTROLS_BUT_LAYOUT : CONTROLS, '');
}

/** `s` cut to `max` code points, the last one `…` (report-format.md §9). */
function cut(s: string, max: number): string {
  const chars = [...s];
  return chars.length <= max ? s : `${chars.slice(0, max - 1).join('')}…`;
}

/** A string SonarQube sent: at most `max` UTF-16 units, controls removed, `min` or more left. */
const clean = (max: number, min = 0) =>
  z
    .string()
    .max(max)
    .transform((s) => stripControls(s))
    .pipe(z.string().min(min));
/** Multi-line text (spec §5.3): controls removed, cut at `max` with `…`, never refused. */
const cutText = (max: number) => z.string().transform((s) => cut(stripControls(s, true), max));
const sonarKey = clean(1024, 1);
const sonarName = clean(1000);
const count = z.number().int().min(0).max(1_000_000_000);
const lineNumber = z.number().int().min(1).max(10_000_000);

/**
 * Codes SonarQube may extend between versions (issue statuses, resolutions, software qualities):
 * bound to a pattern rather than closed, so a new value is carried, not fatal (spec §5.4).
 */
const code = z.string().regex(/^[A-Z][A-Z0-9_-]{0,31}$/);
/** A SonarQube language key (`js`, `ts`, `java`, `cpp`, `web`, `ipynb`, ...). */
const languageKey = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_+.#-]{0,63}$/);
/** A SonarQube metric key (`new_violations`, `software_quality_security_rating`, ...). */
const metricKey = z.string().regex(/^[A-Za-z0-9_.:-]{1,200}$/);
/** A facet name (`rules`, `severities`, ...). */
const facetProperty = z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/);
/** The issue's `hash`: 32 lowercase hex characters, or `""` for a blank line (spec §10.4). */
const lineHash = z.string().regex(/^(?:[0-9a-f]{32})?$/);

/** Messages are cut at 4 000 like report-format.md §9 (spec §5.3), comments at 20 000. */
export const SONAR_MESSAGE_MAX = 4_000;
export const SONAR_COMMENT_MAX = 20_000;
/** At most this many rules per page (`ps=500`), so at most this many keys in `actives`. */
const MAX_ACTIVES = 500;
/** The 10 000-result window at page size 1 (spec §5.2). */
const MAX_PAGE_INDEX = 10_000;

export const LEGACY_SEVERITIES = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'] as const;
export type LegacySeverity = (typeof LEGACY_SEVERITIES)[number];
export const IMPACT_SEVERITIES = ['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type ImpactSeverity = (typeof IMPACT_SEVERITIES)[number];

const impactSchema = z.looseObject({
  softwareQuality: code,
  severity: z.enum(IMPACT_SEVERITIES),
});
export type SonarImpact = z.infer<typeof impactSchema>;

const pagingSchema = z.looseObject({
  pageIndex: z.number().int().min(1).max(MAX_PAGE_INDEX),
  pageSize: z.number().int().min(1).max(500),
  total: count,
});

export interface SonarVersion {
  major: number;
  minor: number;
  text: string;
}

const VERSION = /^(\d{1,4})\.(\d{1,4})(?:\.\d{1,6})?(?:\.\d{1,9})?$/;

/** Spec §5.4: the plain-text answer of `api/server/version` is at most 64 bytes. */
const VERSION_MAX_BYTES = 64;

/**
 * `api/server/version`: `9.9.4.87374`, `10.7.0.96327`, `2025.1.0.102418`, `25.1.0.102122`,
 * surrounding white space (a trailing line break) removed; null beyond 64 bytes.
 */
export function parseSonarVersion(raw: string): SonarVersion | null {
  if (new TextEncoder().encode(raw).length > VERSION_MAX_BYTES) return null;
  const text = raw.trim();
  const m = VERSION.exec(text);
  if (m === null) return null;
  return { major: Number(m[1]), minor: Number(m[2]), text };
}

export function versionAtLeast(v: SonarVersion, major: number, minor: number): boolean {
  return v.major > major || (v.major === major && v.minor >= minor);
}

/** `paging.total`, else 9.9's top-level `total` of `api/rules/search`; null when neither. */
export function pageTotal(page: { paging?: { total: number }; total?: number }): number | null {
  return page.paging?.total ?? page.total ?? null;
}

export const currentUserSchema = z.looseObject({
  isLoggedIn: z.boolean(),
  login: sonarKey.optional(),
});

/** SonarQube Cloud's `api/organizations/search?organizations=<key>` (spec §4.3). */
export const organizationsSchema = z.looseObject({
  organizations: z.array(z.looseObject({ key: sonarKey, name: sonarName.optional() })).max(500),
});

export const profilesSchema = z.looseObject({
  profiles: z
    .array(
      z.looseObject({
        key: sonarKey,
        name: sonarName,
        language: languageKey,
        isDefault: z.boolean().default(false),
        isBuiltIn: z.boolean().default(false),
        parentKey: sonarKey.optional(),
      }),
    )
    .max(1000),
});

export const rulesPageSchema = z.looseObject({
  paging: pagingSchema.optional(),
  total: count.optional(),
  rules: z
    .array(
      z.looseObject({
        key: sonarKey,
        name: sonarName.optional(),
        lang: languageKey.optional(),
        severity: z.enum(LEGACY_SEVERITIES).optional(),
        impacts: z.array(impactSchema).max(10).optional(),
        params: z
          .array(
            z.looseObject({
              key: clean(200, 1),
              defaultValue: clean(10_000).optional(),
            }),
          )
          .max(100)
          .optional(),
      }),
    )
    .max(500),
  actives: z
    .record(
      z.string().max(1024),
      z
        .array(
          z.looseObject({
            qProfile: sonarKey,
            severity: z.enum(LEGACY_SEVERITIES).optional(),
            impacts: z.array(impactSchema).max(10).optional(),
            params: z
              .array(z.looseObject({ key: clean(200, 1), value: clean(10_000) }))
              .max(100)
              .optional(),
          }),
        )
        .max(100),
    )
    .refine((r) => Object.keys(r).length <= MAX_ACTIVES, {
      message: `more than ${String(MAX_ACTIVES)} rules in actives`,
    })
    .transform((r) => {
      const out: typeof r = {};
      for (const [k, v] of Object.entries(r)) {
        const key = stripControls(k);
        if (key !== '') out[key] = v;
      }
      return out;
    })
    .optional(),
});
export type SonarRulesPage = z.infer<typeof rulesPageSchema>;

const gateId = z.union([clean(100), z.number().int()]);

export const gateListSchema = z.looseObject({
  qualitygates: z
    .array(
      z.looseObject({
        id: gateId.optional(),
        name: sonarName,
        isDefault: z.boolean().optional(),
        isBuiltIn: z.boolean().default(false),
      }),
    )
    .max(1000),
  default: gateId.optional(),
});

/** `api/qualitygates/show`'s operators: SonarQube has had only these two since 7.x. */
export const SONAR_GATE_OPERATORS = ['GT', 'LT'] as const;
/**
 * Any other operator is carried, bounded to a pattern, so one unknown condition does not refuse
 * the whole gate: the mapping reports it `unmapped: operator` (spec §5.4, §8.2).
 */
const gateOperator = z.string().regex(/^[A-Z_]{1,16}$/);

export const gateShowSchema = z.looseObject({
  name: sonarName,
  isBuiltIn: z.boolean().default(false),
  conditions: z
    .array(
      z.looseObject({
        metric: metricKey,
        op: gateOperator,
        error: clean(100),
      }),
    )
    .max(100),
});

export const gateByProjectSchema = z.looseObject({
  qualityGate: z.looseObject({ name: sonarName, default: z.boolean().default(false) }),
});

export const componentsPageSchema = z.looseObject({
  paging: pagingSchema,
  components: z.array(z.looseObject({ key: sonarKey, name: sonarName.optional() })).max(500),
});

export const componentShowSchema = z.looseObject({
  component: z.looseObject({ key: sonarKey, name: sonarName.optional() }),
});

export const branchesSchema = z.looseObject({
  branches: z.array(z.looseObject({ name: clean(255, 1), isMain: z.boolean() })).max(10_000),
});

export const issuesPageSchema = z.looseObject({
  paging: pagingSchema,
  issues: z
    .array(
      z.looseObject({
        key: z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/),
        rule: sonarKey,
        component: sonarKey,
        line: lineNumber.optional(),
        hash: lineHash.optional(),
        textRange: z.looseObject({ startLine: lineNumber }).optional(),
        message: cutText(SONAR_MESSAGE_MAX).optional(),
        resolution: code.optional(),
        issueStatus: code.optional(),
        updateDate: clean(40).optional(),
        comments: z
          .array(
            z.looseObject({
              markdown: cutText(SONAR_COMMENT_MAX).optional(),
              createdAt: clean(40).optional(),
            }),
          )
          .max(1000)
          .optional(),
      }),
    )
    .max(500),
  facets: z
    .array(
      z.looseObject({
        property: facetProperty,
        values: z.array(z.looseObject({ val: clean(1024, 1), count })).max(10_000),
      }),
    )
    .max(10)
    .optional(),
});
export type SonarIssue = z.infer<typeof issuesPageSchema>['issues'][number];

export const hotspotsPageSchema = z.looseObject({ paging: pagingSchema });
