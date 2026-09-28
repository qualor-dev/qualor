import { z } from 'zod';

const level = z.enum(['none', 'note', 'warning', 'error']);
const message = z.looseObject({ text: z.string().optional(), markdown: z.string().optional() });
const region = z.looseObject({
  startLine: z.number().int().optional(),
  startColumn: z.number().int().optional(),
  endLine: z.number().int().optional(),
  endColumn: z.number().int().optional(),
  snippet: z.looseObject({ text: z.string().optional() }).optional().catch(undefined),
});
const location = z.looseObject({
  physicalLocation: z
    .looseObject({
      artifactLocation: z
        .looseObject({ uri: z.string().optional(), uriBaseId: z.string().optional() })
        .optional(),
      region: region.optional(),
    })
    .optional(),
  message: message.optional(),
});
const props = z.record(z.string(), z.unknown());
/** SARIF §3.53; a malformed entry becomes `{}` (ignored) without losing the others. */
const relationship = z
  .looseObject({
    target: z
      .looseObject({
        id: z.string().optional(),
        toolComponent: z.looseObject({ name: z.string().optional() }).optional(),
      })
      .optional(),
  })
  .catch({});
const rule = z.looseObject({
  id: z.string(),
  name: z.string().optional(),
  shortDescription: message.optional(),
  /** The rule's static text; the message of a redacting (secret) result. Malformed ⇒ ignored. */
  fullDescription: message.optional().catch(undefined),
  helpUri: z.string().optional(),
  defaultConfiguration: z.looseObject({ level: level.optional() }).optional(),
  properties: props.optional(),
  /** SARIF §3.49.15; SpotBugs links each rule to its CWE entry this way. Malformed ⇒ ignored. */
  relationships: z.array(relationship).optional().catch(undefined),
});
const toolComponent = z.looseObject({
  name: z.string(),
  version: z.string().optional(),
  semanticVersion: z.string().optional(),
  rules: z.array(rule).optional(),
});
const result = z.looseObject({
  ruleId: z.string().optional(),
  ruleIndex: z.number().int().optional(),
  rule: z.looseObject({ id: z.string().optional(), index: z.number().int().optional() }).optional(),
  level: level.optional(),
  kind: z.string().optional(),
  message: message.optional(),
  locations: z.array(location).optional(),
  relatedLocations: z.array(location).optional(),
  partialFingerprints: z.record(z.string(), z.string()).optional(),
  properties: props.optional(),
  suppressions: z.array(z.looseObject({ status: z.string().optional() })).optional(),
});
const run = z.looseObject({
  tool: z.looseObject({ driver: toolComponent, extensions: z.array(toolComponent).optional() }),
  results: z.array(result).optional(),
  originalUriBaseIds: z
    .record(z.string(), z.looseObject({ uri: z.string().optional() }))
    .optional(),
});

export const sarifLogSchema = z.looseObject({ version: z.literal('2.1.0'), runs: z.array(run) });

export type SarifLog = z.infer<typeof sarifLogSchema>;
export type SarifRun = z.infer<typeof run>;
export type SarifResult = z.infer<typeof result>;
export type SarifRule = z.infer<typeof rule>;
export type SarifLocation = z.infer<typeof location>;
export type SarifLevel = z.infer<typeof level>;
