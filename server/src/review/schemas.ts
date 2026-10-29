import { cutAtGrapheme, safeMultilineText } from '@qualor/shared';
import { z } from 'zod';
import { AI_CATEGORIES, REPLY_VERDICTS, type AiCategory } from '../db/schema';

/*
 * The answers of a review's model, and of the model that answers a reply, as strict schemas (llm.md
 * §9.3): an unknown key, a value of the wrong kind, a line that is not a line of a file and a text
 * over its bound are each refused, and the whole answer with them (only the reason for dropping a
 * finding, which is never shown, is cut instead). The pipeline reads every answer with
 * `parseModelJson`, takes the provider's key out of what it read, and only then checks it here; an
 * answer that does not pass is not used (fail closed). The bounds are the ones the prompts give the
 * model. The texts of a finding that people read are cleaned here as they are read (`readable`),
 * its code is not.
 */

export const FINDING_SEVERITIES = ['critical', 'major', 'minor'] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];
export const FINDING_CONFIDENCES = ['high', 'medium', 'low'] as const;
export type FindingConfidence = (typeof FINDING_CONFIDENCES)[number];
/** What the judge says of a finding an earlier review raised. */
export const PRIOR_VERDICTS = ['present', 'fixed', 'unclear'] as const;
export type PriorStatus = (typeof PRIOR_VERDICTS)[number];
/** What the independent verification says of a serious security finding. */
export const VERIFY_VERDICTS = ['confirmed', 'needs_validation', 'rejected'] as const;
export type VerifyVerdict = (typeof VERIFY_VERDICTS)[number];

/** What the model says a person's last note in a thread is (6I-4): the verdict has to match it. */
export const REPLY_INTENTS = ['priority', 'factual', 'question', 'other'] as const;
export type ReplyIntent = (typeof REPLY_INTENTS)[number];

/** The bounds of an answer, in characters (UTF-16 code units) and items. */
export const ANSWER_LIMITS = {
  specialistFindings: 30,
  judgeFindings: 40,
  /** Every specialist finding, of four reviewers. */
  dropped: 120,
  sources: 120,
  /** A verdict for each prior finding the judge is shown (prompts.ts). */
  priorVerdicts: 50,
  pathChars: 1_024,
  titleChars: 120,
  bodyChars: 1_200,
  assumptionChars: 300,
  reasonChars: 300,
  /** A dropped finding's reason is a few words, and cut to this: a judge may drop many. */
  dropReasonChars: 150,
  verdictChars: 200,
  walkthroughItems: 6,
  walkthroughChars: 200,
  /** The lines a suggestion may replace; the storing of findings drops one that replaces more. */
  suggestionReplacedLines: 15,
  suggestionLines: 30,
  suggestionLineChars: 400,
  idChars: 64,
  /** The words of an answer to a reply: the bound of the ledger's column too. */
  replyChars: 1_200,
} as const;
const L = ANSWER_LIMITS;

/** A line of a file: a whole number from 1. */
const lineNumber = z.number().int().min(1);
const notBlank = (value: string): boolean => value.trim() !== '';
/** Text of at most `max` characters that is not blank. */
const text = (max: number) => z.string().max(max).refine(notBlank, 'blank');
const id = z.string().min(1).max(L.idChars);
/**
 * A text of a finding that people read (its title, body and assumption): at most `max` characters,
 * cleaned as the AI assistant's answers are (`safeMultilineText`, llm.md §9.4). Every control,
 * bidirectional control and line separator becomes a space, invisible characters go, a lone
 * surrogate becomes U+FFFD, and at most `lines` lines are kept. It is cleaned as the answer is
 * read, so that the words matched to earlier findings (the fingerprint of a title) are the ones
 * stored, shown and posted; a text that is blank once cleaned is blank. The provider's key was
 * taken out before, matching across the characters removed here (key-scrub.ts), so removing them
 * cannot put a key together again.
 */
const readable = (max: number, lines?: number) =>
  z
    .string()
    .max(max)
    .transform((value) => safeMultilineText(value.trim(), max, lines));

/**
 * A suggestion's lines are code, and are not cleaned: a character taken out of a line of code
 * changes the code (a bidirectional mark in a string literal, say). A suggestion that holds any
 * control, bidirectional or invisible character is refused whole when the finding is stored
 * (checkReviewSuggestion), so no such line reaches a person.
 */
const suggestionSchema = z
  .strictObject({
    startLine: lineNumber,
    endLine: lineNumber,
    lines: z.array(z.string().max(L.suggestionLineChars)).max(L.suggestionLines),
  })
  .refine((s) => s.endLine >= s.startLine, { path: ['endLine'], message: 'before startLine' });

/** What a finding of any reviewer is made of. An optional part may be left out or null. */
const findingFields = {
  category: z.enum(AI_CATEGORIES),
  severity: z.enum(FINDING_SEVERITIES),
  confidence: z.enum(FINDING_CONFIDENCES),
  path: text(L.pathChars),
  line: lineNumber,
  endLine: lineNumber.nullish(),
  /** One line, as the prompts ask and as a thread and the summary show it. */
  title: readable(L.titleChars, 1).refine(notBlank, 'blank'),
  body: readable(L.bodyChars).refine(notBlank, 'blank'),
  assumption: readable(L.assumptionChars).nullish(),
  suggestion: suggestionSchema.nullish(),
};
const endsAfterItStarts = {
  check: (f: { line: number; endLine?: number | null }) => (f.endLine ?? f.line) >= f.line,
  params: { path: ['endLine'], message: 'before line' },
};

const findingSchema = z
  .strictObject(findingFields)
  .refine(endsAfterItStarts.check, endsAfterItStarts.params);
const judgedFindingSchema = z
  .strictObject({
    ...findingFields,
    /** The ids of the specialist findings it comes from. */
    sources: z.array(id).max(L.sources),
    /** The prior finding it is, re-emitted. */
    priorId: id.nullish(),
  })
  .refine(endsAfterItStarts.check, endsAfterItStarts.params);

export const specialistAnswerSchema = z.strictObject({
  findings: z.array(findingSchema).max(L.specialistFindings),
});

export const judgeAnswerSchema = z.strictObject({
  findings: z.array(judgedFindingSchema).max(L.judgeFindings),
  // A drop reason of more than a few words is cut, never the judge's answer refused for it.
  dropped: z
    .array(
      z.strictObject({
        source: id,
        reason: z
          .string()
          .refine((value) => value.trim() !== '', 'blank')
          .transform((value) => cutAtGrapheme(value, L.dropReasonChars)),
      }),
    )
    .max(L.dropped),
  prior: z
    .array(z.strictObject({ id, status: z.enum(PRIOR_VERDICTS), reason: text(L.reasonChars) }))
    .max(L.priorVerdicts),
  summary: z.strictObject({
    verdict: text(L.verdictChars),
    walkthrough: z.array(text(L.walkthroughChars)).max(L.walkthroughItems),
  }),
});

export const verifyAnswerSchema = z.strictObject({
  verdict: z.enum(VERIFY_VERDICTS),
  reason: text(L.reasonChars),
});

/**
 * The answer to a person's reply (6I-4, spec §9): what the person's last note is, what becomes of
 * the finding, and the words Qualor posts, which may be empty (a thanks needs no answer). The words
 * are cleaned as a finding's are. Which verdicts the thread allows, and whether the model read the
 * code for the one it gave, are for the reply engine to check (reply-engine.ts), not for the schema.
 */
export const replyAnswerSchema = z.strictObject({
  intent: z.enum(REPLY_INTENTS),
  verdict: z.enum(REPLY_VERDICTS),
  answer: readable(L.replyChars),
});

export type SpecialistAnswer = z.infer<typeof specialistAnswerSchema>;
export type JudgeAnswer = z.infer<typeof judgeAnswerSchema>;
export type VerifyAnswer = z.infer<typeof verifyAnswerSchema>;
export type ReplyAnswer = z.infer<typeof replyAnswerSchema>;

/** A finding as the pipeline hands it on: its optional parts filled in. */
export interface ReviewFinding {
  category: AiCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  path: string;
  line: number;
  endLine: number;
  title: string;
  body: string;
  assumption: string | null;
  suggestion: { startLine: number; endLine: number; lines: string[] } | null;
}

/**
 * The finding an answer holds, of a specialist or of the judge, with what it left out filled in:
 * `endLine` is `line`, and a missing or blank assumption and a missing suggestion are null.
 */
export function reviewFindingOf(found: z.infer<typeof findingSchema>): ReviewFinding {
  const assumption = found.assumption ?? '';
  const suggestion = found.suggestion ?? null;
  return {
    category: found.category,
    severity: found.severity,
    confidence: found.confidence,
    path: found.path,
    line: found.line,
    endLine: found.endLine ?? found.line,
    title: found.title,
    body: found.body,
    assumption: assumption.trim() === '' ? null : assumption,
    suggestion:
      suggestion === null
        ? null
        : {
            startLine: suggestion.startLine,
            endLine: suggestion.endLine,
            lines: [...suggestion.lines],
          },
  };
}

// ─── What a run keeps of the review's summary ────────────────────────────────

/**
 * What the review says of itself in the summary: a reviewer whose answers could not be read, a
 * conversation that used up its tokens, one that took all its turns, more serious security findings
 * than are verified, a conversation that reached the model's context window, a merge request
 * whose lists were shortened (R47), a review that reached its time limit.
 */
export const REVIEW_NOTES = [
  'reviewer_unreadable',
  'token_limit_reached',
  'turn_limit_reached',
  'verification_capped',
  'context_window_reached',
  'lists_shortened',
  'time_limit_reached',
] as const;
export type ReviewNote = (typeof REVIEW_NOTES)[number];

/** Text of at most `max` characters, counted as the cut counts them: whole characters. */
const upTo = (max: number) =>
  z.string().refine((value) => [...value].length <= max, `at most ${max} characters`);

/**
 * What a run keeps of the review's summary, and what its readers can rely on. It lives here, with
 * the bounds it checks, so that the summary comment can read it without the pipeline.
 */
export const reviewSummarySchema = z.strictObject({
  verdict: upTo(L.verdictChars),
  walkthrough: z.array(upTo(L.walkthroughChars).min(1)).max(L.walkthroughItems),
  notes: z.array(z.enum(REVIEW_NOTES)).max(REVIEW_NOTES.length),
});
export type ReviewSummary = z.infer<typeof reviewSummarySchema>;
