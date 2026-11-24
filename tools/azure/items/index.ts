import type { ProbeItem } from './common.js';
import { item as identity } from './01-identity.js';
import { item as markers } from './02-markers.js';
import { item as threadProperties } from './03-thread-properties.js';
import { item as statusPatch } from './04-status-patch.js';
import { item as suggestion } from './05-suggestion.js';
import { item as threadContext } from './06-thread-context.js';
import { item as statuses } from './07-statuses.js';
import { item as pipeline } from './08-pipeline.js';
import { item as serviceHooks } from './09-service-hooks.js';
import { item as badCredential } from './10-bad-credential.js';
import { item as markdownCorpus } from './11-markdown-corpus.js';
import { item as scopeAndLink } from './12-scope-and-link.js';
import { item as boards } from './13-boards.js';
import { item as threadIds } from './15-thread-ids.js';
import { item as acl } from './16-acl.js';
import { item as headCheckout } from './17-head-checkout.js';
import { item as ci } from './18-ci.js';
import { item as decoration } from './19-decoration.js';
import { item as rightsReplies } from './20-rights-replies.js';
import { item as review } from './21-review.js';
import { item as fixWrites } from './22-fix-writes.js';
import { item as suggestionRanges } from './23-suggestion-ranges.js';
import { item as fixPr } from './24-fix-pr.js';
import { item as aiFix } from './25-ai-fix.js';
import { item as ciSetup } from './26-ci-setup.js';
import { item as onboarding } from './27-onboarding.js';
import { item as ciTrigger } from './28-ci-trigger.js';

/** The probe items, by number (14, the Marketplace publisher verification, is done by hand). */
export const ITEMS: readonly ProbeItem[] = [
  identity,
  markers,
  threadProperties,
  statusPatch,
  suggestion,
  threadContext,
  statuses,
  pipeline,
  serviceHooks,
  badCredential,
  markdownCorpus,
  scopeAndLink,
  boards,
  threadIds,
  acl,
  headCheckout,
  ci,
  decoration,
  rightsReplies,
  review,
  fixWrites,
  suggestionRanges,
  fixPr,
  aiFix,
  ciSetup,
  onboarding,
  ciTrigger,
];
