import type { paths } from '../api/schema';

type TestAnswer =
  paths['/api/v0/system/llm/test']['post']['responses'][200]['content']['application/json'];
/** llm.md §14's codes, from the Test answer's schema (Task 8), so this file needs no DM-1 route. */
export type LlmErrorCode = NonNullable<TestAnswer['problem']>['code'];

/** llm.md §14 in the UI's own words (plan 1F ruling Y3: the server's English text is never shown). */
export function llmProblemText(code: LlmErrorCode): string {
  switch (code) {
    case 'PROVIDER_TIMEOUT':
      return $localize`:@@ai.problem.timeout:The model did not answer in time; raise the timeout in the AI assistant settings.`;
    case 'PROVIDER_UNAVAILABLE':
      return $localize`:@@ai.problem.unavailable:The model provider could not be reached.`;
    case 'PROVIDER_RATE_LIMITED':
      return $localize`:@@ai.problem.rateLimited:The model provider is rate limiting Qualor; try later.`;
    case 'PROVIDER_REFUSED_KEY':
      return $localize`:@@ai.problem.key:The provider refused the API key.`;
    case 'PROVIDER_REJECTED_REQUEST':
      return $localize`:@@ai.problem.rejected:The provider refused the request; check the base URL and the model.`;
    case 'PROVIDER_BAD_ANSWER':
      return $localize`:@@ai.problem.badAnswer:The provider's answer was not understood.`;
    case 'URL_NOT_ALLOWED':
      return $localize`:@@ai.problem.url:The provider's address is not allowed; an internal host must be listed in QUALOR_LLM_INTERNAL_HOSTS.`;
    case 'KEY_UNDECRYPTABLE':
      return $localize`:@@ai.problem.undecryptable:The stored API key can no longer be read; set it again.`;
    case 'MALFORMED_OUTPUT':
    case 'OUTPUT_TRUNCATED':
      return $localize`:@@ai.problem.output:The model's answer could not be used.`;
    case 'MODEL_REFUSED':
      return $localize`:@@ai.problem.refused:The model declined to answer.`;
    case 'OUTPUT_REFUSED':
      return $localize`:@@ai.problem.unsafe:The suggested fix was not safe to show.`;
    case 'AI_DISABLED':
      return $localize`:@@ai.problem.disabled:The AI assistant was turned off for this organisation.`;
    case 'SETTINGS_CHANGED':
    case 'ISSUE_CHANGED':
    case 'ISSUE_GONE':
      return $localize`:@@ai.problem.changed:Something changed since you asked; ask again.`;
    case 'REQUEST_ABANDONED':
      return $localize`:@@ai.problem.abandoned:The request was interrupted; ask again.`;
  }
}
