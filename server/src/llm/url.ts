import { baseUrlProblem } from '../scm/url';

/** llm.md §4: the SCM connection rules, with the LLM's own list of internal hosts. */
export function llmBaseUrlProblem(raw: string, internalHosts: ReadonlySet<string>): string | null {
  return baseUrlProblem(raw, internalHosts, {
    variable: 'QUALOR_LLM_INTERNAL_HOSTS',
    credential: 'the API key',
  });
}
