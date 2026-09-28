import { describe, expect, it } from 'vitest';
import { parseInternalHosts } from '../scm/url';
import { llmBaseUrlProblem } from './url';

const none = new Set<string>();

describe('llmBaseUrlProblem (llm.md §4)', () => {
  it('accepts public https and a listed internal http host', () => {
    expect(llmBaseUrlProblem('https://api.openai.com/v1', none)).toBeNull();
    expect(
      llmBaseUrlProblem('http://ollama:11434/v1', parseInternalHosts('ollama:11434')),
    ).toBeNull();
    expect(
      llmBaseUrlProblem('http://localhost:11434/v1', parseInternalHosts('localhost:11434')),
    ).toBeNull();
  });

  it('names QUALOR_LLM_INTERNAL_HOSTS and the API key, not the SCM variable and token', () => {
    expect(llmBaseUrlProblem('http://ollama:11434/v1', none)).toMatch(/QUALOR_LLM_INTERNAL_HOSTS/);
    expect(llmBaseUrlProblem('https://10.0.0.5/v1', none)).toMatch(/QUALOR_LLM_INTERNAL_HOSTS/);
    expect(llmBaseUrlProblem('https://u:p@api.example.com', none)).toMatch(/the API key/);
  });

  it('refuses a metadata address even when listed, and a query', () => {
    expect(
      llmBaseUrlProblem('http://169.254.169.254/', parseInternalHosts('169.254.169.254:80')),
    ).toMatch(/metadata/);
    expect(llmBaseUrlProblem('https://x.openai.azure.com/openai/v1?api-version=1', none)).toMatch(
      /query/,
    );
  });

  it('is not opened by the SCM list', () => {
    expect(llmBaseUrlProblem('http://gitlab.corp/v1', none)).not.toBeNull();
  });
});
