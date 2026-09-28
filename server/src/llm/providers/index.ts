import { anthropicMessages } from './anthropic';
import { openAiChat } from './openai';
import type { LlmAnswer, LlmCall, ProviderConfig, ProviderHttpOptions } from './types';

export * from './types';
export { retryAfterSeconds } from './http';

/** llm.md §2.1: one call to the configured provider; an answer or an LlmError. */
export function callProvider(
  config: ProviderConfig,
  apiKey: string | null,
  call: LlmCall,
  http: ProviderHttpOptions,
): Promise<LlmAnswer> {
  return config.kind === 'anthropic'
    ? anthropicMessages(config, apiKey, call, http)
    : openAiChat(config, apiKey, call, http);
}
