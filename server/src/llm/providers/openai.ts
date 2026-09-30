import type { FinishReason } from '@qualor/shared';
import { z } from 'zod';
import { NOT_UNDERSTOOD, postJson } from './http';
import {
  LlmError,
  tokenCount,
  type LlmAnswer,
  type LlmCall,
  type ProviderConfig,
  type ProviderHttpOptions,
} from './types';

const answerSchema = z.looseObject({
  model: z.string().optional(),
  choices: z
    .array(
      z.looseObject({
        message: z.looseObject({
          content: z.string().nullable().optional(),
          refusal: z.string().nullable().optional(),
          tool_calls: z.array(z.unknown()).optional(),
        }),
        finish_reason: z.string().nullable().optional(),
      }),
    )
    .min(1),
  // Read through `tokenCount`: an odd count is unknown, never a reason to refuse the answer.
  usage: z
    .looseObject({ prompt_tokens: z.unknown(), completion_tokens: z.unknown() })
    .optional()
    .catch(undefined),
});

function finish(reason: string | null | undefined): FinishReason {
  if (reason === 'stop') return 'stop';
  if (reason === 'length') return 'length';
  if (reason === 'content_filter') return 'refusal';
  if (reason === 'tool_calls' || reason === 'function_call') return 'tool';
  return 'other';
}

/**
 * llm.md §2.2: POST <baseUrl>/chat/completions, the key as `Authorization: Bearer` or (Azure,
 * `api-key`, none without a key. No streaming, tools or vendor metadata fields.
 */
export async function openAiChat(
  config: ProviderConfig,
  apiKey: string | null,
  call: LlmCall,
  http: ProviderHttpOptions,
): Promise<LlmAnswer> {
  const headers: Record<string, string> = {};
  if (apiKey !== null) {
    if (config.auth === 'api-key') headers['api-key'] = apiKey;
    else headers.authorization = `Bearer ${apiKey}`;
  }
  const body: Record<string, unknown> = {
    model: config.model,
    messages: [
      { role: 'system', content: call.system },
      { role: 'user', content: call.user },
    ],
    [config.maxTokensField]: call.maxOutputTokens,
  };
  if (config.jsonMode === 'json_object') body.response_format = { type: 'json_object' };
  if (config.temperature !== null) body.temperature = config.temperature;
  const parsed = answerSchema.safeParse(
    await postJson(config, '/chat/completions', headers, body, http, config.maxTokensField),
  );
  if (!parsed.success) throw new LlmError('bad_answer', NOT_UNDERSTOOD);
  const [choice] = parsed.data.choices;
  if (!choice) throw new LlmError('bad_answer', NOT_UNDERSTOOD);
  const toolCalls = (choice.message.tool_calls?.length ?? 0) > 0;
  const refusal = typeof choice.message.refusal === 'string' && choice.message.refusal !== '';
  const text = choice.message.content;
  if (!toolCalls && !refusal && typeof text !== 'string') {
    throw new LlmError('bad_answer', NOT_UNDERSTOOD);
  }
  return {
    text: text ?? '',
    finishReason: toolCalls ? 'tool' : refusal ? 'refusal' : finish(choice.finish_reason),
    usage: {
      inputTokens: tokenCount(parsed.data.usage?.prompt_tokens),
      outputTokens: tokenCount(parsed.data.usage?.completion_tokens),
    },
    model: parsed.data.model ?? null,
  };
}
