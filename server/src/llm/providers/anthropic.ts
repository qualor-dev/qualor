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

export const ANTHROPIC_VERSION = '2023-06-01';

const answerSchema = z.looseObject({
  type: z.literal('message'),
  model: z.string().optional(),
  content: z.array(z.looseObject({ type: z.string(), text: z.string().optional() })),
  stop_reason: z.string().nullable().optional(),
  // Read through `tokenCount`: an odd count is unknown, never a reason to refuse the answer.
  usage: z
    .looseObject({ input_tokens: z.unknown(), output_tokens: z.unknown() })
    .optional()
    .catch(undefined),
});

function finish(reason: string | null | undefined): FinishReason {
  if (reason === 'end_turn' || reason === 'stop_sequence') return 'stop';
  if (reason === 'max_tokens') return 'length';
  if (reason === 'refusal') return 'refusal';
  if (reason === 'tool_use') return 'tool';
  return 'other';
}

/**
 * llm.md §2.3: POST <baseUrl>/v1/messages with `x-api-key` and `anthropic-version`. No streaming,
 * tools, metadata or thinking.
 */
export async function anthropicMessages(
  config: ProviderConfig,
  apiKey: string | null,
  call: LlmCall,
  http: ProviderHttpOptions,
): Promise<LlmAnswer> {
  const headers: Record<string, string> = { 'anthropic-version': ANTHROPIC_VERSION };
  if (apiKey !== null) headers['x-api-key'] = apiKey;
  const body: Record<string, unknown> = {
    model: config.model,
    max_tokens: call.maxOutputTokens,
    system: call.system,
    messages: [{ role: 'user', content: call.user }],
  };
  if (config.temperature !== null) body.temperature = config.temperature;
  const parsed = answerSchema.safeParse(
    await postJson(config, '/v1/messages', headers, body, http),
  );
  if (!parsed.success) throw new LlmError('bad_answer', NOT_UNDERSTOOD);
  const toolUse = parsed.data.content.some((b) => b.type === 'tool_use');
  return {
    text: parsed.data.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text ?? '')
      .join(''),
    finishReason: toolUse ? 'tool' : finish(parsed.data.stop_reason),
    usage: {
      inputTokens: tokenCount(parsed.data.usage?.input_tokens),
      outputTokens: tokenCount(parsed.data.usage?.output_tokens),
    },
    model: parsed.data.model ?? null,
  };
}
