import { readFileSync } from 'node:fs';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'llm-shapes');
const MAX_BODY = 1024 * 1024;

/** One example answer of `server/test/llm-shapes/` (plan 3B ruling LL11), a fresh copy each call. */
export function llmShape<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(path.join(SHAPES, `${name}.json`), 'utf8')) as T;
}

export interface RecordedLlmRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
  json: unknown;
}
export interface LlmReply {
  status: number;
  headers?: Record<string, string>;
  body: unknown;
  delayMs?: number;
}
export type LlmResponder = (request: RecordedLlmRequest) => LlmReply | Promise<LlmReply>;

/** A chat completion (llm.md §2.2) whose first choice says `text`. */
export function openAiAnswer(
  text: string,
  over: {
    finishReason?: string;
    model?: string;
    usage?: { prompt_tokens: number; completion_tokens: number } | null;
    toolCalls?: boolean;
  } = {},
): unknown {
  const shape = llmShape<{
    choices: { message: Record<string, unknown>; finish_reason: string }[];
    usage?: unknown;
    model: string;
  }>('openai-chat-completion');
  const choice = shape.choices[0]!;
  choice.message.content = text;
  if (over.toolCalls) {
    choice.message.tool_calls = [
      { id: 'call_1', type: 'function', function: { name: 'x', arguments: '{}' } },
    ];
  }
  choice.finish_reason = over.finishReason ?? 'stop';
  if (over.model) shape.model = over.model;
  if (over.usage === null) delete shape.usage;
  else if (over.usage) {
    shape.usage = {
      ...over.usage,
      total_tokens: over.usage.prompt_tokens + over.usage.completion_tokens,
    };
  }
  return shape;
}

/** A Messages API answer (llm.md §2.3) with one text block saying `text`. */
export function anthropicAnswer(
  text: string,
  over: {
    stopReason?: string;
    model?: string;
    usage?: { input_tokens: number; output_tokens: number } | null;
    toolUse?: boolean;
  } = {},
): unknown {
  const shape = llmShape<{
    content: unknown[];
    stop_reason: string;
    usage?: unknown;
    model: string;
  }>('anthropic-message');
  shape.content = [{ type: 'text', text }];
  if (over.toolUse) shape.content.push({ type: 'tool_use', id: 'toolu_1', name: 'x', input: {} });
  shape.stop_reason = over.stopReason ?? 'end_turn';
  if (over.model) shape.model = over.model;
  if (over.usage === null) delete shape.usage;
  else if (over.usage) shape.usage = over.usage;
  return shape;
}

const DATA_BLOCK = /<<<QUALOR-DATA-([0-9a-f]{32})\n(.*)\nQUALOR-DATA-\1>>>/;

interface DataObject {
  task: 'explain' | 'triage' | 'fix';
  issue: { startLine: number | null; snippet: { startLine: number; lines: string[] } | null };
}

function userText(json: unknown): string {
  const messages = (json as { messages?: unknown } | null)?.messages;
  if (!Array.isArray(messages)) return '';
  const user = (messages as { role?: unknown; content?: unknown }[]).find(
    (m) => typeof m === 'object' && m !== null && m.role === 'user',
  );
  return typeof user?.content === 'string' ? user.content : '';
}

/** A valid answer for the task of the request's data block (llm.md §6–§8); `{"ok": true}` without one. */
export function cannedModelText(request: RecordedLlmRequest): string {
  const match = DATA_BLOCK.exec(userText(request.json));
  if (!match) return '{"ok": true}';
  let data: DataObject;
  try {
    data = JSON.parse(match[2] ?? '') as DataObject;
  } catch {
    return '{"ok": true}';
  }
  // A block that is not the data object (a test sending something else) answers like none.
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof data.issue !== 'object' ||
    data.issue === null
  ) {
    return '{"ok": true}';
  }
  if (data.task === 'explain') {
    return JSON.stringify({
      summary: 'Loose equality compares after type coercion.',
      explanation:
        'The == operator converts its operands before comparing them, which hides type mistakes.',
      howToFix: 'Use === and convert the value explicitly when a conversion is intended.',
    });
  }
  if (data.task === 'triage') {
    return JSON.stringify({
      verdict: 'likely_true_positive',
      confidence: 'medium',
      reasons: ['The comparison mixes a number with a value of unknown type.'],
    });
  }
  const { startLine, snippet } = data.issue;
  const line =
    snippet && startLine !== null ? snippet.lines[startLine - snippet.startLine] : undefined;
  if (line === undefined || !/[^=!]==(?!=)/.test(line)) {
    return JSON.stringify({
      status: 'not_applicable',
      startLine: startLine ?? 1,
      endLine: startLine ?? 1,
      replacement: [],
      explanation: 'Nothing to change here.',
    });
  }
  return JSON.stringify({
    status: 'fixed',
    startLine,
    endLine: startLine,
    replacement: [line.replace(/([^=!])==(?!=)/, '$1===')],
    explanation: 'Use strict equality.',
  });
}

export interface FakeLlm {
  /** `http://127.0.0.1:<port>` */
  url: string;
  /** The `openai` base URL (`<url>/v1`). */
  openAiBaseUrl: string;
  /** The `anthropic` base URL (`<url>`). */
  anthropicBaseUrl: string;
  /** `127.0.0.1:<port>`, for `QUALOR_LLM_INTERNAL_HOSTS`. */
  host: string;
  /** The key the fake expects; '' when it expects none. */
  apiKey: string;
  requests: RecordedLlmRequest[];
  /** Replies (or responders) for the next requests, first in first out. */
  enqueue(...replies: (LlmReply | LlmResponder)[]): void;
  /** The model's text for the next answers, in the shape of the path asked. */
  say(...texts: string[]): void;
  close(): Promise<void>;
}

/**
 * A local provider on 127.0.0.1 answering `POST /v1/chat/completions` (OpenAI-compatible, key as
 * `Authorization: Bearer` or Azure's `api-key`) and `POST /v1/messages` (Anthropic, `x-api-key`
 * and `anthropic-version: 2023-06-01`). It records every request; scripted replies are served
 * first, else a canned answer for the request's data block. Nothing here ever calls a real model.
 */
export async function createFakeLlm(options: { apiKey?: string | null } = {}): Promise<FakeLlm> {
  const apiKey =
    options.apiKey === null
      ? ''
      : (options.apiKey ?? ['fake', 'llm', 'key', '0123456789'].join('-'));
  const requests: RecordedLlmRequest[] = [];
  const queue: (LlmReply | LlmResponder | { say: string })[] = [];

  const shaped = (request: RecordedLlmRequest, text: string): LlmReply => ({
    status: 200,
    body: request.path === '/v1/messages' ? anthropicAnswer(text) : openAiAnswer(text),
  });

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size <= MAX_BODY) chunks.push(c);
    });
    req.on('end', () => {
      void (async () => {
        const body = Buffer.concat(chunks).toString('utf8');
        let json: unknown;
        try {
          json = JSON.parse(body);
        } catch {
          json = null;
        }
        const request: RecordedLlmRequest = {
          method: req.method ?? '',
          path: req.url ?? '',
          headers: req.headers,
          body,
          json,
        };
        requests.push(request);
        const send = (reply: LlmReply): void => {
          const text = typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body);
          setTimeout(() => {
            if (res.destroyed) return;
            res.writeHead(reply.status, { 'content-type': 'application/json', ...reply.headers });
            res.end(text);
          }, reply.delayMs ?? 0);
        };
        const anthropic = request.path === '/v1/messages';
        const error = llmShape(anthropic ? 'anthropic-error' : 'openai-error');
        if (size > MAX_BODY) return send({ status: 413, body: error });
        if (request.method !== 'POST' || (!anthropic && request.path !== '/v1/chat/completions')) {
          return send({ status: 404, body: error });
        }
        const key = anthropic
          ? req.headers['x-api-key']
          : (req.headers.authorization?.replace(/^Bearer /, '') ?? req.headers['api-key']);
        if (apiKey === '') {
          // A provider without a key (a local model): a key header sent anyway is a client bug.
          const sent = ['authorization', 'api-key', 'x-api-key'].some((h) => h in req.headers);
          if (sent) return send({ status: 400, body: error });
        } else if (key !== apiKey) {
          return send({ status: 401, body: error });
        }
        if (anthropic && req.headers['anthropic-version'] !== '2023-06-01') {
          return send({ status: 400, body: error });
        }
        const next = queue.shift();
        try {
          if (next === undefined) return send(shaped(request, cannedModelText(request)));
          if (typeof next === 'function') return send(await next(request));
          if ('say' in next) return send(shaped(request, next.say));
          return send(next);
        } catch {
          // A throwing responder answers 500 instead of leaving the request hanging.
          return send({ status: 500, body: error });
        }
      })();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}`;
  return {
    url,
    openAiBaseUrl: `${url}/v1`,
    anthropicBaseUrl: url,
    host: `127.0.0.1:${port}`,
    apiKey,
    requests,
    enqueue: (...replies) => {
      queue.push(...replies);
    },
    say: (...texts) => {
      queue.push(...texts.map((say) => ({ say })));
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => {
          resolve();
        });
      }),
  };
}
