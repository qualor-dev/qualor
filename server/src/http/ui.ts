import { createHash, randomBytes } from 'node:crypto';
import { constants as fs, type Dirent } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { extname, join, relative, sep } from 'node:path';
import { brotliCompressSync, constants as zlib, gzipSync } from 'node:zlib';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { notFound } from './problem';
import { uiContentSecurityPolicy } from './security-headers';

/**
 * The web UI, served from the same origin as the API (plan 1F ruling Y2). The server never imports
 * UI code: it serves whatever built directory `QUALOR_UI_DIR` names, read once at startup into
 * memory (a production build is well under 1 MiB), so a request never touches the file system and
 * a path can only ever name a file that was there at startup.
 */

/** Written by the UI build into index.html (`ngCspNonce`); replaced by a fresh nonce per request. */
export const CSP_NONCE_PLACEHOLDER = '__QUALOR_CSP_NONCE__';
/** Bounds on what `loadUiAssets` accepts, so a wrong directory fails fast instead of eating memory. */
export const UI_MAX_FILES = 2_000;
export const UI_MAX_BYTES = 64 * 1024 * 1024;
/** Every directory entry the walk looks at (skipped ones too), and how deep it descends. */
export const UI_MAX_ENTRIES = 10_000;
export const UI_MAX_DEPTH = 16;
/**
 * Angular's output hashing, and only its output names: `main-DSibPB6J.js`, `chunk-7S2tK-6Y.js`,
 * `polyfills-…js`, `styles-5INURTSO.css` at the top, and `media/<name>-XXXXXXXX.<ext>`, the hash
 * being 8 characters of `[A-Za-z0-9_-]` (Angular 22's esbuild hashes are mixed case, with `-` and
 * `_`). Any other file (a `favicon-ABCDEFGH.ico` copied from `public/`) is revalidated.
 */
const HASHED_NAME =
  /^\/(?:(?:main|chunk|polyfills|styles)-[A-Za-z0-9_-]{8}\.(?:js|css)|media\/[^/]+-[A-Za-z0-9_-]{8}\.[a-z0-9]+)$/;
const COMPRESS_MIN_BYTES = 1024;
/** `/api`, `/api/…`, also written `//api` or `/API`: never answered with the UI. */
const API_PATH = /^\/+api(\/|$)/i;
/** A request target in origin form (`/path`) or absolute form (`http://host/path`). */
const ORIGIN_OR_ABSOLUTE_FORM = /^(?:\/|https?:\/\/)/i;

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};
const COMPRESSIBLE = new Set(['.html', '.js', '.mjs', '.css', '.json', '.map', '.txt', '.svg']);

export interface UiAsset {
  body: Buffer;
  br: Buffer | null;
  gzip: Buffer | null;
  contentType: string;
  /** The ETag of `body`; the `br` and `gzip` variants carry it with a `-br`/`-gzip` suffix. */
  etag: string;
  /** A content-hashed file name: cached for a year, never revalidated. */
  immutable: boolean;
}

export interface UiAssets {
  /** index.html as text; served for every client route with a fresh CSP nonce. */
  index: string;
  /** Every other file, keyed by its URL path (`/main-4BUTXKQY.js`, `/media/logo.svg`). */
  files: Map<string, UiAsset>;
}

export interface UiLimits {
  maxFiles: number;
  maxBytes: number;
  maxEntries: number;
  maxDepth: number;
}

const DEFAULT_LIMITS: UiLimits = {
  maxFiles: UI_MAX_FILES,
  maxBytes: UI_MAX_BYTES,
  maxEntries: UI_MAX_ENTRIES,
  maxDepth: UI_MAX_DEPTH,
};

export class UiAssetsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UiAssetsError';
  }
}

/**
 * Regular files under `dir`, depth first. Symbolic links (and Windows junctions) are skipped, so
 * only what the build wrote inside the directory is served; so are hidden entries (`.env`, `.git`),
 * which a build never emits but a hand-made directory might hold.
 */
async function listFiles(root: string, limits: UiLimits): Promise<string[]> {
  const out: string[] = [];
  let seen = 0;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > limits.maxDepth) {
      throw new UiAssetsError(`QUALOR_UI_DIR nests deeper than ${limits.maxDepth}: ${root}`);
    }
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      throw new UiAssetsError(`QUALOR_UI_DIR has a directory that cannot be read: ${dir}`);
    }
    seen += entries.length;
    if (seen > limits.maxEntries) {
      throw new UiAssetsError(
        `QUALOR_UI_DIR holds more than ${limits.maxEntries} entries: ${root}`,
      );
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path, depth + 1);
      else if (entry.isFile()) out.push(path);
      if (out.length > limits.maxFiles) {
        throw new UiAssetsError(`QUALOR_UI_DIR holds more than ${limits.maxFiles} files: ${root}`);
      }
    }
  };
  await walk(root, 0);
  return out;
}

/**
 * Reads one file without following a link that replaced it after the listing (O_NOFOLLOW where the
 * platform has it), refusing it before reading when it would exceed the remaining byte budget.
 */
async function readRegularFile(path: string, budget: number): Promise<Buffer | null> {
  const handle = await open(path, fs.O_RDONLY | (fs.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) return null;
    if (stat.size > budget) throw new RangeError('over budget');
    const body = await handle.readFile();
    if (body.length > budget) throw new RangeError('over budget');
    return body;
  } finally {
    await handle.close();
  }
}

function asset(path: string, body: Buffer): UiAsset {
  const ext = extname(path).toLowerCase();
  const compress = COMPRESSIBLE.has(ext) && body.length >= COMPRESS_MIN_BYTES;
  return {
    body,
    br: compress ? brotliCompressSync(body, { params: { [zlib.BROTLI_PARAM_QUALITY]: 9 } }) : null,
    gzip: compress ? gzipSync(body, { level: 9 }) : null,
    contentType: CONTENT_TYPES[ext] ?? 'application/octet-stream',
    etag: `"${createHash('sha256').update(body).digest('base64url').slice(0, 27)}"`,
    immutable: HASHED_NAME.test(path),
  };
}

/**
 * Reads a built UI directory (it must contain index.html) into memory. The directory itself may be
 * a symbolic link (a deploy that points `current` at a release); links inside it are skipped.
 */
export async function loadUiAssets(
  configured: string,
  overrides: Partial<UiLimits> = {},
): Promise<UiAssets> {
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  const dir = await realpath(configured).catch(() => null);
  const stat = dir === null ? null : await lstat(dir).catch(() => null);
  if (dir === null || !stat?.isDirectory()) {
    throw new UiAssetsError(`QUALOR_UI_DIR is not a directory: ${configured}`);
  }
  const paths = await listFiles(dir, limits);
  let index: string | undefined;
  let total = 0;
  const files = new Map<string, UiAsset>();
  for (const path of paths) {
    let body: Buffer | null;
    try {
      body = await readRegularFile(path, limits.maxBytes - total);
    } catch (err) {
      if (err instanceof RangeError) {
        throw new UiAssetsError(
          `QUALOR_UI_DIR holds more than ${limits.maxBytes} bytes: ${configured}`,
        );
      }
      throw new UiAssetsError(`QUALOR_UI_DIR has a file that cannot be read: ${path}`);
    }
    if (body === null) continue;
    total += body.length;
    const urlPath = `/${relative(dir, path).split(sep).join('/')}`;
    if (urlPath === '/index.html') index = body.toString('utf8');
    else files.set(urlPath, asset(urlPath, body));
  }
  if (index === undefined) {
    throw new UiAssetsError(`QUALOR_UI_DIR has no index.html: ${configured}`);
  }
  return { index, files };
}

/**
 * `br`, `gzip` or null from an Accept-Encoding header, honouring `q=0`. A q-value that is not a
 * number in (0, 1] (`q=abc`, `q=-1`, `q=`, `q=2`) counts as 0: the coding is not accepted.
 */
export function preferredEncoding(header: string | undefined): 'br' | 'gzip' | null {
  const accepted = new Set<string>();
  for (const part of (header ?? '').split(',')) {
    const [token = '', ...params] = part.trim().toLowerCase().split(';');
    const q = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
    if (q !== undefined) {
      const value = Number(q.slice(2).trim());
      if (!(value > 0 && value <= 1)) continue;
    }
    accepted.add(token.trim());
  }
  if (accepted.has('br')) return 'br';
  if (accepted.has('gzip')) return 'gzip';
  return null;
}

/** If-None-Match (RFC 9110 §13.1.2, weak comparison): `*` or a list naming this ETag. */
function notModified(header: string | undefined, etag: string): boolean {
  if (header === undefined) return false;
  return header
    .split(',')
    .map((tag) => tag.trim().replace(/^W\//, ''))
    .some((tag) => tag === '*' || tag === etag);
}

function sendAsset(request: FastifyRequest, reply: FastifyReply, file: UiAsset): FastifyReply {
  const encoding = preferredEncoding(request.headers['accept-encoding']);
  const encoded = encoding === null ? null : file[encoding];
  // Each encoding is its own representation, with its own validator.
  const etag = encoded === null ? file.etag : `${file.etag.slice(0, -1)}-${encoding}"`;
  reply
    .header(
      'cache-control',
      file.immutable ? 'public, max-age=31536000, immutable' : 'public, no-cache',
    )
    .header('etag', etag)
    .header('vary', 'accept-encoding')
    .type(file.contentType);
  if (notModified(request.headers['if-none-match'], etag)) return reply.code(304).send();
  if (encoded !== null) return reply.header('content-encoding', encoding).send(encoded);
  return reply.send(file.body);
}

function sendIndex(reply: FastifyReply, assets: UiAssets): FastifyReply {
  // 16 random bytes per response (CSP3 asks for at least 128 bits); the page is never cached,
  // since a cached copy would carry a nonce the next response's policy no longer allows.
  const nonce = randomBytes(16).toString('base64');
  return reply
    .header('content-security-policy', uiContentSecurityPolicy(nonce))
    .header('cache-control', 'no-store')
    .type('text/html; charset=utf-8')
    .send(assets.index.replaceAll(CSP_NONCE_PLACEHOLDER, nonce));
}

/**
 * `GET /*` (and HEAD): a file of the build, else index.html for a client route (the SPA fallback).
 * Never for `/api` or anything under `/api/`: an unknown API path stays the API's 404 problem, so
 * a typo in a client never gets HTML back. A missing file (a last path segment with a dot) is 404
 * too, so a stale chunk name fails loudly instead of loading index.html as a script. A path is
 * only ever looked up in the in-memory map, so `..`, backslashes or NUL cannot reach the disk.
 *
 * The path is the one the router matched (its `*` parameter, percent-decoded once), not the raw
 * request target: an absolute-form target (`GET http://host/api/v0/x`, RFC 9112 §3.2.2) is routed
 * by its path, so the API guard must see that same path. Any other form (`*`) is 404.
 */
export function registerUi(app: FastifyInstance, assets: UiAssets): void {
  app.get('/*', { config: { public: true }, schema: { hide: true } }, async (request, reply) => {
    if (!ORIGIN_OR_ABSOLUTE_FORM.test(request.url)) throw notFound('Route');
    const path = `/${(request.params as { '*'?: string })['*'] ?? ''}`;
    if (API_PATH.test(path)) throw notFound('Route');
    const file = assets.files.get(path);
    if (file) return sendAsset(request, reply, file);
    const last = path.slice(path.lastIndexOf('/') + 1);
    if (last.includes('.') && path !== '/index.html') throw notFound('File');
    return sendIndex(reply, assets);
  });
}
