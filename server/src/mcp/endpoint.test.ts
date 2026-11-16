import { describe, expect, it } from 'vitest';
import { missingScope, scopeCovers } from './endpoint';
import { requiredScope } from './tool';
import { MCP_TOOLS } from './tools';

describe('missingScope (the tools/call check before the SDK runs)', () => {
  const scopes = new Map([
    ['qualor_projects', 'mcp:read' as const],
    ['qualor_package_usages', 'mcp:read' as const],
    ['qualor_transition', 'mcp:write' as const],
  ]);
  const call = (name: string, extra: Record<string, unknown> = {}) => ({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name, arguments: {}, ...extra },
  });

  it('names the scope a write tool needs that the token lacks', () => {
    expect(missingScope(call('qualor_transition'), scopes, ['mcp:read'])).toBe('mcp:write');
    expect(missingScope(call('qualor_transition'), scopes, ['mcp:read', 'mcp:write'])).toBeNull();
    expect(missingScope(call('qualor_projects'), scopes, ['mcp:read'])).toBeNull();
  });

  it('needs only mcp:read for qualor_package_usages, as the tool table says (0.16)', () => {
    const table = new Map(MCP_TOOLS.map((t) => [t.name, requiredScope(t.access)]));
    expect(table.get('qualor_package_usages')).toBe('mcp:read');
    expect(missingScope(call('qualor_package_usages'), scopes, ['mcp:read'])).toBeNull();
    expect(missingScope(call('qualor_package_usages'), scopes, [])).toBe('mcp:read');
  });

  it('checks every request of a 2025-era batch', () => {
    const batch = [call('qualor_projects'), call('qualor_transition')];
    expect(missingScope(batch, scopes, ['mcp:read'])).toBe('mcp:write');
  });

  it('checks a 2026-07-28 request, whose envelope rides in params._meta', () => {
    const modern = call('qualor_transition', {
      _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' },
    });
    expect(missingScope(modern, scopes, ['mcp:read'])).toBe('mcp:write');
  });

  it('leaves other methods, unknown tools and junk to the SDK', () => {
    expect(missingScope({ method: 'tools/list' }, scopes, [])).toBeNull();
    expect(missingScope(call('nope'), scopes, [])).toBeNull();
    expect(missingScope('junk', scopes, [])).toBeNull();
    expect(missingScope(null, scopes, [])).toBeNull();
    expect(missingScope({ method: 'tools/call', params: { name: 7 } }, scopes, [])).toBeNull();
  });
});

describe('scopeCovers (the check inside the tool callback)', () => {
  it('needs mcp:write for a write tool and mcp:read for the others', () => {
    expect(scopeCovers(['mcp:read'], 'write')).toBe(false);
    expect(scopeCovers(['mcp:read', 'mcp:write'], 'write')).toBe(true);
    expect(scopeCovers(['mcp:read'], 'read')).toBe(true);
    expect(scopeCovers(['mcp:read'], 'ai')).toBe(true);
    expect(scopeCovers([], 'read')).toBe(false);
  });
});
