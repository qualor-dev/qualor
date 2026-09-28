import cookie from '@fastify/cookie';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  bindingMatches,
  clearBindingCookie,
  newBinding,
  setBindingCookie,
  SSO_COOKIE,
} from './binding';

describe('the browser binding (sso-scim.md §7.2)', () => {
  it('matches its own cookie and nothing else', () => {
    const a = newBinding();
    const b = newBinding();
    expect(a.cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(bindingMatches(a.cookie, a.hash)).toBe(true);
    expect(bindingMatches(b.cookie, a.hash)).toBe(false);
    expect(bindingMatches(undefined, a.hash)).toBe(false);
    expect(bindingMatches('', a.hash)).toBe(false);
    expect(bindingMatches(a.cookie + 'x', a.hash)).toBe(false);
    expect(bindingMatches(a.cookie, '')).toBe(false);
    expect(bindingMatches(a.cookie, a.hash.slice(0, 62))).toBe(false);
    expect(bindingMatches(a.cookie, 'z' + a.hash.slice(1))).toBe(false);
  });

  it('is random every time', () => {
    const cookies = new Set(Array.from({ length: 50 }, () => newBinding().cookie));
    expect(cookies.size).toBe(50);
  });

  async function app() {
    const server = Fastify({ trustProxy: true });
    await server.register(cookie);
    server.get('/set', async (request, reply) => {
      setBindingCookie(reply, request, newBinding().cookie);
      return reply.send('ok');
    });
    server.get('/clear', async (request, reply) => {
      clearBindingCookie(reply);
      return reply.send('ok');
    });
    return server;
  }

  it('sets qualor_sso HttpOnly, SameSite=Lax, on the SSO path for 10 minutes, not Secure over http', async () => {
    const server = await app();
    try {
      const res = await server.inject({ method: 'GET', url: '/set' });
      const set = String(res.headers['set-cookie']);
      expect(SSO_COOKIE).toBe('qualor_sso');
      expect(set).toMatch(/^qualor_sso=[A-Za-z0-9_-]{43};/);
      expect(set).toContain('HttpOnly');
      expect(set).toContain('SameSite=Lax');
      expect(set).toContain('Path=/api/v0/ee/sso');
      expect(set).toContain('Max-Age=600');
      expect(set).not.toContain('Secure');
    } finally {
      await server.close();
    }
  });

  it('sets it Secure when the request is https', async () => {
    const server = await app();
    try {
      const res = await server.inject({
        method: 'GET',
        url: '/set',
        headers: { 'x-forwarded-proto': 'https' },
      });
      const set = String(res.headers['set-cookie']);
      expect(set).toContain('Secure');
      expect(set).toContain('HttpOnly');
      expect(set).toContain('SameSite=Lax');
    } finally {
      await server.close();
    }
  });

  it('clears it on the same path', async () => {
    const server = await app();
    try {
      const res = await server.inject({ method: 'GET', url: '/clear' });
      const set = String(res.headers['set-cookie']);
      expect(set).toMatch(/^qualor_sso=;/);
      expect(set).toContain('Path=/api/v0/ee/sso');
      expect(set).toMatch(/Expires=Thu, 01 Jan 1970|Max-Age=0/);
    } finally {
      await server.close();
    }
  });
});
