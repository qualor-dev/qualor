import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';
import { databaseStartupError, formatStartupError } from './startup-error';

describe('formatStartupError', () => {
  it('formats a plain Error by its class name, with no code', () => {
    expect(formatStartupError(new Error('boom'))).toBe('Error');
  });

  it('formats a subclass by its own class name', () => {
    class BootstrapError extends Error {}
    expect(formatStartupError(new BootstrapError('set QUALOR_BOOTSTRAP_ADMIN_PASSWORD'))).toBe(
      'BootstrapError',
    );
  });

  it('never includes the message or stack, even when they carry a secret', () => {
    const err = new Error('leaked-argon2-hash-should-not-appear');
    const formatted = formatStartupError(err);
    expect(formatted).not.toContain('leaked-argon2-hash-should-not-appear');
    expect(formatted).toBe('Error');
  });

  it('appends the Postgres SQLSTATE from a DrizzleQueryError, without the query or params', () => {
    const cause = Object.assign(new Error('duplicate key value violates unique constraint'), {
      code: '23505',
    });
    const err = new DrizzleQueryError(
      'insert into "users" ("password_hash") values ($1)',
      ['argon2id$v=19$m=19456,t=2,p=1$totally-secret-hash'],
      cause,
    );
    const formatted = formatStartupError(err);
    expect(formatted).toBe('DrizzleQueryError (23505)');
    expect(formatted).not.toContain('secret');
    expect(formatted).not.toContain('insert into');
  });

  it('walks a deeper cause chain to find the SQLSTATE', () => {
    const pgError = Object.assign(new Error('connection refused'), { code: '08006' });
    const wrapped = new Error('pool error', { cause: pgError });
    const outer = new DrizzleQueryError('select 1', [], wrapped);
    expect(formatStartupError(outer)).toBe('DrizzleQueryError (08006)');
  });

  it('omits the code when the cause chain has none', () => {
    const err = new DrizzleQueryError('select 1', [], new Error('generic failure'));
    expect(formatStartupError(err)).toBe('DrizzleQueryError');
  });

  it('stringifies a non-Error value directly', () => {
    expect(formatStartupError('plain string failure')).toBe('plain string failure');
    expect(formatStartupError(42)).toBe('42');
  });

  it('appends a Node system error code and syscall (e.g. the port is already in use)', () => {
    const err = Object.assign(new Error('listen EADDRINUSE: address already in use :::8080'), {
      code: 'EADDRINUSE',
      syscall: 'listen',
    });
    expect(formatStartupError(err)).toBe('Error (EADDRINUSE, listen)');
  });

  it('appends a system error code without a syscall when none is present', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), {
      code: 'ECONNREFUSED',
    });
    expect(formatStartupError(err)).toBe('Error (ECONNREFUSED)');
  });

  it('finds a system error code through a cause chain, without the message', () => {
    const system = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), {
      code: 'ECONNREFUSED',
      syscall: 'connect',
    });
    const outer = new DrizzleQueryError('select 1', [], system);
    const formatted = formatStartupError(outer);
    expect(formatted).toBe('DrizzleQueryError (ECONNREFUSED, connect)');
    expect(formatted).not.toContain('127.0.0.1');
  });

  it('does not report a system error code once a Postgres SQLSTATE was already found', () => {
    const cause = Object.assign(new Error('duplicate key'), { code: '23505' });
    const err = new DrizzleQueryError('insert into "users" values ($1)', ['x'], cause);
    expect(formatStartupError(err)).toBe('DrizzleQueryError (23505)');
  });
});

describe('databaseStartupError (plan 1G)', () => {
  it('names DATABASE_URL and the system error, never the URL or its password', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED postgres://u:hunter2@db:5432/q'), {
      code: 'ECONNREFUSED',
      syscall: 'connect',
    });
    const message = databaseStartupError(err);
    expect(message).toBe(
      'cannot use the database DATABASE_URL names: Error (ECONNREFUSED, connect); check that PostgreSQL is running and reachable, and the URL and password',
    );
    expect(message).not.toContain('hunter2');
  });

  it('names a Postgres SQLSTATE such as a wrong password (28P01)', () => {
    const err = Object.assign(new Error('password authentication failed for user "u"'), {
      code: '28P01',
    });
    expect(databaseStartupError(err)).toContain('(28P01)');
  });
});
