import { TestBed } from '@angular/core/testing';
import { me } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { SetupTokens } from './setup-tokens';

describe('SetupTokens', () => {
  let session: SessionStore;
  let tokens: SetupTokens;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    session = TestBed.inject(SessionStore);
    session.set(me());
    tokens = TestBed.inject(SetupTokens);
    TestBed.tick();
    tokens.keep('run-1', [{ ref: 'acme/api', token: 'qlr_prj_one' }]);
  });

  const kept = () => tokens.forRun('run-1').get('acme/api')?.token ?? null;

  it('keeps a token for the user who received it', () => {
    expect(kept()).toBe('qlr_prj_one');
  });

  it('forgets every token when the user signs out, even if the same user signs in again', () => {
    session.clear();
    TestBed.tick();
    expect(kept()).toBeNull();
    session.set(me());
    TestBed.tick();
    expect(kept()).toBeNull();
    expect(tokens.forRun('run-1').size).toBe(0);
  });

  it('keeps them while the session is only being asked again', () => {
    session.me.set(undefined);
    TestBed.tick();
    session.set(me());
    TestBed.tick();
    expect(kept()).toBe('qlr_prj_one');
  });
});
