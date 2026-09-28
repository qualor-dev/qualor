import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { FakeServer, me, ORG_ID, page, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { OrgContext } from './org-context';

const org = (id: string, name: string) => ({ id, key: id, name, createdAt: '', updatedAt: '' });

describe('OrgContext', () => {
  afterEach(() => localStorage.clear());

  it('reads every page of the list and selects the organisation chosen earlier on page 2', async () => {
    localStorage.setItem('qualor.organizationId', 'org-late');
    const server = new FakeServer();
    server.on('GET', '/api/v0/organizations', (request) =>
      request.query.get('cursor') === 'c1'
        ? { body: page([org('org-late', 'Late')]) }
        : { body: page([org(ORG_ID, 'Default')], 'c1') },
    );
    TestBed.configureTestingModule({ providers: [provideFakeServer(server)] });
    TestBed.inject(SessionStore).set(me());
    const context = TestBed.inject(OrgContext);
    context.orgs();
    await settle(TestBed.inject(ApplicationRef));

    expect(server.requestsTo('GET', '/api/v0/organizations')).toHaveLength(2);
    expect(context.orgs().map((o) => o.id)).toEqual([ORG_ID, 'org-late']);
    expect(context.currentId()).toBe('org-late');
    expect(context.current()?.name).toBe('Late');
  });
});
