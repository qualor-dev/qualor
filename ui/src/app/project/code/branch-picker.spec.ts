import { TestBed } from '@angular/core/testing';
import { FakeServer, page, provideFakeServer, settle } from '../../../testing/fake-server';
import type { Branch } from '../branches';
import { BranchPicker } from './branch-picker';

const PROJECT = 'p1';

function branch(id: string, name: string, overrides: Partial<Branch> = {}): Branch {
  return {
    id,
    name,
    kind: 'branch',
    isMain: false,
    mrTitle: null,
    mrUrl: null,
    mrSourceBranch: null,
    mrTargetBranch: null,
    gateStatus: null,
    lastAnalysisId: null,
    ...overrides,
  } as Branch;
}

describe('BranchPicker', () => {
  it('lists the main branch first, then branches, then merge requests, titled like the Branches page', async () => {
    const server = new FakeServer().on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([
        branch('m1', '7', {
          kind: 'merge_request',
          mrSourceBranch: 'feat',
          mrTargetBranch: 'main',
        }),
        branch('b2', 'dev'),
        branch('b1', 'main', { isMain: true }),
      ]),
    });
    TestBed.configureTestingModule({ providers: [provideFakeServer(server)] });
    const fixture = TestBed.createComponent(BranchPicker);
    fixture.componentRef.setInput('projectId', PROJECT);
    fixture.componentRef.setInput('branchId', 'b2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect([...root.querySelectorAll('option')].map((o) => o.textContent?.trim())).toEqual([
      'main',
      'dev',
      '!7 feat → main',
    ]);
    expect(root.querySelector('select')?.value).toBe('b2');
  });

  it('announces the id of the branch picked', async () => {
    const server = new FakeServer().on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([branch('b1', 'main', { isMain: true }), branch('b2', 'dev')]),
    });
    TestBed.configureTestingModule({ providers: [provideFakeServer(server)] });
    const fixture = TestBed.createComponent(BranchPicker);
    fixture.componentRef.setInput('projectId', PROJECT);
    const picked: string[] = [];
    fixture.componentInstance.picked.subscribe((id) => picked.push(id));
    await settle(fixture);
    const select = (fixture.nativeElement as HTMLElement).querySelector('select')!;
    select.value = 'b2';
    select.dispatchEvent(new Event('change'));
    expect(picked).toEqual(['b2']);
  });
});
