import { describe, expect, it } from 'vitest';
import { Cleanup } from './common.js';
import {
  addBranchCleanups,
  definitionBody,
  describeFire,
  firstCiBuild,
  probeBranchRefs,
  triggerYaml,
} from './28-ci-trigger.js';

describe('item 28 helpers', () => {
  it('the pipeline file triggers on every branch on the hosted pool', () => {
    const text = triggerYaml();
    expect(text).toContain("include: ['*']");
    expect(text).toContain('vmImage: ubuntu-latest');
    expect(text).toContain('script: echo probe');
  });

  it('the definition carries the setup CI trigger and the YAML file', () => {
    const body = definitionBody('probe-28-s1-1', 7, { id: 'r', name: 'n' });
    expect(body['triggers']).toEqual([
      expect.objectContaining({ triggerType: 'continuousIntegration', settingsSourceType: 2 }),
    ]);
    expect(body['process']).toEqual({ type: 2, yamlFilename: '.azure-pipelines/qualor.yml' });
    expect(body['queue']).toEqual({ id: 7 });
  });

  it('a CI build is any build that is not manual and not ignored', () => {
    const builds = [
      { id: 1, reason: 'manual' },
      { id: 2, reason: 'individualCI' },
    ];
    expect(firstCiBuild(builds)?.id).toBe(2);
    expect(firstCiBuild(builds, [2])).toBeUndefined();
    expect(firstCiBuild([{ id: 3 }])).toBeUndefined();
  });

  it('describes a fire and a miss', () => {
    expect(describeFire('S1', { reason: 'individualCI', seconds: 20 }, 20)).toContain('fired yes');
    expect(describeFire('S1', undefined, 300)).toContain('fired no');
  });
});

describe('item 28 clean-up', () => {
  it('names the four probe branches of a run', () => {
    expect(probeBranchRefs('20261124120000')).toEqual([
      'refs/heads/probe/28-s1-20261124120000',
      'refs/heads/probe/28-s2-20261124120000',
      'refs/heads/probe/28-s3-20261124120000',
      'refs/heads/probe/28-s4-20261124120000',
    ]);
  });

  it('one step per branch: a refused delete leaves the others to their own step', async () => {
    const cleanup = new Cleanup();
    const refs = probeBranchRefs('x');
    const tried: string[] = [];
    addBranchCleanups(cleanup, refs, (ref) => {
      tried.push(ref);
      return ref.includes('-s1-')
        ? Promise.reject(new Error(`delete ${ref}: forcePushRequired`))
        : Promise.resolve();
    });
    const failed = await cleanup.run();
    expect([...tried].sort()).toEqual([...refs].sort());
    expect(failed).toEqual([
      'delete branch refs/heads/probe/28-s1-x: delete refs/heads/probe/28-s1-x: forcePushRequired',
    ]);
  });
});
