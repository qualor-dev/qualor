import { describe, expect, it } from 'vitest';
import {
  describeAnswer,
  listedPolicyIds,
  listedYamlFilename,
  queueLines,
  queueNamed,
  rootEntries,
  rotationBody,
  setupYaml,
  variableReadback,
} from './26-ci-setup.js';

describe('item 26 helpers', () => {
  it('the setup YAML uses the hosted pool and has a non-ASCII line', () => {
    const text = setupYaml();
    expect(text).toContain('vmImage: ubuntu-latest');
    expect(Buffer.byteLength(text)).toBeGreaterThan(text.length);
  });

  it('on Server the setup YAML uses the pool Default, not the hosted image', () => {
    const text = setupYaml('server');
    expect(text).toContain('pool:\n  name: Default\n');
    expect(text).not.toContain('vmImage');
    expect(setupYaml('services')).toBe(setupYaml());
  });

  it('finds a queue by its exact name and lists id, name and pool', () => {
    const queues = [
      { id: 1, name: 'Azure Pipelines 2', pool: { id: 9, name: 'Other' } },
      { id: 2, name: 'Azure Pipelines', pool: { id: 3, name: 'Azure Pipelines' } },
      { id: 3, name: 'Default' },
    ];
    expect(queueNamed(queues, 'Azure Pipelines')?.id).toBe(2);
    expect(queueNamed(queues, 'Nope')).toBeUndefined();
    expect(queueLines(queues)).toEqual([
      '1 Azure Pipelines 2 (pool Other)',
      '2 Azure Pipelines (pool Azure Pipelines)',
      '3 Default (pool none)',
    ]);
  });

  it('reads the root entries, folders with a trailing slash', () => {
    expect(
      rootEntries({
        value: [
          { path: '/', isFolder: true },
          { path: '/.azure-pipelines', isFolder: true },
          { path: '/README.md' },
        ],
      }),
    ).toEqual(['//', '/.azure-pipelines/', '/README.md']);
    expect(rootEntries('nope')).toEqual([]);
  });

  it('reads the yaml file name of a listed definition and the ids of listed policies', () => {
    const json = { value: [{ id: 4, process: { yamlFilename: 'a.yml' } }, { id: 5 }] };
    expect(listedYamlFilename(json, 4)).toBe('a.yml');
    expect(listedYamlFilename(json, 5)).toBeUndefined();
    expect(listedYamlFilename(json, 6)).toBeUndefined();
    expect(listedPolicyIds({ value: [{ id: 1 }, { id: 2 }] })).toEqual([1, 2]);
    expect(listedPolicyIds(null)).toEqual([]);
  });

  it('the rotation body sets the new token and the address and keeps the rest', () => {
    const body = rotationBody(
      {
        id: 7,
        revision: 2,
        variables: { QUALOR_TOKEN: { value: null, isSecret: true }, OTHER: { value: 'x' } },
      },
      'new-secret',
      'https://qualor.example.com',
    );
    expect(body).toMatchObject({
      id: 7,
      revision: 2,
      variables: {
        QUALOR_TOKEN: { value: 'new-secret', isSecret: true },
        QUALOR_URL: { value: 'https://qualor.example.com' },
        OTHER: { value: 'x' },
      },
    });
  });

  it('says how a variable reads back', () => {
    const vars = { A: { value: null, isSecret: true }, B: { value: 'v' } };
    expect(variableReadback(vars, 'A')).toBe('null value, isSecret true');
    expect(variableReadback(vars, 'B')).toBe('has a value, isSecret false');
    expect(variableReadback(vars, 'C')).toBe('absent');
    expect(variableReadback(undefined, 'A')).toBe('absent');
  });

  it('describes an answer by status, typeKey and message', () => {
    expect(describeAnswer(400, { typeKey: 'Bad', message: 'no' })).toBe('HTTP 400 Bad: no');
    expect(describeAnswer(404, { message: 'gone' })).toBe('HTTP 404: gone');
  });
});
