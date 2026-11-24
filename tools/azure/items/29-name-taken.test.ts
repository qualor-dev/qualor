import { describe, expect, it } from 'vitest';
import { ITEMS } from './index.js';
import { nameTakenBody, takenAnswer } from './29-name-taken.js';

describe('item 29 helpers', () => {
  it('is registered', () => {
    expect(ITEMS.map((i) => i.id)).toContain(29);
  });

  it('creates what the setup creates, in the root folder, without variables', () => {
    const body = nameTakenBody('Qualor probe item 29 1', 7, { id: 'r', name: 'n' });
    expect(body).toMatchObject({
      name: 'Qualor probe item 29 1',
      path: '\\',
      queue: { id: 7 },
      process: { type: 2, yamlFilename: '.azure-pipelines/qualor.yml' },
      repository: { id: 'r', name: 'n', type: 'TfsGit', defaultBranch: 'refs/heads/main' },
    });
    expect(body).not.toHaveProperty('variables');
  });

  it('reads the status and the typeKey, or none', () => {
    expect(takenAnswer(409, { typeKey: 'DefinitionExistsException', message: 'x' })).toEqual({
      status: 409,
      typeKey: 'DefinitionExistsException',
    });
    expect(takenAnswer(400, 'text')).toEqual({ status: 400, typeKey: 'none' });
  });
});
