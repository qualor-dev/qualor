import { describe, expect, it } from 'vitest';
import { azureShape, type FakeAzureProcess } from '../../test/fake-azure-devops';
import type { AzureWorkItemType } from '../scm/azure/client';
import {
  analyzeWorkItemType,
  BOARDS_SET_FIELDS,
  mappingCheckOps,
  trackerInUse,
  workItemTags,
} from './mapping';

interface RecordedType {
  name: string;
  referenceName: string;
  fields: { referenceName: string; alwaysRequired: boolean; defaultValue: unknown }[];
}

/** A recorded type (probe item 13) as the client reads it: a null or empty default is none. */
function recordedType(process: FakeAzureProcess, name: string): AzureWorkItemType {
  const types = azureShape<{ body: { value: RecordedType[] } }>('services', `13-${process}-types`)
    .body.value;
  const type = types.find((t) => t.name === name);
  if (!type) throw new Error(`no recorded ${process} type ${name}`);
  return {
    name: type.name,
    referenceName: type.referenceName,
    states: [],
    fields: type.fields.map((f) => ({
      referenceName: f.referenceName,
      alwaysRequired: f.alwaysRequired,
      hasDefault: f.defaultValue !== null && f.defaultValue !== undefined && f.defaultValue !== '',
    })),
  };
}

const field = (referenceName: string, alwaysRequired = false, hasDefault = false) => ({
  referenceName,
  alwaysRequired,
  hasDefault,
});

describe('which work item types Qualor can fill (design §7.8, probe item 18)', () => {
  it('names the fields Qualor sets', () => {
    expect(BOARDS_SET_FIELDS).toEqual([
      'System.Title',
      'System.Description',
      'Microsoft.VSTS.TCM.ReproSteps',
      'System.Tags',
      'System.AreaId',
      'System.AreaPath',
      'System.IterationId',
      'System.IterationPath',
      'System.TeamProject',
      'System.WorkItemType',
    ]);
  });

  it('supports the Agile Bug: ValueArea and State have defaults, Area and Iteration are set', () => {
    expect(analyzeWorkItemType(recordedType('agile', 'Bug'))).toEqual({
      supported: true,
      missingFields: [],
      reproSteps: true,
    });
    expect(analyzeWorkItemType(recordedType('scrum', 'Bug'))).toMatchObject({
      supported: true,
      reproSteps: true,
    });
  });

  it("supports Basic's Issue, without Repro Steps", () => {
    expect(analyzeWorkItemType(recordedType('basic', 'Issue'))).toEqual({
      supported: true,
      missingFields: [],
      reproSteps: false,
    });
  });

  it('refuses a type with a required custom field without a default, naming it', () => {
    const bug = recordedType('agile', 'Bug');
    const extended = {
      ...bug,
      fields: [
        ...bug.fields,
        field('Custom.Team', true, false),
        field('Custom.Optional', false, false),
        field('Custom.Defaulted', true, true),
      ],
    };
    expect(analyzeWorkItemType(extended)).toEqual({
      supported: false,
      missingFields: ['Custom.Team'],
      reproSteps: true,
    });
  });

  it('refuses a type with neither Description nor Repro Steps, naming System.Description', () => {
    const bare: AzureWorkItemType = {
      name: 'Note',
      referenceName: 'Custom.Note',
      states: [],
      fields: [field('System.Title', true), field('System.State', true, true)],
    };
    expect(analyzeWorkItemType(bare)).toEqual({
      supported: false,
      missingFields: ['System.Description'],
      reproSteps: false,
    });
    const reproOnly = { ...bare, fields: [...bare.fields, field('Microsoft.VSTS.TCM.ReproSteps')] };
    expect(analyzeWorkItemType(reproOnly)).toEqual({
      supported: true,
      missingFields: [],
      reproSteps: true,
    });
  });

  it('counts a required set field as filled, whatever its default', () => {
    const type: AzureWorkItemType = {
      name: 'Strict',
      referenceName: 'Custom.Strict',
      states: [],
      fields: BOARDS_SET_FIELDS.map((f) => field(f, true, false)),
    };
    expect(analyzeWorkItemType(type)).toEqual({
      supported: true,
      missingFields: [],
      reproSteps: true,
    });
  });
});

describe('the dry run of a mapping (PUT check 5)', () => {
  it('joins the tags after qualor with "; "', () => {
    expect(workItemTags([])).toBe('qualor');
    expect(workItemTags(['security', 'team a'])).toBe('qualor; security; team a');
  });

  it('sends Title, Description, Repro Steps, the tags and the set paths as JSON Patch adds', () => {
    const ops = mappingCheckOps(
      { tags: ['sec'], areaPath: 'Payments\\Backend', iterationPath: 'Payments\\Iteration 1' },
      true,
    );
    expect(ops.map((o) => o.op)).toEqual(['add', 'add', 'add', 'add', 'add', 'add']);
    expect(Object.fromEntries(ops.map((o) => [o.path, o.value]))).toEqual({
      '/fields/System.Title': 'Qualor mapping check',
      '/fields/System.Description': expect.stringMatching(/^<p>.+<\/p>$/),
      '/fields/Microsoft.VSTS.TCM.ReproSteps': expect.stringMatching(/^<p>.+<\/p>$/),
      '/fields/System.Tags': 'qualor; sec',
      '/fields/System.AreaPath': 'Payments\\Backend',
      '/fields/System.IterationPath': 'Payments\\Iteration 1',
    });
  });

  it('leaves out Repro Steps without the field and the paths that are the root (null)', () => {
    const ops = mappingCheckOps({ tags: [], areaPath: null, iterationPath: null }, false);
    expect(ops.map((o) => o.path)).toEqual([
      '/fields/System.Title',
      '/fields/System.Description',
      '/fields/System.Tags',
    ]);
  });
});

describe('one tracker per project', () => {
  it('answers 409 TRACKER_IN_USE naming the tracker in use', () => {
    const jira = trackerInUse('jira').toProblem();
    expect(jira).toMatchObject({ status: 409, code: 'TRACKER_IN_USE' });
    expect(jira.title).toMatch(/Jira/);
    const boards = trackerInUse('boards').toProblem();
    expect(boards).toMatchObject({ status: 409, code: 'TRACKER_IN_USE' });
    expect(boards.title).toMatch(/Azure Boards/);
  });
});
