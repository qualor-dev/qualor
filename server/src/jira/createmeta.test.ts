import { describe, expect, it } from 'vitest';
import type { CreateMetaField } from './client';
import { analyzeIssueType, QUALOR_SET_FIELDS } from './createmeta';

const field = (
  fieldId: string,
  name: string,
  over: Partial<CreateMetaField> = {},
): CreateMetaField => ({
  fieldId,
  name,
  required: false,
  hasDefaultValue: false,
  allowedValues: [],
  ...over,
});

const PRIORITIES = ['1', '2', '3', '4', '5'].map((id) => ({ id, name: `P${id}` }));

/** The create screen of a plain Bug, as Jira answers it. */
const bug = (): CreateMetaField[] => [
  field('project', 'Project', { required: true }),
  field('issuetype', 'Issue Type', { required: true }),
  field('summary', 'Summary', { required: true }),
  field('reporter', 'Reporter', { required: true, hasDefaultValue: true }),
  field('description', 'Description'),
  field('labels', 'Labels'),
  field('priority', 'Priority', {
    hasDefaultValue: true,
    allowedValues: PRIORITIES,
  }),
];

describe('analyzeIssueType (0.16 Jira §6.2)', () => {
  it('names the fields Qualor sets', () => {
    expect(QUALOR_SET_FIELDS).toEqual([
      'project',
      'issuetype',
      'summary',
      'reporter',
      'description',
      'labels',
      'priority',
    ]);
  });

  it('supports a Bug: labels, an optional priority with its five values', () => {
    expect(analyzeIssueType(bug(), false)).toEqual({
      supported: true,
      missingFields: [],
      labels: true,
      priority: { allowed: PRIORITIES, required: false },
    });
  });

  it('refuses a type with a required field Qualor cannot fill, by name', () => {
    const story = [...bug(), field('customfield_10010', 'Components', { required: true })];
    expect(analyzeIssueType(story, false)).toMatchObject({
      supported: false,
      missingFields: ['Components'],
    });
  });

  it('refuses a type whose screen has no description', () => {
    const noDescription = bug().filter((f) => f.fieldId !== 'description');
    expect(analyzeIssueType(noDescription, false)).toMatchObject({
      supported: false,
      missingFields: ['Description'],
    });
  });

  it('accepts a required custom field that has a default', () => {
    const fields = [
      ...bug(),
      field('customfield_10011', 'Team', { required: true, hasDefaultValue: true }),
    ];
    expect(analyzeIssueType(fields, false)).toMatchObject({ supported: true, missingFields: [] });
  });

  it('counts a required priority without a default as missing unless every severity has one (R12)', () => {
    const fields = bug().map((f) =>
      f.fieldId === 'priority' ? { ...f, required: true, hasDefaultValue: false } : f,
    );
    expect(analyzeIssueType(fields, false)).toMatchObject({
      supported: false,
      missingFields: ['Priority'],
    });
    for (const complete of [true, 'any'] as const) {
      expect(analyzeIssueType(fields, complete)).toEqual({
        supported: true,
        missingFields: [],
        labels: true,
        priority: { allowed: PRIORITIES, required: true },
      });
    }
  });

  it('reports no labels field and no priority field', () => {
    const fields = bug().filter((f) => f.fieldId !== 'labels' && f.fieldId !== 'priority');
    expect(analyzeIssueType(fields, false)).toEqual({
      supported: true,
      missingFields: [],
      labels: false,
      priority: null,
    });
  });
});
