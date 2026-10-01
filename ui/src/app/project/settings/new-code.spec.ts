import { definitionFromForm, formFromDefinition, sameDefinition } from './new-code';

describe('new-code form (spec §3.1)', () => {
  it('maps definitions to the form and back', () => {
    expect(formFromDefinition(null)).toEqual({ choice: 'default', days: '30', analysisId: '' });
    expect(formFromDefinition({ type: 'days', value: 14 })).toEqual({
      choice: 'days',
      days: '14',
      analysisId: '',
    });
    expect(formFromDefinition({ type: 'previous_version' }).choice).toBe('previous_version');
    expect(formFromDefinition({ type: 'analysis', analysisId: 'a1' })).toEqual({
      choice: 'analysis',
      days: '30',
      analysisId: 'a1',
    });
    expect(definitionFromForm({ choice: 'default', days: '', analysisId: '' })).toEqual({
      value: null,
    });
    expect(definitionFromForm({ choice: 'days', days: ' 45 ', analysisId: '' })).toEqual({
      value: { type: 'days', value: 45 },
    });
    expect(definitionFromForm({ choice: 'previous_version', days: 'x', analysisId: '' })).toEqual({
      value: { type: 'previous_version' },
    });
    expect(definitionFromForm({ choice: 'analysis', days: '', analysisId: 'a1' })).toEqual({
      value: { type: 'analysis', analysisId: 'a1' },
    });
  });

  it('refuses days outside 1–3650 or not whole, and an analysis choice without one', () => {
    for (const days of ['', '0', '3651', '2.5', '-1', '1e3', 'ten']) {
      expect(definitionFromForm({ choice: 'days', days, analysisId: '' })).toEqual({
        error: 'days',
      });
    }
    expect(definitionFromForm({ choice: 'days', days: '3650', analysisId: '' })).toEqual({
      value: { type: 'days', value: 3650 },
    });
    expect(definitionFromForm({ choice: 'analysis', days: '', analysisId: '' })).toEqual({
      error: 'analysis',
    });
  });

  it('compares definitions by value', () => {
    expect(sameDefinition(null, null)).toBe(true);
    expect(sameDefinition({ type: 'days', value: 30 }, null)).toBe(false);
    expect(sameDefinition({ type: 'days', value: 30 }, { type: 'days', value: 30 })).toBe(true);
    expect(sameDefinition({ type: 'days', value: 30 }, { type: 'days', value: 31 })).toBe(false);
    expect(sameDefinition({ type: 'previous_version' }, { type: 'days', value: 30 })).toBe(false);
    expect(
      sameDefinition({ type: 'analysis', analysisId: 'a' }, { type: 'analysis', analysisId: 'a' }),
    ).toBe(true);
  });
});
