import { formatDate, formatDateTime } from './date-time.pipe';

describe('formatDateTime', () => {
  it('shows every time in UTC and says so, whatever the browser time zone', () => {
    expect(formatDateTime('2026-09-15T09:00:00.000Z')).toBe('Sep 15, 2026, 9:00 AM UTC');
    expect(formatDateTime('2026-09-15T23:30:00.000Z')).toBe('Sep 15, 2026, 11:30 PM UTC');
    expect(formatDate('2026-09-15T23:30:00.000Z')).toBe('Sep 15, 2026');
  });

  it('shows nothing for no date or one it cannot read', () => {
    expect(formatDateTime(null)).toBe('');
    expect(formatDateTime(undefined)).toBe('');
    expect(formatDateTime('not a date')).toBe('');
    expect(formatDate('')).toBe('');
  });
});
