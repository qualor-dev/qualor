import { LOCALE_ID, Pipe, type PipeTransform, inject } from '@angular/core';

/**
 * Dates as people read them, always in UTC and labelled so ("Sep 15, 2026, 9:00 AM UTC"): the
 * same instant reads the same for every viewer, in every table and chart of the app.
 */
export function formatDateTime(value: string | null | undefined, locale = 'en-US'): string {
  const date = parse(value);
  return date
    ? new Intl.DateTimeFormat(locale, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZone: 'UTC',
        timeZoneName: 'short',
      }).format(date)
    : '';
}

/** The UTC calendar day of an instant ("Sep 15, 2026"), for charts and their tables. */
export function formatDate(value: string | null | undefined, locale = 'en-US'): string {
  const date = parse(value);
  return date
    ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone: 'UTC' }).format(date)
    : '';
}

function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** `{{ at | dateTime }}` → "Sep 15, 2026, 9:00 AM UTC"; `{{ at | dateTime: 'date' }}` → the day. */
@Pipe({ name: 'dateTime' })
export class DateTimePipe implements PipeTransform {
  private readonly locale = inject(LOCALE_ID);

  transform(value: string | null | undefined, style: 'dateTime' | 'date' = 'dateTime'): string {
    return style === 'date' ? formatDate(value, this.locale) : formatDateTime(value, this.locale);
  }
}
