export interface ReportWarning {
  code: string;
  message: string;
  count?: number;
}

/** report-format §3 `warnings` bounds (validated server-side). */
const MAX_WARNINGS = 1_000;
const MAX_CODE_CHARS = 64;
const MAX_MESSAGE_CHARS = 4_000;

/** Collects report warnings, one entry per code with an occurrence count. */
export class Warnings {
  private readonly byCode = new Map<string, { message: string; count: number }>();

  add(code: string, message: string, count = 1): void {
    // Truncate before keying so two codes that only differ after MAX_CODE_CHARS merge into
    // the entry the report will actually contain, instead of being counted separately here
    // and then colliding (silently, and unpredictably) when `list()` truncates them.
    const key = code.slice(0, MAX_CODE_CHARS);
    const entry = this.byCode.get(key);
    if (entry) entry.count += count;
    else this.byCode.set(key, { message, count });
  }

  addAll(list: readonly { code: string; message: string; count?: number }[]): void {
    for (const w of list) this.add(w.code, w.message, w.count ?? 1);
  }

  list(): ReportWarning[] {
    return [...this.byCode].slice(0, MAX_WARNINGS).map(([code, { message, count }]) => ({
      code,
      message: message.slice(0, MAX_MESSAGE_CHARS),
      count: Math.max(1, count),
    }));
  }
}
