import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  inject,
  input,
  LOCALE_ID,
  output,
  signal,
} from '@angular/core';
import { PHONE_WIDTH } from '../../shared/media';
import { type CoverageState, lineCounts, lineInfo, type LineMap, type Run } from './line-map';

/** The lanes, left to right (top to bottom on a phone). */
const LANE = { coverage: 0, newCode: 1, duplication: 2, issues: 3 } as const;
/** A mark's inset in its lane: lanes are one unit wide, the marks leave a gap between them. */
const INSET = 0.15;
const BREADTH = 1 - 2 * INSET;

interface Mark {
  key: string;
  cls: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface MarkerMark extends Mark {
  id: string;
}

export function coverageStateLabel(state: CoverageState): string {
  switch (state) {
    case 'covered':
      return $localize`:@@lineMap.state.covered:Covered`;
    case 'uncovered':
      return $localize`:@@lineMap.state.uncovered:Not covered`;
    case 'partial':
      return $localize`:@@lineMap.state.partial:Partly covered`;
    default:
      return $localize`:@@lineMap.state.none:Not coverable`;
  }
}

/**
 * `q-line-map` (spec §4.3): a file as a strip with a band per run of lines, in four lanes —
 * coverage (covered, not covered, partly covered), new code, duplicated blocks, and a marker per
 * issue at its start line in its severity's colour. The SVG is one unit per line in a stretched
 * viewBox, so every mark is one `<rect>` per run whatever the file's length; a hairline stroke
 * that does not scale keeps a one-line run visible in a long file. On a phone the strip lies
 * across. Hover or the keyboard (arrows, Page Up/Down, Home, End, Escape) moves a line cursor whose
 * content is said in a polite live region; a click on a marker, or Enter on its line, opens the
 * issue. The page lists the same things as text, so colour never carries them alone.
 */
@Component({
  selector: 'q-line-map',
  templateUrl: './line-map.component.html',
  styleUrl: './line-map.component.css',
})
export class LineMapComponent {
  private readonly locale = inject(LOCALE_ID);
  readonly map = input.required<LineMap>();
  /** The line the URL names (`#L<n>`), drawn outlined across the lanes. */
  readonly highlight = input<number | null>(null);
  readonly openIssue = output<string>();

  protected readonly labels = {
    covered: coverageStateLabel('covered'),
    uncovered: coverageStateLabel('uncovered'),
    partial: coverageStateLabel('partial'),
  };

  /** Lanes across instead of down: on a phone. */
  protected readonly horizontal = signal(false);
  /** The line under the pointer or the keyboard cursor. */
  protected readonly active = signal<number | null>(null);

  /** The axis along the file: at least one unit, so an empty file still has a valid viewBox. */
  private readonly length = computed(() => Math.max(1, this.map().lines));
  protected readonly viewBox = computed(() =>
    this.horizontal() ? `0 0 ${this.length()} 4` : `0 0 4 ${this.length()}`,
  );
  /** Two pixels a line, between 240px and 70 % of the window; only the vertical strip. */
  protected readonly extent = computed(() =>
    this.horizontal() ? null : `clamp(240px, ${this.map().lines * 2}px, 70vh)`,
  );

  /** A box `breadth` wide at `offset` across the lane `lane`, over the lines `from`..`to`. */
  private box(lane: number, from: number, to: number, offset = INSET, breadth = BREADTH) {
    const along = { start: from - 1, size: to - from + 1 };
    const across = { start: lane + offset, size: breadth };
    return this.horizontal()
      ? { x: along.start, y: across.start, width: along.size, height: across.size }
      : { x: across.start, y: along.start, width: across.size, height: along.size };
  }

  protected readonly runs = computed<Mark[]>(() => {
    const map = this.map();
    const lane = (index: number, cls: string, runs: readonly Run[]) =>
      runs.map((r) => ({ key: `${cls}:${r.from}`, cls, ...this.box(index, r.from, r.to) }));
    return [
      ...map.coverage.runs.map((r) => ({
        key: `cov:${r.from}`,
        cls: `run cov cov-${r.value}`,
        ...this.box(LANE.coverage, r.from, r.to),
      })),
      ...lane(LANE.newCode, 'run new', map.newCode),
      ...lane(LANE.duplication, 'run dup', map.duplication),
    ];
  });

  protected readonly markers = computed<MarkerMark[]>(() =>
    this.map().issues.map((i, n) => ({
      key: `${i.id}:${n}`,
      id: i.id,
      cls: `marker tone-${i.severity}`,
      ...this.box(LANE.issues, i.line, i.line),
    })),
  );

  /** The highlighted line across all lanes, when it is in the file. */
  protected readonly hl = computed(() => {
    const line = this.highlight();
    return line !== null && line >= 1 && line <= this.map().lines
      ? this.box(0, line, line, 0, 4)
      : null;
  });

  /** The cursor: a line through the middle of the active line. */
  protected readonly cursor = computed(() => {
    const line = this.active();
    if (line === null) return null;
    const mid = line - 0.5;
    return this.horizontal()
      ? { x1: mid, x2: mid, y1: 0, y2: 4 }
      : { x1: 0, x2: 4, y1: mid, y2: mid };
  });

  protected readonly summary = computed(() => {
    const map = this.map();
    const c = lineCounts(map);
    const n = (value: number) => new Intl.NumberFormat(this.locale).format(value);
    const lines =
      map.lines === 1
        ? $localize`:@@lineMap.oneLine:1 line`
        : $localize`:@@lineMap.lines:${n(map.lines)}:count: lines`;
    const coverage =
      map.coverage.runs.length === 0
        ? $localize`:@@lineMap.noCoverage:no coverage data`
        : $localize`:@@lineMap.coverage:${n(c.covered)}:covered: covered, ${n(c.uncovered)}:uncovered: uncovered, ${n(c.partial)}:partial: partly covered`;
    const fresh = $localize`:@@lineMap.new:${n(c.newCode)}:count: new`;
    const issues =
      c.issues === 1
        ? $localize`:@@lineMap.oneIssue:1 issue`
        : $localize`:@@lineMap.issues:${n(c.issues)}:count: issues`;
    return $localize`:@@lineMap.summary:${lines}:lines:: ${coverage}:coverage:; ${fresh}:newCode:; ${issues}:issues:`;
  });

  /** The active line's tooltip: where it sits along the strip (%) and what is on the line. */
  protected readonly tip = computed(() => {
    const line = this.active();
    const map = this.map();
    if (line === null || map.lines === 0) return null;
    const info = lineInfo(map, line);
    const parts = [coverageStateLabel(info.coverage)];
    if (info.newCode) parts.push($localize`:@@lineMap.tip.new:New code`);
    if (info.duplicated) parts.push($localize`:@@lineMap.tip.duplicated:Duplicated`);
    if (info.issues === 1) parts.push($localize`:@@lineMap.oneIssue:1 issue`);
    else if (info.issues > 1) parts.push($localize`:@@lineMap.issues:${info.issues}:count: issues`);
    return {
      at: ((line - 0.5) / map.lines) * 100,
      flip: line > map.lines / 2,
      line: $localize`:@@lineMap.tip.line:Line ${line}:line:`,
      what: parts.join(', '),
    };
  });

  constructor() {
    const view = inject(DOCUMENT).defaultView;
    // jsdom (the unit tests) has no matchMedia: the strip stands up there unless a test says so.
    if (typeof view?.matchMedia === 'function') {
      const query = view.matchMedia(PHONE_WIDTH);
      this.horizontal.set(query.matches);
      const change = (event: MediaQueryListEvent) => this.horizontal.set(event.matches);
      query.addEventListener('change', change);
      inject(DestroyRef).onDestroy(() => query.removeEventListener('change', change));
    }
  }

  protected point(event: PointerEvent): void {
    const lines = this.map().lines;
    if (lines === 0) return;
    const box = (event.currentTarget as SVGSVGElement).getBoundingClientRect();
    const [offset, size] = this.horizontal()
      ? [event.clientX - box.left, box.width]
      : [event.clientY - box.top, box.height];
    if (size <= 0) return;
    this.active.set(Math.min(lines, Math.max(1, Math.floor((offset / size) * lines) + 1)));
  }

  protected focusIn(): void {
    const lines = this.map().lines;
    if (lines === 0 || this.active() !== null) return;
    const hl = this.highlight();
    this.active.set(hl !== null && hl >= 1 && hl <= lines ? hl : 1);
  }

  protected key(event: KeyboardEvent): void {
    const lines = this.map().lines;
    if (lines === 0) return;
    const current = this.active() ?? 1;
    if (event.key === 'Enter') {
      const issue = this.map().issues.find((i) => i.line === current);
      if (this.active() !== null && issue) {
        event.preventDefault();
        this.openIssue.emit(issue.id);
      }
      return;
    }
    const page = Math.max(1, Math.round(lines / 20));
    const next: Record<string, number | null> = {
      ArrowUp: current - 1,
      ArrowLeft: current - 1,
      ArrowDown: current + 1,
      ArrowRight: current + 1,
      PageUp: current - page,
      PageDown: current + page,
      Home: 1,
      End: lines,
      Escape: null,
    };
    if (!(event.key in next)) return;
    event.preventDefault();
    const line = next[event.key] ?? null;
    this.active.set(line === null ? null : Math.min(lines, Math.max(1, line)));
  }

  protected open(event: MouseEvent, id: string): void {
    event.stopPropagation();
    this.openIssue.emit(id);
  }
}
