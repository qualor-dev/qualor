import { Component, computed, inject, input, LOCALE_ID, signal } from '@angular/core';
import { formatDateTime } from '../shared/date-time.pipe';

/** One webhook delivery as the strip draws it. */
export interface StripDelivery {
  key: string;
  status: 'succeeded' | 'failed' | 'pending';
  /** When it was created (ISO). */
  at: string;
  /** What was delivered, as the page names it ("Analysis completed"). */
  label: string;
  /** The receiver's HTTP status, once it answered. */
  code: number | null;
}

/** The deliveries a strip draws, and so the width every strip has. */
const SLOTS = 20;
const BAR = 7;
const STEP = 10;
const HEIGHT = 30;
const LINE = 15;
/** Delivered rises above the line, failed drops below it, pending sits on it. */
const SHAPE = {
  succeeded: { y: 2, height: 12 },
  failed: { y: 16, height: 12 },
  pending: { y: 13, height: 4 },
} as const;

/** A delivery's status in words, for the tooltip and the page's table. */
export function deliveryStatusLabel(status: StripDelivery['status']): string {
  switch (status) {
    case 'succeeded':
      return $localize`:@@webhooks.delivery.succeeded:Delivered`;
    case 'failed':
      return $localize`:@@webhooks.delivery.failed:Failed`;
    default:
      return $localize`:@@webhooks.delivery.pending:Pending`;
  }
}

/**
 * `q-delivery-strip` (spec §6.8): a webhook's last 20 deliveries as small bars, oldest to newest
 * with the newest at the right end, and the success rate beside them. Delivered bars rise above a
 * line and failed ones drop below it (so the status never rests on colour alone); a pending one
 * sits on the line. The rate counts the finished deliveries and says how many are pending. Each
 * bar names its delivery in a tooltip, also from the keyboard (arrows, Home, End, Escape); the
 * page lists the same deliveries in a table.
 */
@Component({
  selector: 'q-delivery-strip',
  templateUrl: './delivery-strip.html',
  styleUrl: './delivery-strip.css',
})
export class DeliveryStrip {
  private readonly locale = inject(LOCALE_ID);
  /** The deliveries, newest first, as `GET /webhooks/{id}/deliveries` lists them. */
  readonly deliveries = input.required<readonly StripDelivery[]>();
  protected readonly width = SLOTS * STEP - (STEP - BAR);
  protected readonly height = HEIGHT;
  protected readonly line = LINE;
  protected readonly viewBox = `0 0 ${this.width} ${HEIGHT}`;
  protected readonly active = signal<number | null>(null);

  /** Oldest first, at most the last 20. */
  protected readonly shown = computed(() => this.deliveries().slice(0, SLOTS).reverse());

  protected readonly bars = computed(() => {
    const shown = this.shown();
    const first = SLOTS - shown.length;
    return shown.map((d, i) => ({
      key: d.key,
      status: d.status,
      x: (first + i) * STEP,
      center: (first + i) * STEP + BAR / 2,
      ...SHAPE[d.status],
    }));
  });

  protected readonly counts = computed(() => {
    const shown = this.shown();
    const of = (status: StripDelivery['status']) => shown.filter((d) => d.status === status).length;
    const succeeded = of('succeeded');
    const failed = of('failed');
    const finished = succeeded + failed;
    return {
      succeeded,
      failed,
      pending: of('pending'),
      finished,
      percent: finished > 0 ? Math.round((100 * succeeded) / finished) : null,
    };
  });

  protected readonly summary = computed(() => {
    const { succeeded, failed, pending } = this.counts();
    const total = this.shown().length;
    // One delivery is one ("Last delivery"), as the caption says it.
    const last =
      total === 1
        ? $localize`:@@strip.lastOne:Last delivery`
        : $localize`:@@strip.lastMany:Last ${total}:total: deliveries`;
    return $localize`:@@strip.summaryOf:${last}:last:: ${succeeded}:succeeded: delivered, ${failed}:failed: failed, ${pending}:pending: pending.`;
  });

  protected readonly tip = computed(() => {
    const index = this.active();
    const bar = index === null ? undefined : this.bars()[index];
    const d = index === null ? undefined : this.shown()[index];
    if (!bar || !d) return null;
    return {
      x: bar.center,
      flip: bar.center > this.width / 2,
      status: deliveryStatusLabel(d.status),
      at: formatDateTime(d.at, this.locale),
      detail:
        d.code === null
          ? d.label
          : $localize`:@@strip.detail:${d.label}:what:, HTTP ${d.code}:code:`,
    };
  });

  protected point(event: PointerEvent): void {
    const svg = event.currentTarget as SVGSVGElement;
    const box = svg.getBoundingClientRect();
    const px = box.width > 0 ? ((event.clientX - box.left) * this.width) / box.width : 0;
    let best: number | null = null;
    let distance = Infinity;
    this.bars().forEach((bar, i) => {
      if (Math.abs(bar.center - px) < distance) {
        distance = Math.abs(bar.center - px);
        best = i;
      }
    });
    this.active.set(best);
  }

  protected focusIn(): void {
    const n = this.bars().length;
    if (n > 0 && this.active() === null) this.active.set(n - 1);
  }

  protected key(event: KeyboardEvent): void {
    const n = this.bars().length;
    if (n === 0) return;
    const current = this.active() ?? n - 1;
    const next = new Map<string, number | null>([
      ['ArrowLeft', Math.max(0, current - 1)],
      ['ArrowRight', Math.min(n - 1, current + 1)],
      ['Home', 0],
      ['End', n - 1],
      ['Escape', null],
    ]);
    if (!next.has(event.key)) return;
    event.preventDefault();
    this.active.set(next.get(event.key) ?? null);
  }
}
