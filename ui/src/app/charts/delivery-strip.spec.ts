import { TestBed } from '@angular/core/testing';
import { DeliveryStrip, type StripDelivery } from './delivery-strip';

/** A delivery `minutes` after 09:00 UTC on Sep 15, 2026. */
const delivery = (
  key: string,
  status: StripDelivery['status'],
  minutes = 0,
  code: number | null = status === 'succeeded' ? 204 : status === 'failed' ? 500 : null,
): StripDelivery => ({
  key,
  status,
  at: new Date(Date.UTC(2026, 8, 15, 9, minutes)).toISOString(),
  label: 'Analysis completed',
  code,
});

describe('DeliveryStrip', () => {
  async function render(deliveries: StripDelivery[]) {
    TestBed.configureTestingModule({ imports: [DeliveryStrip] });
    const fixture = TestBed.createComponent(DeliveryStrip);
    fixture.componentRef.setInput('deliveries', deliveries);
    await fixture.whenStable();
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }
  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

  it('draws the deliveries oldest first: delivered above the line, failed below it, pending on it', async () => {
    // The API lists the newest first.
    const { root } = await render([
      delivery('c', 'pending', 2),
      delivery('b', 'failed', 1),
      delivery('a', 'succeeded', 0),
    ]);
    const bars = [...root.querySelectorAll<SVGRectElement>('rect.bar')];
    expect(bars.map((b) => b.getAttribute('data-key'))).toEqual(['a', 'b', 'c']);
    const line = Number(root.querySelector('line.baseline')?.getAttribute('y1'));
    const top = (b: SVGRectElement) => Number(b.getAttribute('y'));
    const bottom = (b: SVGRectElement) => top(b) + Number(b.getAttribute('height'));
    const [up, down, pending] = bars;
    expect(up!.classList).toContain('status-succeeded');
    expect(bottom(up!)).toBeLessThanOrEqual(line);
    expect(down!.classList).toContain('status-failed');
    expect(top(down!)).toBeGreaterThanOrEqual(line);
    expect(pending!.classList).toContain('status-pending');
    expect(top(pending!)).toBeLessThan(line);
    expect(bottom(pending!)).toBeGreaterThan(line);
    // The newest sits at the right end, where every strip ends.
    expect(Number(pending!.getAttribute('x'))).toBeGreaterThan(Number(up!.getAttribute('x')));
  });

  it('sums the deliveries up in words for a screen reader', async () => {
    const { root } = await render([
      delivery('c', 'pending', 2),
      delivery('b', 'failed', 1),
      delivery('a', 'succeeded', 0),
    ]);
    expect(root.querySelector('svg[role="img"]')?.getAttribute('aria-label')).toBe(
      'Last 3 deliveries: 1 delivered, 1 failed, 1 pending.',
    );
  });

  it('says the success rate of the finished deliveries, in numbers beside the percentage', async () => {
    const { root } = await render([
      delivery('d', 'pending', 3),
      delivery('c', 'succeeded', 2),
      delivery('b', 'succeeded', 1),
      delivery('a', 'failed', 0),
    ]);
    expect(text(root.querySelector('.strip-rate'))).toBe('67% delivered 2 of 3');
    expect(text(root.querySelector('.strip-pending'))).toBe('1 pending');
  });

  it('says 0% when every delivery failed, and no rate while none has finished', async () => {
    const failed = await render([delivery('b', 'failed', 1), delivery('a', 'failed', 0)]);
    expect(text(failed.root.querySelector('.strip-rate'))).toBe('0% delivered 0 of 2');
    expect(failed.root.querySelector('.strip-pending')).toBeNull();
    TestBed.resetTestingModule();
    const pending = await render([delivery('a', 'pending', 0)]);
    expect(pending.root.querySelector('.strip-rate')).toBeNull();
    expect(text(pending.root.querySelector('.strip-pending'))).toBe('1 pending');
    expect(text(pending.root.querySelector('.strip-caption'))).toBe('Last delivery');
  });

  it('draws at most the last 20 deliveries', async () => {
    const many = Array.from({ length: 25 }, (_, i) => delivery(`d${24 - i}`, 'succeeded', 24 - i));
    const { root } = await render(many);
    const bars = [...root.querySelectorAll('rect.bar')];
    expect(bars).toHaveLength(20);
    expect(bars[0]?.getAttribute('data-key')).toBe('d5');
    expect(bars.at(-1)?.getAttribute('data-key')).toBe('d24');
    expect(text(root.querySelector('.strip-rate'))).toBe('100% delivered 20 of 20');
    expect(text(root.querySelector('.strip-caption'))).toBe('Last 20 deliveries');
  });

  it('says so when there is no delivery yet, and draws nothing', async () => {
    const { root } = await render([]);
    expect(root.querySelector('svg')).toBeNull();
    expect(text(root)).toBe('No deliveries yet.');
  });

  it('names each delivery in its tooltip, by keyboard too: arrows, Home, End and Escape', async () => {
    const { fixture, root } = await render([
      delivery('b', 'failed', 5),
      delivery('a', 'succeeded', 0),
    ]);
    const svg = root.querySelector<SVGSVGElement>('svg[role="img"]')!;
    expect(svg.getAttribute('tabindex')).toBe('0');
    svg.dispatchEvent(new FocusEvent('focus'));
    await fixture.whenStable();
    // Focus starts on the newest.
    expect(text(root.querySelector('.chart-tip'))).toBe(
      'Failed Sep 15, 2026, 9:05 AM UTC Analysis completed, HTTP 500',
    );
    expect(root.querySelector('.chart-tip')?.getAttribute('role')).toBe('status');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    await fixture.whenStable();
    expect(text(root.querySelector('.chart-tip'))).toBe(
      'Delivered Sep 15, 2026, 9:00 AM UTC Analysis completed, HTTP 204',
    );
    expect(root.querySelector('rect.bar.active')?.getAttribute('data-key')).toBe('a');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'End' }));
    await fixture.whenStable();
    expect(root.querySelector('rect.bar.active')?.getAttribute('data-key')).toBe('b');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home' }));
    await fixture.whenStable();
    expect(root.querySelector('rect.bar.active')?.getAttribute('data-key')).toBe('a');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await fixture.whenStable();
    expect(root.querySelector('.chart-tip')).toBeNull();
  });

  it('says a pending delivery has no answer yet', async () => {
    const { fixture, root } = await render([delivery('a', 'pending', 0)]);
    root.querySelector('svg')!.dispatchEvent(new FocusEvent('focus'));
    await fixture.whenStable();
    expect(text(root.querySelector('.chart-tip'))).toBe(
      'Pending Sep 15, 2026, 9:00 AM UTC Analysis completed',
    );
  });
});
