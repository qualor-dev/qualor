import { TestBed } from '@angular/core/testing';
import { Distribution, type DistributionItem } from './distribution';

const ITEMS: DistributionItem[] = [
  { key: 'blocker', label: 'Blocker', value: 1, tone: 'blocker' },
  { key: 'high', label: 'High', value: 2, tone: 'high' },
  { key: 'medium', label: 'Medium', value: 4, tone: 'medium' },
  { key: 'info', label: '<b>Info</b>', value: 0, tone: 'info' },
];

describe('Distribution', () => {
  async function render(items: DistributionItem[], layout?: 'rows' | 'inline') {
    TestBed.configureTestingModule({ imports: [Distribution] });
    const fixture = TestBed.createComponent(Distribution);
    fixture.componentRef.setInput('items', items);
    if (layout) fixture.componentRef.setInput('layout', layout);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  it('lists every item with its count, and a bar of the non-empty ones', async () => {
    const root = await render(ITEMS);
    const rows = [...root.querySelectorAll('li')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(rows).toEqual(['Blocker 1', 'High 2', 'Medium 4', '<b>Info</b> 0']);
    expect(root.querySelector('b')).toBeNull();
    expect(root.querySelectorAll('.dist-bar span')).toHaveLength(3);
    expect(root.querySelector('.dist-bar')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('scales the row bars to the largest value', async () => {
    const root = await render(ITEMS);
    const widths = [...root.querySelectorAll<HTMLElement>('.dist-fill')].map((i) => i.style.width);
    expect(widths).toEqual(['25%', '50%', '100%', '0%']);
  });

  it('draws no bar when everything is zero', async () => {
    const root = await render([{ key: 'x', label: 'X', value: 0, tone: 'accent' }]);
    expect(root.querySelector('.dist-bar')).toBeNull();
  });

  it('inline, lists nothing when everything is zero: no empty list for a screen reader', async () => {
    const root = await render([{ key: 'x', label: 'X', value: 0, tone: 'accent' }], 'inline');
    expect(root.querySelector('ul')).toBeNull();
  });

  it('inline, names the items of the bar on one line and leaves the empty ones out', async () => {
    const root = await render(ITEMS, 'inline');
    expect(root.querySelector('.dist-rows')).toBeNull();
    const legend = [...root.querySelectorAll('.dist-legend li')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(legend).toEqual(['Blocker 1', 'High 2', 'Medium 4']);
    expect(root.querySelectorAll('.dist-bar span')).toHaveLength(3);
  });
});
