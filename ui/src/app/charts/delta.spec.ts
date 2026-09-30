import { TestBed } from '@angular/core/testing';
import { Delta, deltaView } from './delta';

describe('deltaView', () => {
  it('colours a change by the good direction of the metric', () => {
    expect(deltaView('issues', 7, 10, 'en-US')).toEqual({ text: '−3', tone: 'good' });
    expect(deltaView('issues', 12, 10, 'en-US')).toEqual({ text: '+2', tone: 'bad' });
    expect(deltaView('coverage', 65.7, 63.6, 'en-US')).toEqual({ text: '+2.1 pts', tone: 'good' });
    expect(deltaView('ncloc', 654, 616, 'en-US')).toEqual({ text: '+38', tone: 'neutral' });
  });

  it('says there was no change, and says nothing without both values', () => {
    expect(deltaView('duplicated_lines_density', 0, 0.02, 'en-US')).toEqual({
      text: 'No change',
      tone: 'neutral',
    });
    expect(deltaView('issues', 7, null, 'en-US')).toBeNull();
    expect(deltaView('issues', null, 7, 'en-US')).toBeNull();
  });
});

describe('Delta', () => {
  it('shows the change and since when', async () => {
    TestBed.configureTestingModule({ imports: [Delta] });
    const fixture = TestBed.createComponent(Delta);
    fixture.componentRef.setInput('metric', 'issues');
    fixture.componentRef.setInput('current', 7);
    fixture.componentRef.setInput('previous', 10);
    fixture.componentRef.setInput('since', '2026-09-15T09:00:00.000Z');
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.delta-good')?.textContent?.trim()).toBe('−3');
    expect(root.textContent?.replace(/\s+/g, ' ').trim()).toBe('−3 since Sep 15, 2026');
  });
});
