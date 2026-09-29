import { Component, input } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthLayout } from './auth-layout';

@Component({
  imports: [AuthLayout],
  template: `<q-auth-layout [art]="art()">
    <div class="card auth-card" id="projected">Card</div>
  </q-auth-layout>`,
})
class Host {
  readonly art = input<'signin' | 'offline'>('signin');
}

describe('AuthLayout (spec §7.9)', () => {
  it('shows the ink panel with the brand and the tagline beside the projected card', async () => {
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const main = el.querySelector('main.auth-page')!;
    const art = main.querySelector('aside.auth-art')!;
    expect(art.textContent).toContain('Qualor');
    expect(art.textContent).toContain(
      'Open-source code quality for teams that host their own GitLab or GitHub.',
    );
    // The mark is decoration: the word next to it names the product.
    expect(art.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(main.querySelector('.auth-main #projected')?.textContent).toBe('Card');
    expect(art.classList.contains('offline')).toBe(false);
    // The illustration is its own element under the words (step 10 review), never behind them.
    const illustration = art.querySelector('.auth-illustration');
    expect(illustration?.getAttribute('aria-hidden')).toBe('true');
    expect(art.lastElementChild).toBe(illustration);
  });

  it('shows the offline illustration when asked', async () => {
    const fixture = TestBed.createComponent(Host);
    fixture.componentRef.setInput('art', 'offline');
    await fixture.whenStable();
    const art = (fixture.nativeElement as HTMLElement).querySelector('aside.auth-art');
    expect(art?.classList.contains('offline')).toBe(true);
  });
});
