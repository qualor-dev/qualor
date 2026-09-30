import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { UnavailablePage } from './unavailable.page';

describe('UnavailablePage (spec §7.9)', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [UnavailablePage],
      providers: [provideRouter([{ path: '**', children: [] }])],
    });
  });

  it('says the server cannot be reached beside the offline art, and Try again reopens the page', async () => {
    const fixture = TestBed.createComponent(UnavailablePage);
    fixture.componentRef.setInput('returnUrl', '/gates');
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const art = el.querySelector('q-auth-layout aside.auth-art');
    expect(art?.classList.contains('offline')).toBe(true);
    expect(el.querySelector('.auth-card h1')?.textContent).toContain('Qualor is not available');
    expect(el.querySelector('[role="alert"]')?.textContent).toContain(
      'The server could not be reached.',
    );
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    el.querySelector<HTMLButtonElement>('.auth-card button')!.click();
    expect(navigate).toHaveBeenCalledWith('/gates');
  });
});
