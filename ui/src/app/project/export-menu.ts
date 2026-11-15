import { Component, computed, type ElementRef, input, signal, viewChild } from '@angular/core';
import { inputValue } from '../shared/forms';
import { closePopover } from '../shared/popover';

/** The two exports: the dependency list (SBOM) and the vulnerability decisions (VEX). */
export type ExportKind = 'sbom' | 'vex';

/** A target the server exports: `value` is `<kind>:<id>`, `name` the branch name or version label. */
export interface ExportOption {
  value: string;
  kind: 'branch' | 'version';
  name: string;
}

/**
 * Export SBOM or Export VEX (the sbom feature): a button that opens a native popover with a
 * target and its formats, each a download link of `GET /projects/sbom|vex`. With `selectable`
 * false there is no Target select: the links are the first option's. The popover sits in the top
 * layer and does not follow a scroll, so a scroll or a resize closes it.
 */
@Component({
  selector: 'q-export-menu',
  templateUrl: './export-menu.html',
  styleUrl: './export-menu.css',
  host: {
    '(window:scroll)': 'close()',
    '(window:resize)': 'close()',
  },
})
export class ExportMenu {
  readonly kind = input.required<ExportKind>();
  /** The popover's id, for the button's `popovertarget`. */
  readonly menuId = input.required<string>();
  readonly projectKey = input.required<string>();
  readonly options = input.required<readonly ExportOption[]>();
  /** The option to start on when it is offered, else the first. */
  readonly preferred = input<string | null>(null);
  /** Whether the menu shows the Target select. */
  readonly selectable = input(true);

  private readonly menu = viewChild<ElementRef<HTMLElement>>('menu');
  private readonly picked = signal<string | null>(null);

  protected readonly label = computed(() =>
    this.kind() === 'sbom'
      ? $localize`:@@vuln.export.sbom:Export SBOM`
      : $localize`:@@vuln.export.vex:Export VEX`,
  );

  /** The chosen target; else the preferred one when it is offered, else the first. */
  protected readonly selected = computed(() => {
    const options = this.options();
    const wanted = [this.picked(), this.preferred()];
    return wanted.find((w) => options.some((o) => o.value === w)) ?? options[0]?.value ?? '';
  });

  protected readonly links = computed<{ label: string; href: string }[]>(() => {
    const kind = this.kind();
    const option = this.options().find((o) => o.value === this.selected());
    const key = this.projectKey();
    if (!option || !key) return [];
    const enc = encodeURIComponent;
    const base = `/api/v0/projects/${kind}?projectKey=${enc(key)}&${option.kind === 'branch' ? 'branch' : 'version'}=${enc(option.name)}`;
    const formats =
      kind === 'sbom'
        ? [
            {
              format: 'cyclonedx',
              label: $localize`:@@vuln.export.cyclonedx:CycloneDX 1.6 (JSON)`,
            },
            { format: 'spdx', label: $localize`:@@vuln.export.spdx:SPDX 2.3 (JSON)` },
          ]
        : [
            { format: 'cyclonedx', label: $localize`:@@vuln.export.cyclonedxVex:CycloneDX VEX` },
            { format: 'openvex', label: $localize`:@@vuln.export.openvex:OpenVEX` },
          ];
    return formats.map((f) => ({ label: f.label, href: `${base}&format=${f.format}` }));
  });

  protected pick(event: Event): void {
    this.picked.set(inputValue(event));
  }

  /** The popover goes to the top layer: place it under the button, at its right edge. */
  protected place(button: HTMLElement, menu: HTMLElement): void {
    const rect = button.getBoundingClientRect();
    menu.style.top = `${Math.round(rect.bottom + 4)}px`;
    menu.style.right = `${Math.max(0, Math.round(document.documentElement.clientWidth - rect.right))}px`;
  }

  /** Closes the popover; jsdom has no Popover API. */
  protected close(): void {
    const menu = this.menu()?.nativeElement;
    if (menu) closePopover(menu);
  }
}
