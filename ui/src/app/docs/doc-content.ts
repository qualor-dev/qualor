import { NgTemplateOutlet } from '@angular/common';
import { Component, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { DocBlock } from './markdown';

/**
 * A guide page's body (`DocBlock`s from markdown.ts), rendered by recursive templates: every text
 * is interpolated, never inserted as HTML. Code blocks get a Copy button, and the guide's
 * ```` ```prompt ```` blocks a labelled "Copy prompt" one, as on qualor.dev.
 */
@Component({
  selector: 'q-doc-content',
  imports: [NgTemplateOutlet, RouterLink],
  templateUrl: './doc-content.html',
  styleUrl: './doc-content.css',
  host: { class: 'doc-content' },
})
export class DocContent {
  readonly blocks = input.required<readonly DocBlock[]>();
  /** The code block whose text was copied last, and how that went. */
  protected readonly copied = signal<{ block: DocBlock; ok: boolean } | null>(null);

  protected async copy(block: DocBlock): Promise<void> {
    if (block.kind !== 'code') return;
    try {
      await navigator.clipboard.writeText(block.text.replace(/\n$/, ''));
      this.copied.set({ block, ok: true });
    } catch {
      // No Clipboard API (an insecure context) or permission refused: the text stays selectable.
      this.copied.set({ block, ok: false });
    }
  }
}
