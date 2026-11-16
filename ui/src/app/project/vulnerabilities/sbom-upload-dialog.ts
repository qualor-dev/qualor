import {
  afterNextRender,
  Component,
  computed,
  inject,
  Injector,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import type { ElementRef } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { ApiError, problemMessage } from '../../api/errors';
import type { ResponseBody } from '../../api/types';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { inputValue } from '../../shared/forms';

type Answer = ResponseBody<'/api/v0/projects/sbom', 'put'>;

/** A file larger than this is not read for a label: the server reads it, the browser need not. */
const PREFILL_MAX_BYTES = 16 * 1024 * 1024;
/** The server's cap on a version label. */
const LABEL_MAX = 100;

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** The SPDX id of the package the document describes, as `documentDescribes` or a relationship. */
function describedId(doc: Record<string, unknown>): string | null {
  const listed = Array.isArray(doc['documentDescribes']) ? doc['documentDescribes'] : [];
  const first = text(listed[0]);
  if (first) return first;
  const relationships = Array.isArray(doc['relationships']) ? doc['relationships'] : [];
  for (const entry of relationships) {
    const r = record(entry);
    if (r?.['relationshipType'] === 'DESCRIBES' && r['spdxElementId'] === 'SPDXRef-DOCUMENT') {
      return text(r['relatedSpdxElement']);
    }
  }
  return null;
}

/**
 * The version of what an SBOM describes, the label the server would fall back to: CycloneDX
 * `metadata.component.version`, SPDX `versionInfo` of the described package. Null when the file
 * names none (or is not JSON).
 */
export function subjectVersion(value: unknown): string | null {
  const doc = record(value);
  if (!doc) return null;
  const cyclonedx = text(record(record(doc['metadata'])?.['component'])?.['version']);
  const found = cyclonedx ?? spdxVersion(doc);
  return found !== null && found.length <= LABEL_MAX ? found : null;
}

function spdxVersion(doc: Record<string, unknown>): string | null {
  const id = describedId(doc);
  if (!id || !Array.isArray(doc['packages'])) return null;
  const pkg = doc['packages'].map(record).find((p) => p?.['SPDXID'] === id);
  return text(pkg?.['versionInfo']);
}

function bytesStream(bytes: ArrayBuffer): ReadableStream<BufferSource> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

/**
 * The file as the browser's gzip makes it, in a Blob so that the request declares its length
 * (R10); null where the browser cannot compress, and the plain file goes.
 */
async function gzipped(file: File): Promise<Blob | null> {
  if (typeof CompressionStream === 'undefined') return null;
  try {
    // Streamed where the browser can, so that a large file is not held twice.
    const source: ReadableStream<BufferSource> =
      typeof file.stream === 'function' ? file.stream() : bytesStream(await file.arrayBuffer());
    return await new Response(source.pipeThrough(new CompressionStream('gzip'))).blob();
  } catch {
    return null;
  }
}

/**
 * Upload SBOM (0.16 SBOM, spec §6.9): a CycloneDX or SPDX JSON file becomes a version of the
 * project, with an optional label (prefilled from the file's subject version). The file is sent
 * gzipped when the browser can. The answer is shown as it came: packages, OS packages, what was
 * skipped, the warnings and whether monitoring checks the new version. Everything from the file
 * (subject, warnings, a problem's detail) is shown as text.
 */
@Component({
  selector: 'q-sbom-upload-dialog',
  imports: [RouterLink],
  templateUrl: './sbom-upload-dialog.html',
  styleUrl: './sbom-upload-dialog.css',
})
export class SbomUploadDialog {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  readonly projectKey = input.required<string>();
  /** The SBOM is stored: the page reads its summary again. */
  readonly uploaded = output<{ versionId: string; label: string }>();

  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly fileField = viewChild<ElementRef<HTMLInputElement>>('fileField');
  private readonly resultBox = viewChild<ElementRef<HTMLElement>>('resultBox');

  protected readonly file = signal<File | null>(null);
  protected readonly label = signal('');
  /** The label was typed: a file chosen later does not replace it. */
  private labelTouched = false;
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly proxyRefused = signal(false);
  protected readonly fileError = signal<string | null>(null);
  protected readonly result = signal<Answer | null>(null);

  protected readonly skippedTotal = computed(() => {
    const s = this.result()?.skipped;
    return s ? s.noPurl + s.unsupportedType + s.duplicate : 0;
  });

  /** Opens the dialog on an empty form. */
  open(): void {
    this.file.set(null);
    this.label.set('');
    this.labelTouched = false;
    this.error.set(null);
    this.proxyRefused.set(false);
    this.fileError.set(null);
    this.result.set(null);
    const field = this.fileField()?.nativeElement;
    if (field) field.value = '';
    openAfterRender(this.injector, () => this.dialog()?.nativeElement);
    afterNextRender(() => this.fileField()?.nativeElement.focus(), { injector: this.injector });
  }

  protected close(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected async chooseFile(event: Event): Promise<void> {
    const chosen = (event.target as HTMLInputElement).files?.[0] ?? null;
    this.file.set(chosen);
    this.error.set(null);
    this.proxyRefused.set(false);
    this.fileError.set(null);
    if (chosen === null || this.labelTouched) return;
    const found = await this.versionOf(chosen);
    // Another file was chosen, or the label typed, while this one was read.
    if (this.file() !== chosen || this.labelTouched) return;
    this.label.set(found ?? '');
  }

  protected setLabel(event: Event): void {
    this.labelTouched = true;
    this.label.set(inputValue(event));
  }

  private async versionOf(file: File): Promise<string | null> {
    if (file.size > PREFILL_MAX_BYTES || typeof file.text !== 'function') return null;
    try {
      return subjectVersion(JSON.parse(await file.text()));
    } catch {
      return null;
    }
  }

  protected async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const file = this.file();
    if (file === null) {
      this.fileError.set($localize`:@@sbom.upload.noFile:Choose an SBOM file.`);
      return;
    }
    const version = this.label().trim();
    this.busy.set(true);
    this.error.set(null);
    this.proxyRefused.set(false);
    try {
      const packed = await gzipped(file);
      const answer = await ok(
        this.api.client.PUT('/api/v0/projects/sbom', {
          params: {
            query: { projectKey: this.projectKey(), ...(version !== '' ? { version } : {}) },
          },
          body: (packed ?? file) as unknown as string,
          bodySerializer: (body) => body,
          headers: {
            'Content-Type': 'application/json',
            ...(packed ? { 'Content-Encoding': 'gzip' } : {}),
          },
        }),
      );
      this.result.set(answer);
      this.uploaded.emit({ versionId: answer.version.id, label: answer.version.label });
      afterNextRender(() => this.resultBox()?.nativeElement.focus(), { injector: this.injector });
    } catch (err) {
      if (err instanceof ApiError && err.status === 413 && err.code === null) {
        this.proxyRefused.set(true);
      } else {
        this.error.set(this.problem(err));
      }
    } finally {
      this.busy.set(false);
    }
  }

  /** The refusal in words; the file's own wording (a problem's detail) is shown as it came. */
  private problem(err: unknown): string {
    if (!(err instanceof ApiError)) return problemMessage(err);
    switch (err.code) {
      case 'SBOM_TOO_LARGE':
        return $localize`:@@sbom.upload.tooLarge:The SBOM is too large. Qualor takes at most 32 MiB as sent and 64 MiB unpacked.`;
      case 'UPLOADS_BUSY':
        return $localize`:@@sbom.upload.busy:The server is processing another upload. Try again in a moment.`;
      case 'VERSION_LABEL_TAKEN':
      case 'VERSION_LABEL_INVALID':
      case 'SBOM_INVALID':
      case 'SBOM_FORMAT_UNSUPPORTED':
      case 'SBOM_TOO_MANY_PACKAGES':
      case 'SBOM_MULTIPLE_OS':
        return err.problem?.detail ?? problemMessage(err);
      default:
        return problemMessage(err);
    }
  }
}
