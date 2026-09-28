import { Pipe, type PipeTransform } from '@angular/core';
import { label, type LabelKind } from './labels';

/** `{{ issue.severity | label: 'severity' }}` → "High". */
@Pipe({ name: 'label' })
export class LabelPipe implements PipeTransform {
  transform(value: string | null | undefined, kind: LabelKind): string {
    return label(kind, value);
  }
}
