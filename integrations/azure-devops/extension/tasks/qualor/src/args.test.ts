import { describe, expect, it } from 'vitest';
import { splitArguments } from './args';

describe('splitArguments', () => {
  it('gives no argument for an empty or blank input', () => {
    expect(splitArguments('')).toEqual([]);
    expect(splitArguments('   ')).toEqual([]);
    expect(splitArguments('\n\n')).toEqual([]);
  });

  it('splits one line on spaces', () => {
    expect(splitArguments('--no-wait --project-key acme/app')).toEqual([
      '--no-wait',
      '--project-key',
      'acme/app',
    ]);
  });

  it('keeps a double-quoted value as one argument', () => {
    expect(splitArguments('"a b"')).toEqual(['a b']);
    expect(splitArguments('--name "a b" -x')).toEqual(['--name', 'a b', '-x']);
    expect(splitArguments('"--project-key=a b"')).toEqual(['--project-key=a b']);
  });

  it('splits a YAML block (`arguments: |`) line by line', () => {
    expect(splitArguments('--no-wait\n--project-key acme/app\n')).toEqual([
      '--no-wait',
      '--project-key',
      'acme/app',
    ]);
    expect(splitArguments('--no-wait\r\n\r\n"--config=my config.yml"\r\n')).toEqual([
      '--no-wait',
      '--config=my config.yml',
    ]);
  });

  it('does not join a quote across lines', () => {
    expect(splitArguments('"a\nb"')).toEqual(['a', 'b']);
  });
});
