import { describe, expect, it } from 'vitest';
import { addJsonProperty, jsonLayout, setJsonString } from './json';

const FOUR = `{
    "name": "app",
    "dependencies": {
        "qf-a": "^1.2.5",
        "other": "1.0.0"
    }
}
`;

describe('jsonLayout', () => {
  it('reads the indent, the line ending, a byte order mark and the final newline', () => {
    expect(jsonLayout(FOUR)).toEqual({
      indent: '    ',
      newline: '\n',
      bom: false,
      finalNewline: true,
    });
    expect(jsonLayout('\uFEFF{\r\n\t"a": 1\r\n}')).toEqual({
      indent: '\t',
      newline: '\r\n',
      bom: true,
      finalNewline: false,
    });
    expect(jsonLayout('{}')).toEqual({
      indent: '  ',
      newline: '\n',
      bom: false,
      finalNewline: false,
    });
  });
});

describe('setJsonString', () => {
  it('replaces only the value span of a nested key', () => {
    const next = setJsonString(FOUR, ['dependencies', 'qf-a'], '^1.2.6');
    expect(next).toBe(FOUR.replace('"^1.2.5"', '"^1.2.6"'));
  });

  it('finds escaped keys by their value, and the last of duplicate keys as JSON.parse does', () => {
    const text =
      '{ "dependencies": { "q\\u0066-a": "^1.2.5" }, "a": { "x": "1" }, "a": { "x": "2" } }';
    expect(setJsonString(text, ['dependencies', 'qf-a'], '^1.2.6')).toBe(
      '{ "dependencies": { "q\\u0066-a": "^1.2.6" }, "a": { "x": "1" }, "a": { "x": "2" } }',
    );
    expect(setJsonString(text, ['a', 'x'], '3')).toBe(
      '{ "dependencies": { "q\\u0066-a": "^1.2.5" }, "a": { "x": "1" }, "a": { "x": "3" } }',
    );
  });

  it('writes the new value as a JSON string, escapes included', () => {
    expect(setJsonString('{"a":"b"}', ['a'], 'say "hi"\\')).toBe('{"a":"say \\"hi\\"\\\\"}');
  });

  it('keeps a byte order mark and CRLF line endings', () => {
    const text = '\uFEFF{\r\n  "dependencies": {\r\n    "qf-a": "~1.2.5"\r\n  }\r\n}\r\n';
    expect(setJsonString(text, ['dependencies', 'qf-a'], '~1.2.6')).toBe(
      text.replace('~1.2.5', '~1.2.6'),
    );
  });

  it('is null when the path is missing or crosses a value that is not an object', () => {
    expect(setJsonString(FOUR, ['devDependencies', 'qf-a'], '1')).toBeNull();
    expect(setJsonString(FOUR, ['name', 'x'], '1')).toBeNull();
    expect(setJsonString('[1, {"a": "b"}]', ['a'], '1')).toBeNull();
    expect(setJsonString('{ not json', ['a'], '1')).toBeNull();
  });
});

describe('addJsonProperty', () => {
  it('fills an empty root object, creating the missing objects', () => {
    expect(addJsonProperty('{}', ['overrides'], 'qf-a', '^1.2.6')).toBe(
      '{\n  "overrides": {\n    "qf-a": "^1.2.6"\n  }\n}',
    );
    expect(addJsonProperty('{ }\n', [], 'a', 'b')).toBe('{\n  "a": "b"\n}\n');
  });

  it('adds after the last member of an object at the end of the file, keeping its 4-space indent', () => {
    expect(addJsonProperty(FOUR, ['overrides'], 'qf-a', '^1.2.6')).toBe(`{
    "name": "app",
    "dependencies": {
        "qf-a": "^1.2.5",
        "other": "1.0.0"
    },
    "overrides": {
        "qf-a": "^1.2.6"
    }
}
`);
  });

  it('adds into an existing object and fills an empty nested one, with a 2-space layout', () => {
    const text = '{\n  "name": "app",\n  "pnpm": {\n    "overrides": {}\n  }\n}\n';
    const once = addJsonProperty(text, ['pnpm', 'overrides'], 'qf-a', '^1.2.6');
    expect(once).toBe(
      '{\n  "name": "app",\n  "pnpm": {\n    "overrides": {\n      "qf-a": "^1.2.6"\n    }\n  }\n}\n',
    );
    expect(addJsonProperty(once, ['pnpm', 'overrides'], 'qf-b@>=2.0.0 <3.0.0', '^2.0.3')).toBe(
      '{\n  "name": "app",\n  "pnpm": {\n    "overrides": {\n      "qf-a": "^1.2.6",\n      "qf-b@>=2.0.0 <3.0.0": "^2.0.3"\n    }\n  }\n}\n',
    );
  });

  it('follows a tab layout, CRLF line endings and a byte order mark', () => {
    const text = '\uFEFF{\r\n\t"name": "app"\r\n}\r\n';
    expect(addJsonProperty(text, ['resolutions'], 'qf-a', '^1.2.6')).toBe(
      '\uFEFF{\r\n\t"name": "app",\r\n\t"resolutions": {\r\n\t\t"qf-a": "^1.2.6"\r\n\t}\r\n}\r\n',
    );
  });

  it('adds inline to an object written on one line', () => {
    expect(addJsonProperty('{ "name": "app", "pnpm": { "x": 1 } }', ['pnpm'], 'y', 'z')).toBe(
      '{ "name": "app", "pnpm": { "x": 1, "y": "z" } }',
    );
  });

  it('throws when a path step is not an object, or the text is not JSON', () => {
    expect(() => addJsonProperty(FOUR, ['name'], 'x', 'y')).toThrow();
    expect(() => addJsonProperty('{ not json', [], 'x', 'y')).toThrow();
  });
});
