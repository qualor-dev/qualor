import { readPom, type PomElement } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { addManagedDependency, replaceXmlText, xmlTextSpan } from './xml';

const SPRING = 'org.springframework:spring-core';

/** The text a span covers. */
function spanned(text: string, span: { start: number; end: number } | null): string | null {
  return span === null ? null : text.slice(span.start, span.end);
}

const childText = (el: PomElement, name: string) =>
  el.children.find((c) => c.name === name)?.text ?? null;
/** A `<dependency>` of `groupId:artifactId`, whatever order its children come in. */
const isDependency = (ga: string) => (el: PomElement) =>
  `${childText(el, 'groupId')}:${childText(el, 'artifactId')}` === ga;

const DEPENDENCY_VERSION = ['project', 'dependencies', 'dependency', 'version'];

const NESTED = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <properties>
    <java.version>17</java.version>
    <spring.version>5.2.20.RELEASE</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.example.fork</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.2.20.RELEASE</version>
    </dependency>
    <dependency>
      <version>5.2.20.RELEASE</version>
      <artifactId>spring-core</artifactId>
      <groupId>org.springframework</groupId>
    </dependency>
  </dependencies>
</project>
`;

describe('xmlTextSpan', () => {
  it('finds the text of a nested element, the parent picked by match whatever its child order', () => {
    const span = xmlTextSpan(NESTED, DEPENDENCY_VERSION, isDependency(SPRING));
    expect(spanned(NESTED, span)).toBe('5.2.20.RELEASE');
    // The second dependency's <version>, not the fork's.
    const second = NESTED.indexOf('<version>5.2.20.RELEASE</version>\n      <artifactId>');
    expect(span?.start).toBe(second + '<version>'.length);
  });

  it('without match, takes the first element at the path in document order', () => {
    const span = xmlTextSpan(NESTED, DEPENDENCY_VERSION);
    expect(span?.start).toBe(NESTED.indexOf('5.2.20.RELEASE</version>'));
    expect(spanned(NESTED, xmlTextSpan(NESTED, ['project', 'properties', 'spring.version']))).toBe(
      '5.2.20.RELEASE',
    );
  });

  it('is null when the path is missing, the root differs, no parent matches or the text is not XML', () => {
    expect(xmlTextSpan(NESTED, ['project', 'dependencyManagement', 'dependencies'])).toBeNull();
    expect(xmlTextSpan(NESTED, ['settings', 'properties', 'java.version'])).toBeNull();
    expect(xmlTextSpan(NESTED, DEPENDENCY_VERSION, isDependency('org.other:x'))).toBeNull();
    expect(xmlTextSpan('<project><version>1</project>', ['project', 'version'])).toBeNull();
  });

  it('skips self-closing elements on the way, and is null for a self-closing target', () => {
    const text =
      '<project><properties/><parent/><properties><a/><b>2</b><c x="1" /></properties></project>';
    expect(spanned(text, xmlTextSpan(text, ['project', 'properties', 'b']))).toBe('2');
    expect(xmlTextSpan(text, ['project', 'properties', 'a'])).toBeNull();
    expect(xmlTextSpan(text, ['project', 'properties', 'c'])).toBeNull();
  });

  it('covers a CDATA section and the text around it, trimmed; a comment or a child inside is null', () => {
    const cdata = '<project><version> <![CDATA[5.2.20]]> </version></project>';
    expect(spanned(cdata, xmlTextSpan(cdata, ['project', 'version']))).toBe('<![CDATA[5.2.20]]>');
    const commented = '<project><version><!-- pinned -->5.2.20</version></project>';
    expect(xmlTextSpan(commented, ['project', 'version'])).toBeNull();
    expect(xmlTextSpan(NESTED, ['project', 'properties'])).toBeNull();
  });

  it('gives positions in the text as given: a byte order mark, CRLF and astral characters before it', () => {
    const text =
      '﻿<?xml version="1.0"?>\r\n<project>\r\n  <!-- \u{1D11E} -->\r\n  <name>café \u{1D11E}</name>\r\n  <version>\r\n    1.0\r\n  </version >\r\n</project>\r\n';
    expect(spanned(text, xmlTextSpan(text, ['project', 'version']))).toBe('1.0');
    expect(spanned(text, xmlTextSpan(text, ['project', 'name']))).toBe('café \u{1D11E}');
  });

  it('an empty element has an empty span between its tags', () => {
    const text = '<project><version></version></project>';
    const span = xmlTextSpan(text, ['project', 'version']);
    expect(span).toEqual({ start: 18, end: 18 });
  });
});

describe('replaceXmlText', () => {
  it('replaces only the span, escaping the value', () => {
    const span = xmlTextSpan(NESTED, DEPENDENCY_VERSION, isDependency(SPRING));
    if (span === null) throw new Error('no span');
    const next = replaceXmlText(NESTED, span, '5.2.21');
    const lines = (t: string) => t.split('\n');
    const changed = lines(next).filter((line, i) => line !== lines(NESTED)[i]);
    expect(changed).toEqual(['      <version>5.2.21</version>']);
    expect(replaceXmlText('<a>x</a>', { start: 3, end: 4 }, '1 < 2 & 3 > 0')).toBe(
      '<a>1 &lt; 2 &amp; 3 &gt; 0</a>',
    );
  });

  it('replaces a CDATA section with the plain value', () => {
    const text = '<project><version><![CDATA[5.2.20]]></version></project>';
    const span = xmlTextSpan(text, ['project', 'version']);
    if (span === null) throw new Error('no span');
    expect(replaceXmlText(text, span, '5.2.21')).toBe(
      '<project><version>5.2.21</version></project>',
    );
  });
});

/** The managed `<dependency>` of org.springframework:spring-core 5.2.21 at `indent`, one unit in. */
const managed = (indent: string, unit: string, nl = '\n') =>
  [
    `${indent}<dependency>`,
    `${indent}${unit}<groupId>org.springframework</groupId>`,
    `${indent}${unit}<artifactId>spring-core</artifactId>`,
    `${indent}${unit}<version>5.2.21</version>`,
    `${indent}</dependency>`,
  ].join(nl);

/** The managed versions of the package in a pom, read back by Task 4's reader. */
function managedVersions(text: string): string[] {
  const project = readPom(text);
  return project.children
    .filter((c) => c.name === 'dependencyManagement')
    .flatMap((m) => m.children.filter((c) => c.name === 'dependencies'))
    .flatMap((list) => list.children.filter(isDependency(SPRING)))
    .map((d) => childText(d, 'version') ?? '');
}

describe('addManagedDependency', () => {
  it('creates <dependencyManagement> before <dependencies>, at its indentation', () => {
    const text = `<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-context</artifactId>
      <version>5.2.20.RELEASE</version>
    </dependency>
  </dependencies>
</project>
`;
    const next = addManagedDependency(text, SPRING, '5.2.21');
    expect(next).toBe(
      text.replace(
        '  <dependencies>\n',
        `  <dependencyManagement>\n    <dependencies>\n${managed('      ', '  ')}\n    </dependencies>\n  </dependencyManagement>\n  <dependencies>\n`,
      ),
    );
    expect(managedVersions(next)).toEqual(['5.2.21']);
  });

  it('keeps a byte order mark, CRLF line endings and a 4-space indent', () => {
    const text =
      '﻿<?xml version="1.0"?>\r\n<project>\r\n    <modelVersion>4.0.0</modelVersion>\r\n    <dependencies>\r\n        <dependency>\r\n            <groupId>org.springframework</groupId>\r\n            <artifactId>spring-context</artifactId>\r\n            <version>5.2.20.RELEASE</version>\r\n        </dependency>\r\n    </dependencies>\r\n</project>\r\n';
    const next = addManagedDependency(text, SPRING, '5.2.21');
    const block = [
      '    <dependencyManagement>',
      '        <dependencies>',
      managed('            ', '    ', '\r\n'),
      '        </dependencies>',
      '    </dependencyManagement>',
      '',
    ].join('\r\n');
    expect(next).toBe(text.replace('    <dependencies>\r\n', `${block}    <dependencies>\r\n`));
    expect(next.startsWith('﻿')).toBe(true);
    expect(next.replaceAll('\r\n', '')).not.toContain('\n');
  });

  it('extends an existing section after its last entry, with that entry’s indentation', () => {
    const text = `<project>
\t<dependencyManagement>
\t\t<dependencies>
\t\t\t<dependency>
\t\t\t\t<groupId>org.springframework</groupId>
\t\t\t\t<artifactId>spring-framework-bom</artifactId>
\t\t\t\t<version>5.2.20.RELEASE</version>
\t\t\t\t<type>pom</type>
\t\t\t\t<scope>import</scope>
\t\t\t</dependency> <!-- the BOM -->
\t\t</dependencies>
\t</dependencyManagement>
</project>
`;
    const next = addManagedDependency(text, SPRING, '5.2.21');
    expect(next).toBe(
      text.replace('<!-- the BOM -->\n', `<!-- the BOM -->\n${managed('\t\t\t', '\t')}\n`),
    );
    expect(managedVersions(next)).toEqual(['5.2.21']);
  });

  it('adds <dependencies> into a <dependencyManagement> without one', () => {
    const text = '<project>\n  <dependencyManagement>\n  </dependencyManagement>\n</project>\n';
    expect(addManagedDependency(text, SPRING, '5.2.21')).toBe(
      `<project>\n  <dependencyManagement>\n    <dependencies>\n${managed('      ', '  ')}\n    </dependencies>\n  </dependencyManagement>\n</project>\n`,
    );
  });

  it('fills a self-closing <dependencies/> of the section', () => {
    const text =
      '<project>\n  <dependencyManagement>\n    <dependencies/>\n  </dependencyManagement>\n</project>\n';
    const next = addManagedDependency(text, SPRING, '5.2.21');
    expect(next).toBe(
      `<project>\n  <dependencyManagement>\n    <dependencies>\n${managed('      ', '  ')}\n    </dependencies>\n  </dependencyManagement>\n</project>\n`,
    );
  });

  it('without <dependencies>, appends the section after the project’s last element', () => {
    const text =
      '<project>\n  <modelVersion>4.0.0</modelVersion>\n  <modules>\n    <module>core</module>\n  </modules>\n</project>';
    expect(addManagedDependency(text, SPRING, '5.2.21')).toBe(
      `<project>\n  <modelVersion>4.0.0</modelVersion>\n  <modules>\n    <module>core</module>\n  </modules>\n  <dependencyManagement>\n    <dependencies>\n${managed('      ', '  ')}\n    </dependencies>\n  </dependencyManagement>\n</project>`,
    );
  });

  it('T15j: escapes a hostile version, so it stays one text node and the pom stays one pom', () => {
    const text = ['<project>', '  <dependencies>', '  </dependencies>', '</project>', ''].join(
      '\n',
    );
    const hostile = '1</version><x/>&';
    const next = addManagedDependency(text, SPRING, hostile);
    expect(next).toContain('<version>1&lt;/version&gt;&lt;x/&gt;&amp;</version>');
    expect(next).not.toContain('<x/>');
    const span = xmlTextSpan(next, [
      'project',
      'dependencyManagement',
      'dependencies',
      'dependency',
      'version',
    ]);
    expect(span).not.toBeNull();
    expect(next.slice(span?.start, span?.end)).toBe('1&lt;/version&gt;&lt;x/&gt;&amp;');
  });

  it('throws for a text that is not a pom, or a name that is not groupId:artifactId', () => {
    expect(() => addManagedDependency('<settings/>', SPRING, '1')).toThrow();
    expect(() => addManagedDependency('<project>', SPRING, '1')).toThrow();
    expect(() => addManagedDependency('<project/>', 'spring-core', '1')).toThrow();
  });
});
