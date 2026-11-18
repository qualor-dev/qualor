import { describe, expect, it } from 'vitest';
import { checkPom, pomDependencyVersion, readPom } from './maven';
import type { FixCheckContext, FixFileChange } from './types';

const GA = 'org.springframework:spring-core';

const ctx = (lockfile = 'pom.xml'): FixCheckContext => ({
  family: 'maven',
  packageName: GA,
  targets: [{ installed: '5.2.20.RELEASE', target: '5.2.21', lockfile }],
});

function check(base: string, next: string, path = 'pom.xml') {
  return checkPom({ path, base, next } satisfies FixFileChange, ctx(path));
}

const POM = ({
  version = '5.2.20.RELEASE',
  properties = '',
  managed = '',
  extra = '',
  build = '',
} = {}) => `<?xml version="1.0" encoding="UTF-8"?>
<!-- The app. -->
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <java.version>17</java.version>${properties}
  </properties>
${managed}  <dependencies>
    <!-- Spring -->
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${version}</version>
    </dependency>
    <dependency>
      <groupId>com.other</groupId>
      <artifactId>spring-core</artifactId>
      <version>1.0.0</version>
    </dependency>${extra}
  </dependencies>
${build}</project>
`;

const BASE = POM();

/** The pom whose dependency reads `${spring.version}`, the property set to `v`. */
const viaProperty = (v: string) =>
  POM({
    version: '${spring.version}',
    properties: `\n    <spring.version>${v}</spring.version>`,
  });

describe('readPom', () => {
  it('reads elements, trimmed text and attributes; drops comments and processing instructions', () => {
    const pom = readPom(
      '<?xml version="1.0"?>\n<project a="1"><!-- c --><?pi x?>\n  <version> 1.<!-- x -->0 </version>\n  <e><![CDATA[ <raw> ]]></e>\n</project>',
    );
    expect(pom).toEqual({
      name: 'project',
      text: '',
      attributes: { a: '1' },
      children: [
        { name: 'version', text: '1.0', attributes: {}, children: [] },
        { name: 'e', text: '<raw>', attributes: {}, children: [] },
      ],
    });
  });

  it('reads the predefined entities and character references', () => {
    expect(readPom('<p><v>a&amp;b&#x41;</v></p>').children[0]?.text).toBe('a&bA');
  });

  it.each([
    ['a DOCTYPE', '<!DOCTYPE project [<!ENTITY v "6.6.6">]><project><v>&v;</v></project>'],
    ['an undefined entity', '<project><v>&v;</v></project>'],
    ['an external entity', '<!DOCTYPE p SYSTEM "file:///etc/passwd"><p/>'],
    ['two roots', '<a/><b/>'],
    ['text outside the root', '<a/>x'],
    ['a mismatched tag', '<a><b></a>'],
    ['no root', '<!-- c -->'],
  ])('throws on %s', (_name, text) => {
    expect(() => readPom(text)).toThrow();
  });

  it('reads a BOM and CRLF line endings', () => {
    const crlf = '\uFEFF' + BASE.replaceAll('\n', '\r\n');
    expect(readPom(crlf)).toEqual(readPom(BASE));
  });
});

describe('pomDependencyVersion', () => {
  it('finds the literal version by group and artifact', () => {
    expect(pomDependencyVersion(readPom(BASE), GA)).toEqual({
      version: '5.2.20.RELEASE',
      property: null,
      section: 'dependencies',
    });
    expect(pomDependencyVersion(readPom(BASE), 'com.other:spring-core')).toMatchObject({
      version: '1.0.0',
    });
    expect(pomDependencyVersion(readPom(BASE), 'org.springframework:spring-web')).toBeNull();
    expect(pomDependencyVersion(readPom(BASE), 'spring-core')).toBeNull();
  });

  it('resolves a property of the pom, and names a property defined elsewhere', () => {
    expect(pomDependencyVersion(readPom(viaProperty('5.2.20.RELEASE')), GA)).toEqual({
      version: '5.2.20.RELEASE',
      property: 'spring.version',
      section: 'dependencies',
    });
    expect(pomDependencyVersion(readPom(POM({ version: '${parent.v}' })), GA)).toEqual({
      version: null,
      property: 'parent.v',
      section: 'dependencies',
    });
  });

  it('finds a managed version, and a dependency without one', () => {
    const managed = POM({
      managed: `  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.2.21</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
`,
    }).replace('      <version>5.2.20.RELEASE</version>\n', '');
    expect(pomDependencyVersion(readPom(managed), GA)).toEqual({
      version: '5.2.21',
      property: null,
      section: 'dependencyManagement',
    });
    const unmanaged = BASE.replace('      <version>5.2.20.RELEASE</version>\n', '');
    expect(pomDependencyVersion(readPom(unmanaged), GA)).toEqual({
      version: null,
      property: null,
      section: 'dependencies',
    });
  });
});

const MANAGED = (version: string, extra = '') => `  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${version}</version>${extra}
      </dependency>
    </dependencies>
  </dependencyManagement>
`;

describe('checkPom', () => {
  it('accepts a direct literal 5.2.20.RELEASE → 5.2.21 (§11.4)', () => {
    expect(check(BASE, POM({ version: '5.2.21' }))).toEqual({ ok: true });
  });

  it('accepts the change through ${spring.version}', () => {
    expect(check(viaProperty('5.2.20.RELEASE'), viaProperty('5.2.21'))).toEqual({ ok: true });
    expect(check(viaProperty('5.2.20.RELEASE'), viaProperty('5.2.20.RELEASE'))).toMatchObject({
      rule: 'below_target',
    });
  });

  it('accepts an added dependencyManagement entry in a pom with comments, created when absent', () => {
    expect(check(BASE, POM({ version: '5.2.21', managed: MANAGED('5.2.21') }))).toEqual({
      ok: true,
    });
    const transitive = BASE.replace(
      /<dependency>\s*<groupId>org\.springframework<\/groupId>[\s\S]*?<\/dependency>/,
      '<dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>2.0</version></dependency>',
    );
    const withManaged = transitive.replace(
      '  <dependencies>',
      `${MANAGED('5.2.21')}  <dependencies>`,
    );
    expect(check(transitive, withManaged)).toEqual({ ok: true });
    const withScope = transitive.replace(
      '  <dependencies>',
      `${MANAGED('5.2.21', '\n        <scope>runtime</scope>')}  <dependencies>`,
    );
    expect(check(transitive, withScope)).toEqual({ ok: true });
  });

  it('accepts an entry added to an existing dependencyManagement section', () => {
    const other = `  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.example</groupId>
        <artifactId>bom</artifactId>
        <version>1.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
`;
    const added = other.replace(
      '    </dependencies>',
      '      <dependency>\n        <groupId>org.springframework</groupId>\n        <artifactId>spring-core</artifactId>\n        <version>5.2.21</version>\n      </dependency>\n    </dependencies>',
    );
    expect(check(POM({ managed: other }), POM({ version: '5.2.21', managed: added }))).toEqual({
      ok: true,
    });
  });

  it('accepts a changed managed version', () => {
    const base = POM({ managed: MANAGED('5.2.20.RELEASE') });
    expect(check(base, POM({ version: '5.2.21', managed: MANAGED('5.2.21') }))).toEqual({
      ok: true,
    });
  });

  it('keeps CRLF and a BOM readable (Review Focus 1)', () => {
    const base = '\uFEFF' + BASE.replaceAll('\n', '\r\n');
    const next = '\uFEFF' + POM({ version: '5.2.21' }).replaceAll('\n', '\r\n');
    expect(check(base, next)).toEqual({ ok: true });
  });

  describe('smuggling (§11.8)', () => {
    it.each([
      [
        'an added <plugin>',
        POM({
          version: '5.2.21',
          build:
            '  <build>\n    <plugins>\n      <plugin>\n        <groupId>org.evil</groupId>\n        <artifactId>evil-maven-plugin</artifactId>\n        <version>1.0</version>\n      </plugin>\n    </plugins>\n  </build>\n',
        }),
      ],
      [
        'an added <repository>',
        POM({
          version: '5.2.21',
          build:
            '  <repositories>\n    <repository>\n      <id>evil</id>\n      <url>https://evil.example/maven</url>\n    </repository>\n  </repositories>\n',
        }),
      ],
      [
        'an added <pluginRepository>',
        POM({
          version: '5.2.21',
          build:
            '  <pluginRepositories>\n    <pluginRepository>\n      <id>evil</id>\n      <url>https://evil.example/maven</url>\n    </pluginRepository>\n  </pluginRepositories>\n',
        }),
      ],
      [
        'an added <parent>',
        POM({ version: '5.2.21', build: '  <parent><groupId>e</groupId></parent>\n' }),
      ],
      [
        'an added <profiles>',
        POM({ version: '5.2.21', build: '  <profiles><profile/></profiles>\n' }),
      ],
      [
        'an added <modules>',
        POM({ version: '5.2.21', build: '  <modules><module>x</module></modules>\n' }),
      ],
      [
        'an added <extensions>',
        POM({
          version: '5.2.21',
          build: '  <build><extensions><extension/></extensions></build>\n',
        }),
      ],
      [
        'another dependency',
        POM({
          version: '5.2.21',
          extra:
            '\n    <dependency>\n      <groupId>org.evil</groupId>\n      <artifactId>evil</artifactId>\n      <version>1.0</version>\n    </dependency>',
        }),
      ],
      ['a changed property it does not reference', POM({ version: '5.2.21' }).replace('17', '21')],
      [
        'an exclusion on the package',
        POM({ version: '5.2.21' }).replace(
          '<version>5.2.21</version>',
          '<version>5.2.21</version><exclusions><exclusion/></exclusions>',
        ),
      ],
      [
        'a changed scope on the package',
        POM({ version: '5.2.21' }).replace(
          '<version>5.2.21</version>',
          '<version>5.2.21</version><scope>system</scope>',
        ),
      ],
      [
        'an attribute on an element',
        POM({ version: '5.2.21' }).replace(
          '<dependencies>',
          '<dependencies combine.self="override">',
        ),
      ],
    ])('refuses %s as other_change', (_name, next) => {
      expect(check(BASE, next)).toEqual({ ok: false, rule: 'other_change', path: 'pom.xml' });
    });

    it.each([
      ['a <type>', '\n        <type>pom</type>'],
      ['an import scope', '\n        <scope>import</scope>'],
      ['a system scope', '\n        <scope>system</scope>'],
      ['an <exclusions>', '\n        <exclusions/>'],
    ])('refuses an added managed entry with %s as other_change', (_name, extra) => {
      const next = POM({ version: '5.2.21', managed: MANAGED('5.2.21', extra) });
      expect(check(BASE, next)).toMatchObject({ rule: 'other_change' });
    });

    it('refuses a second added managed entry, and one for another artifact', () => {
      const two = MANAGED('5.2.21').replace(
        '    </dependencies>',
        '      <dependency>\n        <groupId>org.springframework</groupId>\n        <artifactId>spring-core</artifactId>\n        <version>5.2.22</version>\n      </dependency>\n    </dependencies>',
      );
      expect(check(BASE, POM({ version: '5.2.21', managed: two }))).toMatchObject({
        rule: 'other_change',
      });
      const other = MANAGED('5.2.21').replace('<artifactId>spring-core', '<artifactId>spring-web');
      expect(check(BASE, POM({ version: '5.2.21', managed: other }))).toMatchObject({
        rule: 'other_change',
      });
    });
  });

  it.each([
    '[5.2,)',
    '(5.2,6.0]',
    'LATEST',
    'RELEASE',
    'latest',
    '${evil}',
    '',
    '5.2.21 x',
    '5.2.21/../../evil',
    '5.2.21:x',
    '5.2.21?x',
    '5.2.21*',
  ])('refuses the version %j as bad_spec', (version) => {
    expect(check(BASE, POM({ version }))).toEqual({
      ok: false,
      rule: 'bad_spec',
      path: 'pom.xml',
    });
    expect(check(BASE, POM({ managed: MANAGED(version) }))).toMatchObject({ rule: 'bad_spec' });
  });

  it('refuses a range or a property in the referenced property as bad_spec', () => {
    expect(check(viaProperty('5.2.20.RELEASE'), viaProperty('[5.2,)'))).toMatchObject({
      rule: 'bad_spec',
    });
    expect(check(viaProperty('5.2.20.RELEASE'), viaProperty('${other}'))).toMatchObject({
      rule: 'bad_spec',
    });
  });

  it('matches group:artifact by both elements, not by artifactId alone (Review Focus 3)', () => {
    const wrong = BASE.replace(
      '<groupId>com.other</groupId>\n      <artifactId>spring-core</artifactId>\n      <version>1.0.0</version>',
      '<groupId>com.other</groupId>\n      <artifactId>spring-core</artifactId>\n      <version>5.2.21</version>',
    );
    expect(wrong).not.toBe(BASE);
    expect(check(BASE, wrong)).toEqual({ ok: false, rule: 'other_change', path: 'pom.xml' });
    expect(check(BASE, POM({ version: '5.2.21' }))).toEqual({ ok: true });
  });

  it('refuses a version still below the target as below_target', () => {
    expect(check(BASE, BASE)).toEqual({ ok: false, rule: 'below_target', path: 'pom.xml' });
    expect(check(BASE, POM({ version: '5.2.20' }))).toMatchObject({ rule: 'below_target' });
    // A managed entry does not lift a direct version declared in the same pom.
    expect(check(BASE, POM({ managed: MANAGED('5.2.21') }))).toMatchObject({
      rule: 'below_target',
    });
    expect(check(BASE, POM({ version: '5.3.0' }))).toEqual({ ok: true });
  });

  it('applies only the targets of this pom (Ruling F14)', () => {
    const other = checkPom({ path: 'core/pom.xml', base: BASE, next: BASE }, ctx('pom.xml'));
    expect(other).toEqual({ ok: true });
  });

  it('answers unparsable, without throwing, for a pom it cannot read', () => {
    for (const next of ['<project>', '<!DOCTYPE p><project/>', '<other/>', '']) {
      expect(check(BASE, next)).toEqual({ ok: false, rule: 'unparsable', path: 'pom.xml' });
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 1 (task-4-fix-1.md): I1 Java's trim, M2 snapshots, M3 the XML declaration

describe('fix round 1: Java trim, snapshot versions and the XML declaration (I1, M2, M3)', () => {
  const NBSP = String.fromCharCode(0xa0);
  const EMSP = String.fromCharCode(0x2003);
  const refused = (rule: string) => ({ ok: false, rule, path: 'pom.xml' });
  const other = (optional: string, exclusion = 'log4j-core') => `
    <dependency>
      <groupId>x</groupId>
      <artifactId>y</artifactId>
      <version>1.0</version>
      <optional>${optional}</optional>
      <exclusions><exclusion><groupId>org.apache.logging.log4j</groupId><artifactId>${exclusion}</artifactId></exclusion></exclusions>
    </dependency>`;
  const plugin = (skip: string) =>
    `  <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><version>3.1.0</version><configuration><skip>${skip}</skip></configuration></plugin></plugins></build>\n`;
  const BASE_EXTRA = POM({ extra: other('true'), build: plugin('true') });
  const at = (optional: string, skip = 'true', exclusion = 'log4j-core') =>
    POM({ version: '5.2.21', extra: other(optional, exclusion), build: plugin(skip) });

  it('accepts the bump next to these elements, and white space Java trims', () => {
    expect(check(BASE_EXTRA, at('true'))).toEqual({ ok: true });
    expect(check(BASE_EXTRA, at('\n        true\t', ' true '))).toEqual({ ok: true });
  });

  it.each([
    ['NBSP before true in <optional> (P2)', at(`${NBSP}true`)],
    ['&#160; before true in <optional>', at('&#160;true')],
    ['EM SPACE before true in a plugin <skip> (P2)', at('true', `${EMSP}true`)],
    ['NBSP before the excluded artifactId', at('true', 'true', `${NBSP}log4j-core`)],
  ])('refuses %s as other_change: Maven reads another value', (_name, next) => {
    expect(check(BASE_EXTRA, next)).toEqual(refused('other_change'));
  });

  it('refuses a version with NBSP around it as bad_spec (P2b)', () => {
    expect(check(BASE, POM({ version: `${NBSP}5.2.21${NBSP}` }))).toEqual(refused('bad_spec'));
  });

  it.each([
    ['another version and encoding (P2c)', '<?xml version="1.1" encoding="ISO-8859-1"?>'],
    ['another encoding', '<?xml version="1.0" encoding="ISO-8859-1"?>'],
    ['an added standalone', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'],
    ['no declaration', ''],
  ])('refuses a changed XML declaration (%s) as other_change (M3)', (_name, declaration) => {
    const next = POM({ version: '5.2.21' }).replace(
      '<?xml version="1.0" encoding="UTF-8"?>',
      declaration,
    );
    expect(next).not.toBe(POM({ version: '5.2.21' }));
    expect(check(BASE, next)).toEqual(refused('other_change'));
  });

  it.each(['5.2.22-SNAPSHOT', '5.2.22-snapshot', '5.2.22-20240101.123456-1'])(
    'refuses the snapshot version %s as bad_spec (M2, P2d)',
    (version) => {
      expect(check(BASE, POM({ version }))).toEqual(refused('bad_spec'));
      expect(check(BASE, POM({ managed: MANAGED(version) }))).toMatchObject({ rule: 'bad_spec' });
      expect(check(viaProperty('5.2.20.RELEASE'), viaProperty(version))).toMatchObject({
        rule: 'bad_spec',
      });
    },
  );

  it('accepts a snapshot version the base has, unchanged, on another dependency', () => {
    const snapshot = (v: string) =>
      POM({
        version: v,
        extra:
          '\n    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1.0-SNAPSHOT</version></dependency>',
      });
    expect(check(snapshot('5.2.20.RELEASE'), snapshot('5.2.21'))).toEqual({ ok: true });
  });
});
