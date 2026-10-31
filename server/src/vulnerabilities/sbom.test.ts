import { describe, expect, it } from 'vitest';
import { buildSbom } from './sbom';

describe('buildSbom', () => {
  it('writes CycloneDX 1.6 with one component per distinct purl', () => {
    const json = buildSbom([
      { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' },
      { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' },
      { purl: 'pkg:npm/%40babel/traverse@7.0.0', name: '@babel/traverse', version: '7.0.0' },
      {
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        name: 'org.apache.logging.log4j:log4j-core',
        version: '2.14.1',
      },
    ]);
    const bom = JSON.parse(json);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.version).toBe(1);
    expect(bom.components).toEqual([
      {
        type: 'library',
        'bom-ref': 'pkg:npm/lodash@4.17.20',
        name: 'lodash',
        version: '4.17.20',
        purl: 'pkg:npm/lodash@4.17.20',
      },
      {
        type: 'library',
        'bom-ref': 'pkg:npm/%40babel/traverse@7.0.0',
        name: '@babel/traverse',
        version: '7.0.0',
        purl: 'pkg:npm/%40babel/traverse@7.0.0',
      },
      {
        type: 'library',
        'bom-ref': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        name: 'org.apache.logging.log4j:log4j-core',
        version: '2.14.1',
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      },
    ]);
  });

  it('is valid for an empty list', () => {
    expect(JSON.parse(buildSbom([])).components).toEqual([]);
  });
});
