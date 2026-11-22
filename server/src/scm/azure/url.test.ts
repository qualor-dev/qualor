import { describe, expect, it } from 'vitest';
import {
  AZURE_REPOSITORY_ID,
  azureBaseUrlProblem,
  azureDeployment,
  azurePullRequestWebUrl,
  azureWebBase,
} from './url.js';

const SERVICES_HINT = 'Use https://dev.azure.com/<organization>';
const SERVER_HINT = 'Use the collection URL, e.g. https://ado.example.com/DefaultCollection';

describe('azureBaseUrlProblem', () => {
  it.each([
    'https://dev.azure.com/acme',
    'https://dev.azure.com/a',
    'https://dev.azure.com/a-b',
    `https://dev.azure.com/${'a'.repeat(50)}`,
    'https://acme.visualstudio.com',
    'https://ado.example.com/DefaultCollection',
    'https://ado.example.com/tfs/DefaultCollection',
    'https://ado.example.com:8443/tfs/DefaultCollection',
  ])('accepts %s', (url) => {
    expect(azureBaseUrlProblem(url)).toBeNull();
  });

  it.each([
    'https://dev.azure.com',
    'https://dev.azure.com/acme/project',
    'https://dev.azure.com/-acme',
    'https://dev.azure.com/acme-',
    `https://dev.azure.com/${'a'.repeat(51)}`,
    'https://dev.azure.com/ac_me',
    'https://dev.azure.com/acme?x=1',
    'http://dev.azure.com/acme',
    'https://dev.azure.com:8443/acme',
    'https://acme.visualstudio.com/DefaultCollection',
    'https://acme.visualstudio.com/acme',
    'http://acme.visualstudio.com',
    'https://.visualstudio.com',
    'https://a.b.visualstudio.com',
    'https://dev.azure.com//acme',
    'https://dev.azure.com/acme//x',
  ])('refuses %s with the Services hint', (url) => {
    expect(azureBaseUrlProblem(url)).toBe(SERVICES_HINT);
  });

  it.each([
    'https://ado.example.com',
    'https://ado.example.com:8443',
    'https://ado.example.com/tfs//Coll',
    'https://ado.example.com//Coll',
  ])('refuses %s with the Server hint', (url) => {
    expect(azureBaseUrlProblem(url)).toBe(SERVER_HINT);
  });

  it('compares hosts case-insensitively', () => {
    expect(azureBaseUrlProblem('https://DEV.AZURE.COM/acme')).toBeNull();
    expect(azureBaseUrlProblem('https://DEV.AZURE.COM')).toBe(SERVICES_HINT);
  });
});

describe('azureDeployment', () => {
  it.each([
    ['https://dev.azure.com/acme', 'services'],
    ['https://acme.visualstudio.com', 'services'],
    ['https://ACME.VisualStudio.com', 'services'],
    ['https://ado.example.com/DefaultCollection', 'server'],
    ['https://ado.example.com/tfs/DefaultCollection', 'server'],
    ['https://notvisualstudio.com/x', 'server'],
    ['https://dev.azure.com.evil.example/acme', 'server'],
    ['https://evil-visualstudio.com/x', 'server'],
    ['https://xvisualstudio.com/x', 'server'],
    ['https://dev.azure.com./acme', 'server'],
  ])('%s is %s', (url, kind) => {
    expect(azureDeployment(url)).toBe(kind);
  });
});

describe('AZURE_REPOSITORY_ID', () => {
  it('accepts a GUID in either case', () => {
    expect(AZURE_REPOSITORY_ID.test('0f8fad5b-d9cb-469f-a165-70867728950e')).toBe(true);
    expect(AZURE_REPOSITORY_ID.test('0F8FAD5B-D9CB-469F-A165-70867728950E')).toBe(true);
  });

  it.each([
    '',
    'my-repo',
    '0f8fad5bd9cb469fa16570867728950e',
    '0f8fad5b-d9cb-469f-a165-70867728950g',
    ' 0f8fad5b-d9cb-469f-a165-70867728950e',
  ])('refuses %j', (id) => {
    expect(AZURE_REPOSITORY_ID.test(id)).toBe(false);
  });
});

describe('web URLs', () => {
  it('uses the base URL as the web base', () => {
    expect(azureWebBase('https://dev.azure.com/acme')).toBe('https://dev.azure.com/acme');
  });

  it('builds a pull request URL from the repository web URL', () => {
    expect(azurePullRequestWebUrl('https://dev.azure.com/acme/p/_git/r', 42)).toBe(
      'https://dev.azure.com/acme/p/_git/r/pullrequest/42',
    );
  });
});
