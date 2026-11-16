import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FETCH } from '../../api/api';
import { SessionStore } from '../../auth/session';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../../testing/fake-server';
import { SbomUploadDialog } from './sbom-upload-dialog';

const PATH = '/api/v0/projects/sbom';

const ANSWER = {
  version: { id: '0190a6c2-0000-7000-8000-0000000000c9', label: '1.4.0', source: 'sbom' },
  format: 'CycloneDX 1.6',
  subject: 'ghcr.io/acme/shop:1.4.0',
  distribution: { family: 'debian', version: '12.15' },
  packages: 412,
  osPackages: 97,
  skipped: { noPurl: 3, unsupportedType: 2, duplicate: 5 },
  warnings: [
    { code: 'SBOM_PURL_UNPARSABLE', message: 'Not a purl: <img src=x onerror="alert(1)">' },
  ],
  monitoring: { enabled: true, recheckQueued: true },
};

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();

interface Sent {
  method: string;
  url: URL;
  headers: Headers;
  bytes: Uint8Array;
}

interface Stable {
  whenStable(): Promise<unknown>;
}

describe('SbomUploadDialog', () => {
  let server: FakeServer;
  let sent: Sent[];

  beforeEach(() => {
    server = new FakeServer();
    sent = [];
    const recording: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      sent.push({
        method: request.method,
        url: new URL(request.url),
        headers: request.headers,
        bytes: new Uint8Array(await request.clone().arrayBuffer()),
      });
      return server.fetch(request);
    };
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideFakeServer(server),
        { provide: FETCH, useValue: recording },
      ],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(SbomUploadDialog);
    fixture.componentRef.setInput('projectKey', 'acme/shop');
    const uploaded: { versionId: string; label: string }[] = [];
    fixture.componentInstance.uploaded.subscribe((u) => uploaded.push(u));
    await settle(fixture);
    fixture.componentInstance.open();
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement, uploaded };
  }

  async function choose(fixture: Stable, root: HTMLElement, body: string) {
    const input = root.querySelector<HTMLInputElement>('#sbom-file')!;
    const file = new File([body], 'bom.json', { type: 'application/json' });
    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    input.dispatchEvent(new Event('change'));
    await new Promise((r) => setTimeout(r, 20));
    await fixture.whenStable();
  }

  async function submit(fixture: Stable, root: HTMLElement) {
    root.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r, 50));
    await fixture.whenStable();
  }

  function setLabel(root: HTMLElement, value: string) {
    const label = root.querySelector<HTMLInputElement>('#sbom-label')!;
    label.value = value;
    label.dispatchEvent(new Event('input'));
  }

  const gunzip = async (bytes: Uint8Array) => {
    const source = new ReadableStream<BufferSource>({
      start(controller) {
        controller.enqueue(bytes as Uint8Array<ArrayBuffer>);
        controller.close();
      },
    });
    return new Response(source.pipeThrough(new DecompressionStream('gzip'))).text();
  };

  it('sends the file gzipped (a Blob, so its length is declared), the key and the label', async () => {
    server.on('PUT', PATH, { status: 201, body: ANSWER });
    const { fixture, root, uploaded } = await render();
    const body = JSON.stringify({ bomFormat: 'CycloneDX', components: [] });
    await choose(fixture, root, body);
    setLabel(root, ' 1.4.0 ');
    await submit(fixture, root);
    const request = sent.find((s) => s.method === 'PUT')!;
    expect(request.url.pathname).toBe(PATH);
    expect(request.url.searchParams.get('projectKey')).toBe('acme/shop');
    expect(request.url.searchParams.get('version')).toBe('1.4.0');
    expect(request.headers.get('content-type')).toBe('application/json');
    expect(request.headers.get('content-encoding')).toBe('gzip');
    expect(request.bytes[0]).toBe(0x1f);
    expect(request.bytes[1]).toBe(0x8b);
    expect(await gunzip(request.bytes)).toBe(body);
    expect(uploaded).toEqual([{ versionId: ANSWER.version.id, label: '1.4.0' }]);
  });

  it('sends the plain file without an encoding where CompressionStream is missing, and no version when blank', async () => {
    vi.stubGlobal('CompressionStream', undefined);
    try {
      server.on('PUT', PATH, { body: ANSWER });
      const { fixture, root } = await render();
      const body = '{"spdxVersion":"SPDX-2.3"}';
      await choose(fixture, root, body);
      await submit(fixture, root);
      const request = sent.find((s) => s.method === 'PUT')!;
      expect(request.headers.get('content-encoding')).toBeNull();
      expect(request.url.searchParams.has('version')).toBe(false);
      expect(new TextDecoder().decode(request.bytes)).toBe(body);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('shows the answer: packages, OS packages with the distribution, skipped, warnings, monitoring', async () => {
    server.on('PUT', PATH, { status: 201, body: ANSWER });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    const result = text(root.querySelector('.sbom-result'))!;
    expect(result).toContain('CycloneDX 1.6');
    expect(result).toContain('ghcr.io/acme/shop:1.4.0');
    expect(result).toContain('412 packages');
    expect(result).toContain('97 OS packages (debian 12.15)');
    expect(result).toContain('3 without a purl');
    expect(result).toContain('2 of an unsupported type');
    expect(result).toContain('5 duplicates');
    expect(result).toContain('Monitoring is on');
    // The warning is text, never markup.
    expect(root.querySelector('.sbom-result img')).toBeNull();
    expect(result).toContain('Not a purl: <img src=x onerror="alert(1)">');
  });

  it('says that monitoring is off', async () => {
    server.on('PUT', PATH, {
      body: { ...ANSWER, monitoring: { enabled: false, recheckQueued: false } },
    });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    expect(text(root.querySelector('.sbom-result'))).toContain('Monitoring is off');
  });

  it('shows the detail of a label a tag scan holds', async () => {
    server.on('PUT', PATH, {
      status: 409,
      body: {
        ...problem(409, 'VERSION_LABEL_TAKEN'),
        detail:
          'Version 1.4.0 comes from a tag scan. Use a project of its own, for example shop-image.',
      },
    });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    expect(text(root.querySelector('[role=alert]'))).toContain('for example shop-image');
    expect(root.querySelector('.sbom-result')).toBeNull();
  });

  it('shows the detail of an invalid SBOM, as text', async () => {
    server.on('PUT', PATH, {
      status: 422,
      body: {
        ...problem(422, 'SBOM_INVALID'),
        detail: 'components[3].<b>name</b> must be a string.',
      },
    });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    const alert = root.querySelector('[role=alert]');
    expect(text(alert)).toContain('components[3].<b>name</b> must be a string.');
    expect(alert?.querySelector('b')).toBeNull();
  });

  it('says that a proxy refused a 413 without a problem body', async () => {
    server.on('PUT', PATH, () => ({ status: 413 }));
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    expect(text(root.querySelector('[role=alert]'))).toContain(
      'The proxy in front of Qualor refused the file.',
    );
  });

  it('names the cap for SBOM_TOO_LARGE and asks to retry on UPLOADS_BUSY', async () => {
    server.on('PUT', PATH, { status: 413, body: problem(413, 'SBOM_TOO_LARGE') });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    expect(text(root.querySelector('[role=alert]'))).toContain('32 MiB');
    server.on('PUT', PATH, { status: 503, body: problem(503, 'UPLOADS_BUSY') });
    await submit(fixture, root);
    expect(text(root.querySelector('[role=alert]'))).toContain('another upload');
  });

  it("shows the server's reason for SBOM_TOO_LARGE: a 20 MiB flood is not over 32 MiB", async () => {
    const detail = 'The SBOM holds more than 6000000 JSON keys and values.';
    server.on('PUT', PATH, {
      status: 413,
      body: { ...problem(413, 'SBOM_TOO_LARGE'), detail },
    });
    const { fixture, root } = await render();
    await choose(fixture, root, '{}');
    setLabel(root, '1.4.0');
    await submit(fixture, root);
    const alert = text(root.querySelector('[role=alert]'));
    expect(alert).toContain(detail);
    expect(alert).not.toContain('32 MiB');
  });

  it('prefills the label from the SBOM subject version, without overwriting a typed one', async () => {
    const { fixture, root } = await render();
    await choose(fixture, root, JSON.stringify({ metadata: { component: { version: '2.0.0' } } }));
    expect(root.querySelector<HTMLInputElement>('#sbom-label')!.value).toBe('2.0.0');
    setLabel(root, 'mine');
    await choose(fixture, root, JSON.stringify({ metadata: { component: { version: '3.0.0' } } }));
    expect(root.querySelector<HTMLInputElement>('#sbom-label')!.value).toBe('mine');
  });

  it('prefills from the package an SPDX document describes', async () => {
    const { fixture, root } = await render();
    await choose(
      fixture,
      root,
      JSON.stringify({
        spdxVersion: 'SPDX-2.3',
        documentDescribes: ['SPDXRef-root'],
        packages: [{ SPDXID: 'SPDXRef-root', versionInfo: '9.1' }],
      }),
    );
    expect(root.querySelector<HTMLInputElement>('#sbom-label')!.value).toBe('9.1');
  });

  it('sends nothing without a file', async () => {
    const { fixture, root } = await render();
    await submit(fixture, root);
    expect(sent.filter((s) => s.method === 'PUT')).toHaveLength(0);
  });
});
