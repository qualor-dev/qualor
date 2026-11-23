import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/** Every `FROM` of a Dockerfile: an exact version tag and a digest (plan 1G ruling D1). */
function baseImages(dockerfile: string): string[] {
  return [...readFileSync(dockerfile, 'utf8').matchAll(/^FROM (\S+)/gm)].map((m) => m[1] ?? '');
}

/**
 * The modules a build module of tools/analyzers/go-tools requires (direct or indirect), after
 * checking that go.sum holds both hashes of each (ruling G9-6).
 */
function hashPinnedModules(name: string): string[] {
  const goMod = readFileSync(`tools/analyzers/go-tools/${name}/go.mod`, 'utf8');
  const goSum = readFileSync(`tools/analyzers/go-tools/${name}/go.sum`, 'utf8');
  const required = [
    ...goMod.matchAll(/^\s*(?:require\s+)?([^\s()]+) (v\d\S*)(?:\s+\/\/ indirect)?\s*$/gm),
  ].map((r) => [r[1] as string, r[2] as string] as const);
  for (const [p, v] of required) {
    expect(goSum, `${name}: ${p} ${v}`).toContain(`${p} ${v} h1:`);
    expect(goSum, `${name}: ${p} ${v}/go.mod`).toContain(`${p} ${v}/go.mod h1:`);
  }
  return required.map(([p, v]) => `${p} ${v}`);
}

describe('image definitions (plan 1G)', () => {
  it('builds qualor/server from pinned bases and runs it as a non-root user', () => {
    const file = 'deploy/server/Dockerfile';
    const images = baseImages(file);
    expect(images.length).toBeGreaterThan(1);
    for (const image of images) expect(image, image).toMatch(/:[\w.-]+@sha256:[0-9a-f]{64}$/);
    const text = readFileSync(file, 'utf8');
    // The last USER is the one the container runs as (an earlier `USER 0:0` only builds /app).
    expect([...text.matchAll(/^USER (\S+)$/gm)].at(-1)?.[1]).toBe('65532:65532');
    // Type declarations are not runtime code, and nothing may point at a removed package.
    expect(text).toContain('/out/node_modules/@types ');
    expect(text).toContain('undici-types');
    expect(text).toContain('find /out/node_modules -xtype l -delete');
    expect(text).toMatch(/^HEALTHCHECK [^\n]*\\\n[^\n]*\/healthz/m);
    expect(text).toContain('QUALOR_UI_DIR=/app/ui');
    expect(text).not.toMatch(/SECRET_KEY|PASSWORD|DATABASE_URL/);
    // enterprise.md §14.1: one image; the plugin and its licence ride along, inert without a key.
    expect(text).toContain('pnpm --filter @qualor/enterprise build');
    // Staged with explicit modes whatever the build stage's umask (R-PLUGINPATH refuses a group-
    // or world-writable plugin or directory); the smoke test checks the built image the same way.
    // No `COPY --chmod` for it: that would make the directory it creates 0644 as well.
    expect(text).toContain('install -d -m 0755 /enterprise');
    expect(text.replace(/\\\n\s*/g, '')).toContain(
      'install -m 0644 enterprise/dist/plugin.js enterprise/dist/plugin.js.map enterprise/LICENSE ' +
        // Its own manifest (with its own SPDX licence id), so an SBOM lists it apart from the MIT server.
        'enterprise/package.json /enterprise/',
    );
    const enterpriseCopies = text.split('\n').filter((l) => /^COPY .*\.\/enterprise/.test(l));
    expect(enterpriseCopies).toEqual(['COPY --from=build /enterprise ./enterprise']);
    expect(text).toContain('QUALOR_PLUGIN_PATHS=/app/enterprise/plugin.js');
    expect(text).not.toMatch(/QUALOR_LICENSE/);
    // Root-owned and read-only like the rest of /app: the enterprise files come before the last USER.
    const lastUser = text.lastIndexOf('\nUSER 65532:65532');
    expect(text.indexOf('./enterprise')).toBeGreaterThan(text.indexOf('\nUSER 0:0'));
    expect(text.lastIndexOf('./enterprise')).toBeLessThan(lastUser);
    expect(text).not.toMatch(/--chown=[^\n]*enterprise/);
    // The Trivy pins come from install.sh by eval: a renamed variable stops the build with a
    // message that names the pin.
    expect(text).toContain(': "${TRIVY_VERSION:?');
    expect(text).toContain('"${TRIVY_SHA256_X64:?');
    expect(text).toContain('"${TRIVY_SHA256_ARM64:?');
    // The vulnerability database copy outlives the container (docker-compose.yml names the volume).
    expect(text).toMatch(/^VOLUME \["\/var\/lib\/qualor", "\/var\/cache\/qualor\/vulndb"\]$/m);
    // A licence signing key never enters the build context (final review A M-3).
    expect(readFileSync('.dockerignore', 'utf8').split(/\r?\n/)).toContain('**/*.private.pem');
  });

  it('lists the enterprise plugin in the server notices as not MIT and inert without a key', () => {
    const notice = readFileSync('deploy/server/NOTICE.md', 'utf8');
    const row = notice.split('\n').find((line) => line.startsWith('| Qualor Enterprise'));
    expect(row).toMatch(/`\/app\/enterprise`/);
    expect(row).toMatch(/Qualor Enterprise Licence \(`\/app\/enterprise\/LICENSE`\)/);
    expect(row).toMatch(/inert without a licence key/);
    expect(notice).toMatch(/The enterprise plugin is not MIT\./);
    expect(notice).toMatch(/14-day grace period/);
    // The same terms as enterprise/LICENSE (one image, inert without a key; grace; no
    // organisation limit, enterprise.md §1.3).
    const flat = notice.replace(/\s+/g, ' ');
    expect(flat).toMatch(
      /mirroring or redistributing this image with the plugin unused needs no subscription/,
    );
    expect(flat).toMatch(/enables: its features and its validity, grace period included/);
    expect(flat).toMatch(/a trial key has no grace period/i);
    expect(flat).not.toMatch(/organisation limit|read-only/);
    const readme = readFileSync('deploy/README.md', 'utf8').replace(/\s+/g, ' ');
    expect(readme).toMatch(/redistributing the image with the plugin unused needs no subscription/);
    expect(readme).toMatch(/production use of the plugin needs a subscription or a trial/);
    expect(readme).toMatch(/\(its features and its validity, grace period included\)/);
    expect(readme).not.toMatch(/organisation limit|beyond which organisations/);
    // The MIT row names only what is MIT.
    expect(notice).toMatch(/\| Qualor server and web UI[^|]*\| this release\s*\| MIT/);
  });

  it('builds qualor/scanner from pinned bases, as a non-root user, with the entrypoint qualor', () => {
    const file = 'deploy/scanner/Dockerfile';
    for (const image of baseImages(file)) {
      expect(image, image).toMatch(/:[\w.-]+@sha256:[0-9a-f]{64}$/);
    }
    const text = readFileSync(file, 'utf8');
    expect([...text.matchAll(/^USER (\S+)$/gm)].at(-1)?.[1]).toBe('node');
    expect(text).toMatch(/^ENTRYPOINT \["\/usr\/local\/bin\/qualor-entrypoint"\]$/m);
    expect(text).toContain('sh /tmp/install.sh');
    expect(text).toContain('sh /tmp/install-qualor-rules.sh');
    expect(text).toContain('install -d /opt/qualor/rules/semgrep');
  });

  it("builds Gitleaks from install.sh's version, its source checked before it is unpacked", () => {
    const text = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    const installSh = readFileSync('tools/analyzers/install.sh', 'utf8');
    const version = /^GITLEAKS_VERSION=(\S+)$/m.exec(installSh)?.[1];
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(text).toContain(`ARG GITLEAKS_VERSION=${version}`);
    expect(text).toMatch(/^ARG GITLEAKS_SOURCE_SHA256=[0-9a-f]{64}$/m);
    expect(text.indexOf('sha256sum -c -')).toBeLessThan(
      text.indexOf('tar -xzf /tmp/gitleaks.tar.gz'),
    );
    // The stage's binary replaces install.sh's in the tools stage the final image copies.
    const copy = text.indexOf('COPY --from=gitleaks /gitleaks /opt/qualor/bin/gitleaks');
    expect(copy).toBeGreaterThan(text.indexOf('RUN sh /tmp/install.sh'));
    expect(copy).toBeLessThan(text.lastIndexOf('\nFROM '));
  });

  it("builds staticcheck and gosec of install-go.sh's versions from hash-pinned build modules (plan 9C, ruling G9-6)", () => {
    const text = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    const installGo = readFileSync('tools/analyzers/install-go.sh', 'utf8');
    const version = (tool: string) =>
      new RegExp(`^${tool}_VERSION=(\\S+)$`, 'm').exec(installGo)?.[1];
    for (const tool of ['STATICCHECK', 'GOSEC']) {
      expect(version(tool), tool).toMatch(/^\d+\.\d+\.\d+$/);
      expect(text).toContain(`ARG ${tool}_VERSION=${version(tool)}`);
    }
    const from = text.indexOf(' AS gotools');
    expect(from).toBeGreaterThan(0);
    const stage = text.slice(from, text.indexOf('\nFROM ', from));
    expect(stage).toContain('COPY tools/analyzers/go-tools/ /src/go-tools/');
    expect(stage).toContain('GOFLAGS="-trimpath -mod=readonly"');
    // Nothing is resolved at build time: no go get, go install or go mod in the stage.
    expect(stage).not.toMatch(/\bgo (get|install|mod)\b/);
    // The stage checks that it built install-go.sh's versions.
    expect(stage).toContain(
      '/out/staticcheck -version | grep -F "staticcheck ${STATICCHECK_VERSION} "',
    );
    expect(stage).toContain('/out/gosec -version | grep -Fx "Version: ${GOSEC_VERSION}"');
    const modules = {
      staticcheck: { tool: 'honnef.co/go/tools/cmd/staticcheck', raised: 'golang.org/x/mod' },
      gosec: { tool: 'github.com/securego/gosec/v2/cmd/gosec', raised: 'google.golang.org/grpc' },
    };
    for (const [name, m] of Object.entries(modules)) {
      const goMod = readFileSync(`tools/analyzers/go-tools/${name}/go.mod`, 'utf8');
      expect(
        goMod.split('\n').map((l) => l.trim()),
        name,
      ).toContain(`tool ${m.tool}`);
      // Every required module (direct or indirect) with both of its hashes in go.sum.
      expect(
        hashPinnedModules(name).map((r) => r.split(' ')[0]),
        name,
      ).toContain(m.raised);
    }
    const gosecMod = readFileSync('tools/analyzers/go-tools/gosec/go.mod', 'utf8');
    expect(gosecMod).toContain(`github.com/securego/gosec/v2 v${version('GOSEC')}`);
    // The stage's binaries replace install-go.sh's in the tools stage the final image copies.
    const copy = text.indexOf('COPY --from=gotools /out/staticcheck /out/gosec /opt/qualor/bin/');
    expect(copy).toBeGreaterThan(text.indexOf('sh /tmp/install-go.sh'));
    expect(copy).toBeLessThan(text.lastIndexOf('\nFROM '));
  });

  it("filters Trivy's database with the gotools stage's trivy-db-filter, which stays out of the image (D31-1)", () => {
    const text = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    const from = text.indexOf(' AS gotools');
    const stage = text.slice(from, text.indexOf('\nFROM ', from));
    // Built from its hash-pinned module (the stage's -mod=readonly), after its own tests.
    expect(stage).toContain('GOFLAGS="-trimpath -mod=readonly"');
    const build = stage.indexOf('go build -ldflags "-s -w" -o /out/trivy-db-filter .');
    expect(
      stage.indexOf('WORKDIR /src/go-tools/trivy-db-filter\nRUN go test ./...'),
    ).toBeGreaterThan(0);
    expect(stage.indexOf('go test ./...')).toBeGreaterThan(
      stage.indexOf('/src/go-tools/trivy-db-filter'),
    );
    expect(build).toBeGreaterThan(stage.indexOf('go test ./...'));
    expect(hashPinnedModules('trivy-db-filter')).toContain('go.etcd.io/bbolt v1.5.0');
    // The tools stage runs filter-trivy-db.sh with it after install-go.sh, then deletes both.
    const copy = text.indexOf('COPY --from=gotools /out/trivy-db-filter /tmp/');
    const run = text.indexOf(
      'RUN QUALOR_TRIVY_DB_FILTER=/tmp/trivy-db-filter sh /tmp/filter-trivy-db.sh && rm /tmp/trivy-db-filter /tmp/filter-trivy-db.sh',
    );
    expect(copy).toBeGreaterThan(text.indexOf('sh /tmp/install-go.sh'));
    expect(text).toContain('COPY tools/analyzers/filter-trivy-db.sh /tmp/');
    expect(run).toBeGreaterThan(copy);
    expect(run).toBeLessThan(text.lastIndexOf('\nFROM '));
    // Nothing named trivy-db-filter is copied anywhere but /tmp, and the final stage never names it.
    const copies = text
      .split('\n')
      .filter((l) => l.startsWith('COPY ') && l.includes('trivy-db-filter'));
    expect(copies).toEqual(['COPY --from=gotools /out/trivy-db-filter /tmp/']);
    expect(text.slice(text.lastIndexOf('\nFROM '))).not.toContain('trivy-db-filter');
  });

  it('accepts image vulnerabilities only with a reason and a review date', () => {
    const file = parse(readFileSync('deploy/scanner/.trivyignore.yaml', 'utf8')) as {
      vulnerabilities: { id: string; statement?: string; expired_at?: string }[];
    };
    expect(file.vulnerabilities.length).toBeGreaterThan(0);
    const ids = file.vulnerabilities.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const v of file.vulnerabilities) {
      expect(v.id).toMatch(/^CVE-\d{4}-\d+$/);
      expect(v.statement, v.id).toBeTruthy();
      // Trivy reports an entry again from its expiry date: the review date, never open-ended.
      expect(v.expired_at, v.id).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it('keeps every go command in qualor/scanner on the bundled Go (plan 9C, ruling G9-11)', () => {
    const text = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    const final = text.slice(text.lastIndexOf('\nFROM '));
    expect(final).toMatch(/^ENV GOTOOLCHAIN=local$/m);
  });

  it('builds qualor/scanner-dotnet from a named qualor/scanner, failing fast without one (plan 2D)', () => {
    const text = readFileSync('deploy/scanner-dotnet/Dockerfile', 'utf8');
    expect(text).toMatch(/^ARG SCANNER_IMAGE$/m);
    // buildkit's FROM has no ${VAR:?}: the fallback is an invalid (uppercase) reference.
    expect(baseImages('deploy/scanner-dotnet/Dockerfile')).toEqual([
      '${SCANNER_IMAGE:-SET_SCANNER_IMAGE_TO_A_BUILT_QUALOR_SCANNER_IMAGE}',
    ]);
    expect(text).toContain('COPY tools/analyzers/install-dotnet.sh /tmp/install-dotnet.sh');
    expect(text).toMatch(/^RUN sh \/tmp\/install-dotnet\.sh/m);
    // The ENV instructions, continuation lines joined: what the image's processes inherit.
    const env = Object.fromEntries(
      text
        .replace(/\\\r?\n/g, ' ')
        .split(/\r?\n/)
        .filter((line) => line.startsWith('ENV '))
        .flatMap((line) => line.slice(4).trim().split(/\s+/))
        .map((pair) => pair.split('=', 2)),
    );
    expect(env).toMatchObject({
      DOTNET_ROOT: '/opt/qualor/share/dotnet',
      DOTNET_CLI_TELEMETRY_OPTOUT: '1',
      QUALOR_DOTNET_ANALYZERS: '/opt/qualor/dotnet/analyzers',
    });
    expect([...text.matchAll(/^USER (\S+)$/gm)].at(-1)?.[1]).toBe('node');
  });
});
