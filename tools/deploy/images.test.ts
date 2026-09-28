import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/** Every `FROM` of a Dockerfile: an exact version tag and a digest (plan 1G ruling D1). */
function baseImages(dockerfile: string): string[] {
  return [...readFileSync(dockerfile, 'utf8').matchAll(/^FROM (\S+)/gm)].map((m) => m[1] ?? '');
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
    expect(flat).not.toMatch(/organisation limit|read-only/);
    const readme = readFileSync('deploy/README.md', 'utf8').replace(/\s+/g, ' ');
    expect(readme).toMatch(/redistributing the image with the plugin unused needs no subscription/);
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
    expect(text).toMatch(/^ENTRYPOINT \["qualor"\]$/m);
    expect(text).toContain('sh /tmp/install.sh');
    expect(text).toContain('install -d /opt/qualor/rules/semgrep');
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
