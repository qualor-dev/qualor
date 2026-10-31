const TYPE_OF: Readonly<Record<string, string>> = {
  npm: 'npm',
  yarn: 'npm',
  pnpm: 'npm',
  bun: 'npm',
  'node-pkg': 'npm',
  pip: 'pypi',
  pipenv: 'pypi',
  poetry: 'pypi',
  uv: 'pypi',
  'python-pkg': 'pypi',
  pom: 'maven',
  gradle: 'maven',
  sbt: 'maven',
  jar: 'maven',
  nuget: 'nuget',
  'dotnet-core': 'nuget',
  'packages-props': 'nuget',
  gomod: 'golang',
  gobinary: 'golang',
  cargo: 'cargo',
  'rust-binary': 'cargo',
  composer: 'composer',
  'composer-vendor': 'composer',
  bundler: 'gem',
  gemspec: 'gem',
  pub: 'pub',
  'mix-lock': 'hex',
  swift: 'swift',
  cocoapods: 'cocoapods',
  conan: 'conan',
};

/** Encodes one path segment: everything but unreserved characters is percent-encoded. */
const segment = (s: string): string =>
  encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );

/**
 * Package URL of a stored dependency (`branch_dependencies.ecosystem` is Trivy's `Result.Type`),
 * or null when the ecosystem has no purl type (it is counted as "not checked").
 */
export function purlOf(ecosystem: string, name: string, version: string): string | null {
  const type = TYPE_OF[ecosystem];
  if (type === undefined || name === '' || version === '') return null;
  let path = name;
  if (type === 'pypi') path = name.toLowerCase().replace(/_/g, '-');
  else if (type === 'maven') path = name.replace(':', '/');
  const encoded = path.split('/').map(segment).join('/');
  return `pkg:${type}/${encoded}@${segment(version)}`;
}
