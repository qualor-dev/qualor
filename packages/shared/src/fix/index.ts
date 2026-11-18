/**
 * `@qualor/shared/fix` (R1): what the CLI's `qualor fix` and the server's fix checks share. A
 * subpath export, not part of the shared index, so its libraries stay out of the UI bundle.
 */
export * from './families';
export * from './versions';
export * from './target';
export * from './scrub';
export { compareSemver } from './versions/semver';
export { compareGo, goSameModuleMajor } from './versions/go';
export { comparePep440 } from './versions/pep440';
export { compareMaven, mavenItems, type MavenItem, type MavenPrefix } from './versions/maven';
