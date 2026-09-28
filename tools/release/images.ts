import { RELEASE_ORDER, type Flavour } from '../deploy/release';
import { imageTags, type Version } from './version';

/** release.md §5: push order; each sources image before its image, scanner before scanner-dotnet. */
export { RELEASE_ORDER };

/**
 * Every release name of every image, in push order. `released` is the versions already released
 * (`releasedVersions()`, the checkout's `v*` tags), so a moving tag never goes backwards
 * (release.md §2); callers always pass it.
 */
export function releaseRefs(
  namespace: string,
  v: Version,
  released: readonly Version[],
): { image: Flavour; refs: string[] }[] {
  const tags = imageTags(v, released);
  return RELEASE_ORDER.map((image) => ({
    image,
    refs: tags.map((t) => `${namespace}/${image}:${t}`),
  }));
}
