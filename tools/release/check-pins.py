"""Re-checks every pinned release download, independently of the toolbox (release.md §9).

Runs in a throwaway python container (check-pins.sh), never in qualor-release-tools:local, so no
tool checks its own signature:
- cosign: cosign_checksums.txt against its .sigstore.json bundle with sigstore-python, identity
  keyless@projectsigstore.iam.gserviceaccount.com, issuer https://accounts.google.com;
- Syft: syft_<v>_checksums.txt against its .sig and .pem with sigstore-python, with the exact
  identity of Syft's release workflow;
- Helm: helm-v<v>-linux-<arch>.tar.gz.sha256sum against its .asc with GnuPG and the Helm KEYS
  file, from the one pinned key;
- each pinned SHA-256 appears in the signed checksums file, and equals GitHub's release asset
  `digest` (Helm's tarballs are served from get.helm.sh, not GitHub, and have none);
- the Bun runtimes of bun-runtimes.json: the npm registry's integrity, and both our hashes of the
  downloaded tarball.
Read-only: HTTPS GETs and Sigstore's public TUF root and Rekor lookups. Prints each result and
"all pins verified", or stops at the first failure.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

PINS = os.environ.get("PINS_DIR", "/pins")
COSIGN_IDENTITY = "keyless@projectsigstore.iam.gserviceaccount.com"
COSIGN_ISSUER = "https://accounts.google.com"
SYFT_IDENTITY = "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
HELM_KEY = "208DD36ED5BB3745A16743A4C7C6FBB5B91C1155"
ARCHES = {"X64": "amd64", "ARM64": "arm64"}

work = tempfile.mkdtemp(prefix="check-pins-")


def fail(message):
    print(f"FAIL: {message}", flush=True)
    sys.exit(1)


def ok(message):
    print(f"ok   {message}", flush=True)


def get(url):
    if not url.startswith("https://"):
        fail(f"not https: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "qualor-check-pins"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def fetch(url):
    path = os.path.join(work, url.rsplit("/", 1)[1])
    with open(path, "wb") as f:
        f.write(get(url))
    return path


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def sigstore(*args):
    r = subprocess.run([sys.executable, "-m", "sigstore", "verify", "identity", *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"sigstore verify identity {' '.join(args)}\n{r.stdout}{r.stderr}")
    return (r.stdout + r.stderr).strip()


def in_checksums(path, sha, name):
    lines = open(path, encoding="utf-8").read().splitlines()
    if f"{sha}  {name}" not in lines:
        fail(f"{name}: the pin {sha} is not in {os.path.basename(path)}")
    ok(f"{name} {sha} is in {os.path.basename(path)}")


def github_digests(repo, tag):
    release = json.loads(get(f"https://api.github.com/repos/{repo}/releases/tags/{tag}"))
    return {a["name"]: a.get("digest") for a in release["assets"]}


def github_digest(digests, name, sha):
    if digests.get(name) != f"sha256:{sha}":
        fail(f"{name}: GitHub says {digests.get(name)}, the pin is sha256:{sha}")
    ok(f"{name} equals GitHub's asset digest sha256:{sha}")


script = open(os.path.join(PINS, "install-tools.sh"), encoding="utf-8").read()
pins = dict(re.findall(r"^([A-Z0-9_]+)=([^\s]+)$", script, re.M))

# cosign
v = pins["COSIGN_VERSION"]
base = f"https://github.com/sigstore/cosign/releases/download/v{v}"
sums = fetch(f"{base}/cosign_checksums.txt")
bundle = fetch(f"{base}/cosign_checksums.txt.sigstore.json")
out = sigstore("--bundle", bundle, "--cert-identity", COSIGN_IDENTITY,
               "--cert-oidc-issuer", COSIGN_ISSUER, sums)
ok(f"cosign_checksums.txt: {out} ({COSIGN_IDENTITY}, {COSIGN_ISSUER})")
digests = github_digests("sigstore/cosign", f"v{v}")
github_digest(digests, "cosign_checksums.txt", sha256(sums))
for arch, name in ARCHES.items():
    sha = pins[f"COSIGN_SHA256_{arch}"]
    in_checksums(sums, sha, f"cosign-linux-{name}")
    github_digest(digests, f"cosign-linux-{name}", sha)

# Syft
v = pins["SYFT_VERSION"]
base = f"https://github.com/anchore/syft/releases/download/v{v}"
sums = fetch(f"{base}/syft_{v}_checksums.txt")
sig = fetch(f"{base}/syft_{v}_checksums.txt.sig")
pem_b64 = fetch(f"{base}/syft_{v}_checksums.txt.pem")
pem = os.path.join(work, "syft-checksums.pem")
with open(pem, "wb") as f:  # goreleaser writes the PEM base64-encoded once more
    f.write(base64.b64decode(open(pem_b64, "rb").read()))
out = sigstore("--certificate", pem, "--signature", sig, "--cert-identity", SYFT_IDENTITY,
               "--cert-oidc-issuer", GITHUB_ISSUER, sums)
ok(f"syft_{v}_checksums.txt: {out} ({SYFT_IDENTITY}, {GITHUB_ISSUER})")
digests = github_digests("anchore/syft", f"v{v}")
for name in (f"syft_{v}_checksums.txt", f"syft_{v}_checksums.txt.sig",
             f"syft_{v}_checksums.txt.pem"):
    github_digest(digests, name, sha256(os.path.join(work, name)))
for arch, name in ARCHES.items():
    sha = pins[f"SYFT_SHA256_{arch}"]
    in_checksums(sums, sha, f"syft_{v}_linux_{name}.tar.gz")
    github_digest(digests, f"syft_{v}_linux_{name}.tar.gz", sha)

# Helm
v = pins["HELM_VERSION"]
home = tempfile.mkdtemp(prefix="gnupg-")
os.chmod(home, 0o700)
keys = fetch("https://raw.githubusercontent.com/helm/helm/main/KEYS")
subprocess.run(["gpg", "--homedir", home, "--batch", "--quiet", "--import", keys],
               check=True, capture_output=True)
digests = github_digests("helm/helm", f"v{v}")
for arch, name in ARCHES.items():
    tarball = f"helm-v{v}-linux-{name}.tar.gz"
    sums = fetch(f"https://get.helm.sh/{tarball}.sha256sum")
    asc = fetch(f"https://github.com/helm/helm/releases/download/v{v}/{tarball}.sha256sum.asc")
    r = subprocess.run(["gpg", "--homedir", home, "--batch", "--status-fd", "1", "--verify",
                        asc, sums], capture_output=True, text=True)
    valid = re.findall(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]{40})", r.stdout, re.M)
    if r.returncode != 0 or HELM_KEY not in valid:
        fail(f"{tarball}.sha256sum: no good signature by {HELM_KEY}\n{r.stdout}{r.stderr}")
    ok(f"{tarball}.sha256sum: good signature by {HELM_KEY}")
    github_digest(digests, f"{tarball}.sha256sum.asc", sha256(asc))
    in_checksums(sums, pins[f"HELM_SHA256_{arch}"], tarball)

# Bun runtimes (ruling R-MAC)
runtimes = json.load(open(os.path.join(PINS, "bun-runtimes.json"), encoding="utf-8"))
for target, pin in runtimes["runtimes"].items():
    meta = json.loads(get(f"https://registry.npmjs.org/{pin['package']}/{runtimes['version']}"))
    if meta["dist"]["integrity"] != pin["integrity"] or meta["dist"]["tarball"] != pin["url"]:
        fail(f"{pin['package']}: the registry says {meta['dist']}, the pin is {pin}")
    ok(f"{pin['package']}@{runtimes['version']}: the registry's integrity equals the pin")
    data = get(pin["url"])
    sha512 = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    if sha512 != pin["integrity"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        fail(f"{pin['url']}: the tarball does not match its pins")
    ok(f"{target}: the tarball matches {pin['integrity'][:20]}… and sha256 {pin['sha256']}")

print("all pins verified", flush=True)
