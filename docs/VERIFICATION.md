# Verify release downloads and the scanning engine

Verify the signed checksum manifest, every downloaded file's checksum and GitHub
build provenance before extracting or executing a release. Use a trusted cosign
2.6.2 (or compatible newer version) and a current GitHub CLI with `gh attestation
verify`. Commands below run in Bash on Linux and macOS. GitHub CLI may require
`gh auth login` for API access; no account token is sent to the scanner.

On Windows, there is no native build yet. Use the Linux release inside WSL 2:
enable WSL from PowerShell with `wsl --install`, then run the Linux commands in
this document from a WSL Linux shell. For firmware root filesystems, extract
under the WSL Linux filesystem (for example, your Linux home directory), not
under `/mnt/c/` or another Windows drive, where NTFS can lose symlinks and
permissions and make the inventory incomplete. You can also run the generator
on the Linux build machine or CI runner that builds the firmware. See the
[README Windows section](../README.md#windows).

## Release download

Set the exact version you intend to install; do not substitute `latest` or a
certificate identity regular expression. Before running this block, obtain the
full source commit SHA for that reviewed version from an independently trusted
release announcement or your organisation's approved record and set
`EXPECTED_COMMIT` to it. Reading a SHA from the same unverified download is not
an independent trust anchor. For a maintainer trial, use its reviewed tag SHA.

```bash
set -euo pipefail
VERSION=v0.1.0
: "${EXPECTED_COMMIT:?Set EXPECTED_COMMIT to the trusted full source commit SHA}"
COSIGN=cosign
mkdir "cracken-sbom-${VERSION}"
cd "cracken-sbom-${VERSION}"
gh release download "$VERSION" --repo alexv-mc2/cracken-sbom

"$COSIGN" verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/alexv-mc2/cracken-sbom/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Then verify all assets on **Linux**:

```bash
sha256sum --check SHA256SUMS
```

Or verify all assets on **macOS**:

```bash
shasum -a 256 --check SHA256SUMS
```

On either platform, verify the exact workflow, tag, source commit and hosted
runner provenance for every asset. Stop if any command fails:

```bash
for asset in SHA256SUMS SHA256SUMS.sigstore.json LICENSE NOTICE *.tar.gz *.cdx.json; do
  gh attestation verify "$asset" --repo alexv-mc2/cracken-sbom \
    --cert-identity "https://github.com/alexv-mc2/cracken-sbom/.github/workflows/release.yml@refs/tags/$VERSION" \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    --source-ref "refs/tags/$VERSION" --source-digest "$EXPECTED_COMMIT" \
    --deny-self-hosted-runners || exit 1
done
```

Only after **all** verification commands succeed, extract the matching archive:

```bash
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux_amd64 ;;
  Linux/aarch64|Linux/arm64) platform=linux_arm64 ;;
  Darwin/x86_64) platform=darwin_amd64 ;;
  Darwin/arm64) platform=darwin_arm64 ;;
  *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
tar -xzf "cracken-sbom_${VERSION#v}_${platform}.tar.gz"
./cracken-sbom version
```

Expected results are cosign `Verified OK`, checksum `OK` for every line, and
successful GitHub verification of each asset. A checksum alone does not identify
a publisher. A signature alone does not establish inventory completeness,
vulnerability absence, CRA conformity or trusted provenance at a receiving
service. Archive SBOM files describe the exact binary scan; they do not inventory
Syft because it is separately installed.

## Separate engine installation

Provision tools separately from the offline scan phase. Syft is not modified or
vendored. The supported engine is **v1.54.0**, with platform archive and executable
hashes recorded in `engine-manifest.json`. The helpers require Python 3.8+, curl
and cosign >=2.5. Run from a trusted source checkout of this repository:

```bash
./scripts/provision-cosign.sh /tmp/cracken-install/cosign
COSIGN=/tmp/cracken-install/cosign \
SYFT_CACHE=/tmp/cracken-install/syft-cache \
./scripts/provision-syft.sh /tmp/cracken-install/syft
```

The first helper bootstraps cosign v2.6.2 over authenticated upstream HTTPS and
checks its recorded platform SHA-256. This is a separate trust anchor from the
Syft signature. An organisation may provide its already-trusted cosign instead.
The second helper authenticates the upstream checksum bundle before checking
both the platform archive and exact extracted executable. It does not install
globally. Keep verification material in the cache and recheck it with:

```bash
./scripts/verify-syft.sh --cache /tmp/cracken-install/syft-cache \
  --cosign /tmp/cracken-install/cosign
```

For all four platforms, pre-provision archives and use `--all-platforms` with the
verifier. Sigstore trust-root initialization may require network; initialize it
during provisioning before an offline recheck. Both trust predicates are required:

```text
Certificate OIDC issuer: https://token.actions.githubusercontent.com
Certificate identity: https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main
```

Cosign verifies the v1.54.0 checksum manifest using its
`checksums.txt.sigstore.json` bundle. The archive SHA-256 must match both the
authenticated manifest and the local engine manifest; extraction follows those
checks. Scanning uses the already-provisioned binary and does not rerun the
online installation verifier. Use an explicit verified absolute engine path
under your installation controls. A version string alone cannot authenticate
an executable, and the executable must not be replaced after verification.

Syft is separately licensed Apache-2.0. Its authenticity, licence and update
obligations are distinct from this tool's. Its authenticated release bytes do
not prove that it detects every shipped component.

Sources: [Syft v1.54.0 release](https://github.com/anchore/syft/releases/tag/v1.54.0),
[Anchore verification](https://oss.anchore.com/docs/installation/verification/),
[release process](RELEASE.md).
