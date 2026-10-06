# Verify release downloads and the scanning engine

Verify the signed checksum manifest, every downloaded file's checksum and GitHub
build provenance before extracting or executing a release. Use a trusted
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.6.2 (or compatible newer version).

cosign is a tool from the Sigstore project (Linux Foundation) for checking
digital signatures of software. It confirms that the file comes from the public
crAcken build and has not been changed.

Use a current [GitHub CLI](https://cli.github.com/) with `gh attestation verify`.
Commands below run in Bash on Linux and macOS. GitHub CLI may require
`gh auth login` for API access; no account token is sent to the scanner.

On Windows, use the Linux release inside WSL 2. Follow the setup instructions
in the [README Windows section](../README.md#windows), then run these Linux
commands from a WSL Linux shell. For firmware root filesystems, extract under
the WSL Linux filesystem (for example, your Linux home directory), not under
`/mnt/c/` or another Windows drive, where NTFS can lose symlinks and permissions
and make the inventory incomplete. You can also run the generator on the Linux
build machine or CI runner that builds the firmware.

## Before you start

Install [GitHub CLI](https://cli.github.com/), trusted
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
[Git](https://git-scm.com/downloads/), [curl](https://curl.se/download.html)
and [Python 3.8 or later](https://www.python.org/downloads/).
Use [Bash](https://www.gnu.org/software/bash/) for the commands below, including
on macOS. You also need [tar](https://www.gnu.org/software/tar/manual/),
[sha256sum](https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html)
on Linux or [shasum](https://perldoc.perl.org/shasum) on macOS. Install these
using your operating system's trusted package manager where appropriate.
These tools are used to download, check and unpack the release; Python and
curl are used by the Syft installation helpers. They are not prerequisites for
running the already-installed generator itself.

Run the following sections in order in the same Bash terminal. Keep the network
connected during installation and verification. After both tools are verified,
you can disconnect it and [generate the component list](#generate-the-component-list).

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
RELEASE_DIR="$PWD"
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
and cosign >=2.5. Use Git to obtain the same public source commit you reviewed
for the release. This downloads the generator's public code, not your firmware
or your private source repository. Keep `EXPECTED_COMMIT` and `RELEASE_DIR`
from the release verification above:

```bash
: "${EXPECTED_COMMIT:?Complete release verification first}"
: "${RELEASE_DIR:?Complete release verification first}"
SOURCE_DIR="$RELEASE_DIR/source"
git clone --no-checkout https://github.com/alexv-mc2/cracken-sbom.git "$SOURCE_DIR"
git -C "$SOURCE_DIR" fetch origin "$EXPECTED_COMMIT"
git -C "$SOURCE_DIR" checkout --detach "$EXPECTED_COMMIT"
test "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$EXPECTED_COMMIT"
cd "$SOURCE_DIR"
```

Run the existing helpers from that verified checkout:

```bash
INSTALL_DIR="$RELEASE_DIR/tools"
mkdir "$INSTALL_DIR"
./scripts/provision-cosign.sh "$INSTALL_DIR/cosign"
COSIGN="$INSTALL_DIR/cosign" \
SYFT_CACHE="$INSTALL_DIR/syft-cache" \
./scripts/provision-syft.sh "$INSTALL_DIR/syft"
```

The first helper bootstraps cosign v2.6.2 over authenticated upstream HTTPS and
checks its recorded platform SHA-256. This is a separate trust anchor from the
Syft signature. An organisation may provide its already-trusted cosign instead.
The second helper authenticates the upstream checksum bundle before checking
both the platform archive and exact extracted executable. It does not install
globally. Keep verification material in the cache and recheck it with:

```bash
./scripts/verify-syft.sh --cache "$INSTALL_DIR/syft-cache" \
  --cosign "$INSTALL_DIR/cosign"
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

## Generate the component list

Keep the variables from the installation above. Extract your firmware locally,
replace `ROOTFS` with its unpacked root directory and choose a non-secret release
identifier. The output directory must not already exist. You can disconnect the
network for this step:

```bash
ROOTFS="$HOME/firmware/rootfs"
RELEASE_ID=firmware-2026.10.06
OUTPUT_DIR="$HOME/evidence/$RELEASE_ID"
mkdir -p "$HOME/evidence"
"$RELEASE_DIR/cracken-sbom" generate \
  --target-type rootfs --target "$ROOTFS" \
  --target-id "$RELEASE_ID" \
  --syft "$INSTALL_DIR/syft" \
  --output "$OUTPUT_DIR"
```

Review `sbom.cdx.json`, `provenance.json` and `quality.json` in that output
directory. Upload only `sbom.cdx.json`; keep the two other files locally.
See [output review and coverage limits](../README.md#review-the-output).

Sources: [Syft v1.54.0 release](https://github.com/anchore/syft/releases/tag/v1.54.0),
[Anchore verification](https://oss.anchore.com/docs/installation/verification/),
[release process](RELEASE.md).
