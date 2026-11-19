# Upload an SBOM from a Yocto build

A [Yocto Project](https://www.yoctoproject.org/) build can create an SBOM itself.
Use the files from the exact image you ship, and keep the original build output
for your records. There are two ways to use them:

- **Upload the native SPDX to crAcken** (sections below). crAcken reads the
  build's patched-CVE and VEX data from it directly, so already fixed CVEs are
  not reported. This needs no generator.
- **Generate a CycloneDX 1.6 SBOM plus a separate VEX file** with
  `cracken-sbom generate --target-type yocto` for customers or authorities that
  ask for BSI TR-03183-2 v2.1.0 (CycloneDX 1.6), as described next.

## CycloneDX 1.6 and VEX from the Yocto SPDX

Run it on the image's deploy directory, `tmp/deploy/images/<machine>/` in the
build directory (here for `qemux86-64`):

```sh
./cracken-sbom generate --target-type yocto \
  --target "$BUILDDIR/tmp/deploy/images/qemux86-64" \
  --target-id core-image-minimal-2026.11.18 \
  --syft /opt/verified-tools/syft \
  --output /work/evidence/core-image-minimal-2026.11.18 \
  --manufacturer-name "Example GmbH" --manufacturer-email psirt@example.com \
  --product-license LicenseRef-example-proprietary
```

`cracken-sbom detect` on the build directory or on the deploy directory finds
the image SPDX and runs this command itself; with several images or machines
it prints one complete command for each.

A deploy directory holds the dated files of each build and links without the
date (`IMAGE_LINK_NAME`), for example
`core-image-minimal-qemux86-64.rootfs-20261118093000.spdx.tar.zst` and the
link `core-image-minimal-qemux86-64.rootfs.spdx.tar.zst`. A link and its target
count as one file. The tool reads:

| Release | What it reads | Notes |
|---|---|---|
| Scarthgap 5.0 and earlier (SPDX 2.2, `create-spdx-2.2`) | the image's `*.spdx.tar.zst`, or the unpacked `*.spdx.json` documents | the archive is unpacked with the external [zstd](https://facebook.github.io/zstd/) (`--zstd /path/to/zstd` when it is not on `PATH`); the image document's `CONTAINS` list selects the installed packages |
| Styhead 5.1 and later, including Walnascar 5.2, Whinlatter 5.3 and Wrynose 6.0 (SPDX 3, `create-spdx-3.0` is the default class since 5.1) | the single complete `*.rootfs.spdx.json` (SPDX 3.0.0 or 3.0.1, depending on the release) | packages reachable from the image through `contains`, `dependsOn` and `hasInput` |

If the directory holds several different images, choose one with
`--yocto-image NAME` (a file name prefix, such as `core-image-minimal`). Build-host and SDK packages (`*-native`, `nativesdk-*`,
`*-cross*`) and recipes (source packages) are never listed. The same checks
as the crAcken GitHub Action's `yocto-pack` apply: no links out of the
directory, no unsafe archive paths or links, one SPDX version, SPDX 3.1 refused,
128 MiB read limit, 10,000 documents.

The pinned Syft converts the selected packages with `syft convert` to
CycloneDX 1.6, and the normal minimization and TR-03183-2 layer follow
(see [TR-03183-2](TR-03183-2.md)). The image is the product
(`metadata.component`); its name and version come from the image document
unless `--product-name` / `--product-version` are given.

### The VEX file

BSI TR-03183-2 §3.1 forbids vulnerability information in an SBOM. The CVEs
the build already handled therefore go into a **separate** file,
`sbom.vex.cdx.json` (CycloneDX VEX 1.6), next to `sbom.cdx.json`:

| Yocto source | CycloneDX `analysis.state` |
|---|---|
| SPDX 2.2 recipe `sourceInfo` "CVEs fixed: …" | `resolved` |
| SPDX 3 `security_VexFixedVulnAssessmentRelationship` (`fixedIn`) | `resolved` |
| SPDX 3 `security_VexNotAffectedVulnAssessmentRelationship` (`doesNotAffect`) | `not_affected` (with `code_not_present`, `code_not_reachable` or `protected_by_mitigating_control` when the SPDX justification maps to one) |
| SPDX 3 `security_VexAffectedVulnAssessmentRelationship` (`affects`) | `exploitable` |

These are the same rules crAcken uses when it reads the native SPDX.
Licence references to another document of the set
(`DocumentRef-recipe-xz:LicenseRef-PD`) are written as `LicenseRef-PD` in the
CycloneDX licence expression, because the document prefix names nothing in a
single CycloneDX file; `quality.json` notes when this happened. An
assessment on a recipe applies to the packages the recipe generates;
assessments withdrawn in the past are left out. Each `affects[].ref` is the
`bom-ref` of the component in `sbom.cdx.json`, and `versions` repeats its
version. The file has no inventory of its own and no free-text notes from the
build. `provenance.json` lists it with its SHA-256 under `extra_outputs`. If
the SPDX holds no such data, no VEX file is written and `quality.json` says so.

Tested on real build output: a Scarthgap 5.0 `core-image-minimal` archive
(`fixtures/yocto/real-scarthgap`, 38 components, 28 `resolved`) and the Yocto
Project's own Wrynose 6.0.3 `core-image-minimal-qemux86-64.rootfs.spdx.json`
from downloads.yoctoproject.org (38 components, 32 CVEs: 22 `not_affected`,
10 `resolved`). The second file is not checked in; to repeat that test, set
`CRACKEN_SBOM_YOCTO_SPDX3_SAMPLE` to a local copy when running
`tests/run-tests.sh`.

For crAcken, upload the build's native SPDX ZIP as described below; the CycloneDX 1.6 SBOM and the VEX file are the files for BSI TR-03183-2 and your customers, not for crAcken.

## Choose the instructions for your release

The [Yocto release index](https://docs.yoctoproject.org/releases.html) lists
Scarthgap 5.0 and Wrynose 6.0 as supported release families at the time of this
guide. Their default SPDX formats differ:

| Yocto release | Default SBOM format | Default image output directory | Upload to crAcken |
|---|---|---|---|
| [Scarthgap 5.0](https://docs.yoctoproject.org/5.0/dev-manual/sbom.html) | SPDX 2.2 JSON | `tmp/deploy/images/<machine>/` inside the build directory | Repack the image's SPDX document archive as ZIP and upload it through the web app's SPDX JSON → ZIP archive mode |
| [Wrynose 6.0](https://docs.yoctoproject.org/6.0/dev-manual/sbom.html) | SPDX 3.0.1 JSON | `tmp/deploy/images/<machine>/` inside the build directory | Upload the single complete `*.rootfs.spdx.json` file for the image |

Paths assume the default `TMPDIR` and deployment settings. Custom settings can
move them. The filenames begin with your image name and machine; build variants
may add a timestamp. Select the archive emitted by the build you are assessing.

Wrynose's `create-spdx` class selects SPDX 3.0.1 and no longer includes the
SPDX 2.2 class. crAcken accepts one complete SPDX 3.0.0 or 3.0.1 JSON document,
including the image's `*.rootfs.spdx.json`; SPDX 3.1 and later are not accepted.
Do not combine multiple SPDX 3 documents or mix SPDX 2 and SPDX 3 in a ZIP.
A ZIP does not convert between SPDX versions. Keep the native SBOM for your
records and review it for sensitive information before uploading.

The public API limits a single JSON document to 10 MiB. ZIP archives can be
uploaded in the crAcken web app by selecting **ZIP archive** under **SPDX
upload method**, or sent to the public API's `POST /v1/sboms` endpoint with
`Content-Type: application/zip`. API ZIPs are limited to 16 MiB compressed and
16 MiB unpacked. Exceeding the compressed limit returns HTTP 413
`archive_too_large`; exceeding the unpacked limit returns HTTP 413
`archive_unpacked_too_large`. ZIP upload is available to every account and does
not require the large-SBOM option. The web app's ZIP archive mode also accepts
a ZIP containing only CycloneDX JSON; do not use the CycloneDX file picker for a
ZIP. In the web app, a single JSON document larger than 10 MiB requires the
large-SBOM option. Check the upload result and any coverage notices.

Older Yocto releases have different defaults. Use the manual for your exact
release and check the format before uploading; do not assume that every file
ending in `.spdx.json` uses the same SPDX model.

## Converting SPDX 2.2 or 2.3 RDF, YAML or XML

crAcken does not directly ingest SPDX RDF, YAML or XML. The external
[spdx/tools-python](https://github.com/spdx/tools-python) package supplies
`pyspdxtools` to convert SPDX 2.2 or 2.3 documents to SPDX JSON. Install it
separately in your controlled environment, then use filenames with the
appropriate input and output extensions, for example:

```bash
pyspdxtools -i input.spdx.yaml -o output.spdx.json
```

Review and validate the converted output before uploading. This conversion
guidance applies to SPDX 2.2 and 2.3, not SPDX 3. CycloneDX 2.0 is not accepted
by crAcken.

## Enable SPDX output

In the build's `conf/local.conf`, enable the native class:

```bitbake
INHERIT += "create-spdx"
```

Standard Poky configurations already enable it through `INHERIT_DISTRO`; if
your configuration does too, no extra line is needed. Check custom distribution
settings if they remove it. Then build your image normally in the configured
[BitBake](https://docs.yoctoproject.org/bitbake/) build shell:

```bash
bitbake your-image
```

The [Scarthgap SBOM manual](https://docs.yoctoproject.org/5.0/dev-manual/sbom.html)
and [Wrynose SBOM manual](https://docs.yoctoproject.org/6.0/dev-manual/sbom.html)
describe the release-specific options. Leave source and package archive options
off unless you need them for your own records. Those archives are not upload
inputs for this workflow.

## Find the Scarthgap SPDX files

In `tmp/deploy/images/<machine>/`, find the image's `.spdx.json`,
`.spdx.index.json` and `.spdx.tar.zst` outputs. The `.spdx.tar.zst` archive
contains the image document and the package, runtime and recipe documents
referenced by that image, plus `index.json`. Use this image-specific archive
rather than collecting every document from every previous build.

Individual documents also live under `tmp/deploy/spdx/`, split into architecture
directories with `recipes/`, `packages/` and `runtime/` subdirectories. A package
architecture can differ from the image's machine. Uploading only the top-level
image file or only `recipe-*` files can omit the referenced component documents.

## Prepare a Scarthgap ZIP

Run this on the Linux build host. You need
[GNU tar](https://www.gnu.org/software/tar/manual/),
[zstd](https://facebook.github.io/zstd/),
[zip](https://infozip.sourceforge.net/Zip.html) and
[mktemp](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html),
installed through your distribution's package manager. Replace the archive
path below with the exact `.spdx.tar.zst` from your image build. Run from your
build directory and choose a new ZIP filename:

```bash
set -euo pipefail
SBOM_ARCHIVE="$PWD/tmp/deploy/images/your-machine/your-image-your-machine.spdx.tar.zst"
ZIP_PATH="$PWD/yocto-image.spdx.zip"
test -f "$SBOM_ARCHIVE"
test ! -e "$ZIP_PATH"
EXPORT_DIR="$(mktemp -d)"
tar --zstd -xf "$SBOM_ARCHIVE" -C "$EXPORT_DIR"
(
  cd "$EXPORT_DIR"
  zip "$ZIP_PATH" ./*.spdx.json
)
```

Open the extracted JSON files in a text editor and check that they declare
`"spdxVersion": "SPDX-2.2"`. Review their contents before uploading: native
Yocto files can include source references, filenames and internal package
identities. This workflow does not apply the generator's privacy filtering.
The ZIP includes all SPDX documents from the image archive; it excludes
`index.json` and any source/package content archives. Keep the extracted index
and original archive locally for your records.

On crAcken's Tools page, choose SPDX JSON → ZIP archive and upload
`yocto-image.spdx.zip`.
The app applies its normal upload limits and reports extraction results;
review any missing-component or partial-coverage notice before relying on the
analysis. Packaging the documents does not prove that the inventory is complete
or that your product is secure or compliant.

Format and archive layout sources:
[Scarthgap class](https://github.com/openembedded/openembedded-core/blob/yocto-5.0/meta/classes/create-spdx-2.2.bbclass),
[Wrynose default class](https://github.com/openembedded/openembedded-core/blob/yocto-6.0/meta/classes/create-spdx.bbclass)
and [Wrynose SPDX class](https://github.com/openembedded/openembedded-core/blob/yocto-6.0/meta/classes/create-spdx-3.0.bbclass).
