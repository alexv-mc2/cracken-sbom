# Upload an SBOM from a Yocto build

A [Yocto Project](https://www.yoctoproject.org/) build can create an SBOM itself.
You do not need the crAcken generator to create a second inventory when your
build already produces a supported SPDX inventory. Use the files from the
exact image you ship, and keep the original build output for your records.

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

A single JSON document is limited to 10 MiB for the public API and
`cracken-action`, which do not accept ZIP archives. The crAcken web app accepts
a ZIP up to 16 MiB both compressed and uncompressed in its SPDX JSON → ZIP
archive mode; ZIP upload is available to every account and does not require the
large-SBOM option. This mode also accepts a ZIP containing only CycloneDX JSON;
do not use the CycloneDX file picker for a ZIP. A single JSON document larger
than 10 MiB requires the large-SBOM option. Check the upload result and any
coverage notices.

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
