# cracken-sbom

Generate a software inventory locally from package metadata and image archives.
The primary use case is an unpacked firmware root filesystem; a binary firmware
image can be unpacked locally first (see [Firmware images](#firmware-images)). The tool wraps
unmodified Syft v1.54.0 and writes minimized CycloneDX JSON 1.5 with local
provenance and quality sidecars.

The output reflects metadata available to the selected catalogers. Custom
binaries and software without package metadata may be absent. Some stripped
or statically linked programs are
[recognised by version strings](#components-recognised-by-version-strings).
Scan the shipped artifact and review the quality file. An inventory does not establish completeness, absence
of vulnerabilities or regulatory conformity.

## How it works and why your code stays with you

The crAcken generator runs on your own computer. It uses
[Syft](https://github.com/anchore/syft) to read local package metadata, such as
installed package lists and versions, from your unpacked firmware or local
image archive. For npm, it reads package and lock metadata instead of claiming
that those dependencies are installed or shipped. It does not install packages
or run your build scripts.

After downloading and verifying the generator and Syft, you can disconnect the
network and generate the list offline. Installation and signature verification
may need internet access; generation does not upload data or send telemetry.
It does not need access to your online source repository.

The result is a readable JSON text file. It does not contain copied source code
or file contents. The generator removes source/file lists, scan locations,
contacts and arbitrary metadata from Syft's output. Package names, versions,
licenses, package identifiers and hashes can remain. Your non-secret release
identifier is also included. Open `sbom.cdx.json` in a text editor and check it
before uploading: component names can reveal internal product or customer
names. Upload only that file; keep `provenance.json` and `quality.json` for your
records. Nothing is sent until you choose to upload the list yourself.

The generator's [source code](https://github.com/alexv-mc2/cracken-sbom) is open
under Apache-2.0. Signed downloads can be checked against the public build and
its exact source commit using the [verification guide](docs/VERIFICATION.md).
The signature and build record identify the downloaded file and the public
code used to build it; they do not prove that every component was found or that
your product is secure or compliant.

## Requirements and installation

Supported binary targets: Linux and macOS, amd64 and arm64. Works on Windows
through WSL 2 (Windows Subsystem for Linux): use the Linux release inside WSL 2
as described below. The CLI does not require [Node.js](https://nodejs.org/),
[Python](https://www.python.org/downloads/), [Docker](https://docs.docker.com/get-started/), a daemon, socket
or repository credentials. Input metadata and artifacts must already be
available locally; scanning does not run installs or build scripts. Provisioning
the CLI and Syft requires network access; generation can run offline.

### Windows

Works on Windows through WSL 2 (Windows Subsystem for Linux): use the Linux
release inside WSL 2 as described below. For a new installation, run
`wsl --install` in an administrator
[PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/overview)
session. WSL 2 (Windows Subsystem for Linux) is a Windows component from
Microsoft that runs Linux programs. It is switched on once.

1. Follow Microsoft's [WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
   and its Windows version requirements. Open PowerShell as administrator and
   run `wsl --install`. Restart your computer if prompted.
2. Open the installed Linux distribution (Ubuntu by default) from the Start
   menu and create the Linux username and password when prompted.
3. In PowerShell, run `wsl -l -v` and check that the distribution uses version 2.
   If it uses version 1, run `wsl --set-version <DistroName> 2`, replacing
   `<DistroName>` with its name in that list. If `wsl --install` only shows help,
   run `wsl --list --online`, then `wsl --install -d <DistroName>` to install a
   distribution from that list.
4. In the distribution's Linux shell, install the tools linked in
   [installation verification](docs/VERIFICATION.md#before-you-start), then
   follow that guide's Linux download and verification commands. Select the
   Linux archive for the architecture reported inside WSL, not a macOS archive.
5. Extract the firmware root filesystem under your Linux home directory and
   run the [rootfs inventory command](#generate-a-rootfs-inventory) there.

For firmware scans, extract the root filesystem inside the WSL Linux filesystem,
for example under your Linux home directory. Do not extract it under `/mnt/c/`
or another Windows drive: NTFS does not preserve all Linux symlinks and
permissions, so the resulting inventory can be incomplete. Alternatively, run
the generator on the Linux build machine or CI runner that builds the firmware.

Download the CLI from the [project releases](https://github.com/alexv-mc2/cracken-sbom/releases)
and verify the checksums and signatures as described in
[installation verification](docs/VERIFICATION.md). Download and verify the
pinned Syft engine using the same instructions. Do not substitute an
unverified engine or a moving `latest` install URL.

## Generate a rootfs inventory

Extract or export your firmware image locally using your existing build
process. Pass the filesystem root directory, not the source repository. Choose
a non-secret release identifier, not a path or URL. The output directory must
be new; existing output is not overwritten.

```sh
./cracken-sbom generate \
  --target-type rootfs --target /work/firmware/rootfs \
  --target-id firmware-2026.10.04 \
  --syft /opt/verified-tools/syft \
  --output /work/evidence/firmware-2026.10.04
```

Ctrl-C cancels generation and cleans temporary engine and staging files before
the process exits.

Other local targets use the same command with these arguments:

| `--target-type` | Local `--target` | Meaning |
|---|---|---|
| `npm` | Directory containing lock/package metadata | Metadata inventory; does not prove dependencies shipped |
| `python` | Directory containing installed `.dist-info` metadata | Installed distribution metadata; no package installation |
| `docker-archive` | Local archive exported with existing build tooling | No registry pull or Docker socket |
| `oci-archive` | Local OCI image archive | No registry pull |
| `rootfs` | Unpacked filesystem root with package metadata | Preferred firmware artifact scenario |
| `firmware-image` | Binary firmware image file (needs `--extractor`) | Unpacked locally first; see [Firmware images](#firmware-images) |

For [Yocto Project](https://www.yoctoproject.org/) builds, use the native SPDX
output from the build. The [Yocto guide](docs/YOCTO.md) explains how to enable
it, where each release puts the files and how to prepare a ZIP for upload.
This tool does not provide a Yocto adapter or conversion.

## Firmware images

Sometimes a contractor hands over only a binary image (`firmware.bin`) and no
build inventory. The `firmware-image` target is available from cracken-sbom
v1.1.0. With `--target-type firmware-image` the generator unpacks the
image on your computer with an open-source extractor, picks the root filesystem
it finds, and then runs exactly the same steps as for a `rootfs` target. The
image is never uploaded and the generator never contacts a network.

The extractor is a separate program that you install and name yourself, in the
same way as Syft. Two are supported: [unblob](https://github.com/onekey-sec/unblob)
(preferred) and [binwalk](https://github.com/ReFirmLabs/binwalk) version 3. Both
are MIT-licensed and run as separate processes; no extractor code is linked into
the generator.

Install unblob with [pipx](https://pipx.pypa.io/):

```sh
pipx install unblob
unblob --show-external-dependencies
```

The second command lists the helper tools unblob needs for each image format
(for example 7z, lz4, zstd, and `sasquatch` for SquashFS). Install the ones for
the formats in your image with your system package manager or as described in
the unblob installation guide; a missing helper means that format is not
unpacked. On macOS also run `brew install libmagic`. Windows users work inside
WSL 2 as described above.

The command was tested with unblob 26.6.4 and binwalk 3.1.0; older releases
were not tested. On Linux, a CI job ([Firmware Linux end-to-end](.github/workflows/firmware-linux-e2e.yml))
runs the target on every pull request and push to `main` with real unblob 26.6.4
and real binwalk 3.1.0, using the real `sasquatch` 4.5.1-6 package for SquashFS,
on the OpenWrt 24.10.8 ath79 Archer C7 v2 image (7 MB, SHA-256 and download URL
pinned in the workflow). It checks the image digest, the `firmware` block of
`provenance.json`, the `cracken:firmware:*` properties, that busybox and the
OpenWrt base packages are in the SBOM, that no path of the runner appears in the
output, and that no extraction folder is left behind. The same check is
`tests/firmware_e2e_linux.sh`. On macOS the earlier manual runs used a stand-in
for `sasquatch`, so the SquashFS path there is tested less. The CI job covers one
image of one device family; ext4, FIT and vendor-specific formats, other
extractor releases and larger images (the test image is 7 MB) are not part of it.

The generator passes only options that the installed unblob
lists in its `--help` (for unblob it turns off randomness analysis when the
version has that option), so differences in optional flags between releases do
not cause usage errors.

Then run the generator. `--extractor` is an absolute path (the link that pipx
creates is fine), and the output directory must be new:

```sh
./cracken-sbom generate \
  --target-type firmware-image --target /work/firmware/firmware.bin \
  --target-id firmware-2026.10.17 \
  --syft /opt/verified-tools/syft \
  --extractor "$HOME/.local/bin/unblob" \
  --output /work/evidence/firmware-2026.10.17
```

The extractor kind is read from the file name (`unblob` or `binwalk`). For any
other name add `--extractor-kind unblob` or `--extractor-kind binwalk`.
Extraction can take a long time and needs free disk space of several times the
image size; nothing limits its size except the 2-hour time limit.

The unpacked image is written to a private folder `.cracken-sbom-extract-*`
that is created next to the output directory and deleted when the command ends,
also after an error or Ctrl-C. If the process is killed without a chance to
clean up (for example `kill -9` or a power cut), that folder stays and you can
delete it by hand. Do not put the output directory inside a folder that a sync
client uploads (iCloud Drive or Desktop, OneDrive, Dropbox), because the sync
client could upload the unpacked firmware. Use `--work-dir /absolute/folder` to
create the private folder somewhere else, for example on a larger local disk;
the default is unchanged.

What happens, in order:

1. The generator computes the SHA-256 of the image and runs the extractor with
   `--version`. After the extraction the generator checks that the image file is
   still the same file with the same size, modification time and first and last
   MiB, and that the extractor file is unchanged; otherwise the run stops with an
   error. This does not detect an in-place rewrite of the middle of a large image
   that keeps its size and modification time, because the image is not copied. Do
   not change the image while the command runs.
2. The extractor unpacks the image into the private folder (for unblob:
   `unblob --extract-dir DIR firmware.bin`; for binwalk: `binwalk --extract
   --matryoshka --quiet --log LOG --directory DIR firmware.bin`).
3. The generator looks for the root filesystem: a folder that has `etc` and at
   least one of `bin`, `sbin`, `lib`, `usr`, or at least three of them, or that
   holds a package database. If several are found, the one with the most files is
   scanned and the others are listed. If none is found, the command stops and
   lists what was extracted, so you can unpack it yourself and use `rootfs`.
4. Syft scans the chosen folder with the same settings as for `rootfs`.

The `firmware` block in `provenance.json` records the image file name (without
its folder), size and SHA-256, the extractor kind and version, the SHA-256 of
the file you passed to `--extractor` (`entry_file_sha256`), the extraction time, the chosen root folder (relative to the
extraction folder), the number of extracted files, the entries extracted next to
the chosen root that were not scanned, and whether the extractor reported
errors. The extractor digest identifies only that one file, not the installed
software: with pipx it is a small launcher script, so it is not a pin of unblob's
code; the version is the stronger statement. `sbom.cdx.json` carries the main
facts as `cracken:firmware:*` properties so they travel with the file; it never
contains extracted file lists or paths of your computer. It does contain the
image file name (for example `firmware-2026.10.17.bin`), so name the file
accordingly before you upload the SBOM. A name with unusual characters is
replaced by `withheld-unsafe-characters` there; the exact name stays in
`provenance.json`. `quality.json` gets a warning that the inventory came
from an extracted image.

Archives inside the chosen root filesystem may also be unpacked by the extractor
(unblob unpacks nested containers into `*_extract` folders), and Syft then scans
those folders as part of the root. The inventory can therefore include packages
from nested archives that are not installed on the device.

Extraction is best effort. Encrypted content, formats the extractor does not
know and formats whose helper tool is missing are not unpacked, so packages
inside them are missing. Stripped or statically linked programs may lack
package metadata. Some are [recognised by version strings](#components-recognised-by-version-strings),
but images without a package database can still give a short or empty inventory.
Some extractors exit with an error for one chunk of an image and still unpack
the rest; this is recorded, not hidden. As with every
target type, the inventory does not establish completeness, absence of
vulnerabilities or regulatory conformity. A build-time inventory from your build
system, where one exists, is more accurate than an inventory read back from a
finished image.

**Security of the extraction step.** The generator itself never opens a network
connection. The extractor and the many helper programs it starts (7z, sasquatch
and others) are third-party tools that parse untrusted data with your own user
rights. They are not sandboxed by this tool on macOS, and the network
restrictions the generator sets for them (proxy variables pointing at a closed
port) are a courtesy to well-behaved programs, not a barrier. For an image from a
supplier you do not trust, run the whole command inside a virtual machine or
container without network access.

### Components recognised by version strings

Syft's [binary classifiers](https://github.com/anchore/syft/blob/v1.54.0/syft/pkg/cataloger/binary/classifiers.go)
recognise about 70 known programs from version strings inside binaries.
Examples include BusyBox, OpenSSL, curl, bash, lighttpd, nginx, Python and
Node.js. This can work even when a program is stripped or statically linked
and no package database exists. These components carry
`cracken:detection:method=version-string`. The `version_string_components`
field in `quality.json` counts them. The same count appears in provenance.

Nothing is found by these classifiers when the version string has been
removed, altered or obfuscated. The reported version is the upstream version
string; backported vendor fixes are not visible. Many components common in
embedded firmware are not recognised by Syft v1.54.0: zlib, Dropbear, OpenSSH,
dnsmasq, hostapd, wpa_supplicant, U-Boot, mbedTLS and wolfSSL.

This is not binary code analysis of the kind commercial firmware analysers
such as ONEKEY and Finite State do. Code compiled into a program without its
own version string is not found by these classifiers.

## What leaves your machine

The CLI does not upload data or send telemetry. Generation writes the SBOM and
sidecars to the output directory you selected. If you choose to submit an
inventory to a service, upload only `sbom.cdx.json`; keep `provenance.json` and
`quality.json` in your local evidence store. Submission is a manual action. The
generator has no automatic upload.

## Review the output

A successful output directory contains:

- `sbom.cdx.json`: minimized CycloneDX 1.5 inventory;
- `provenance.json`: CLI and engine versions, resolved scan-policy digest,
  supplied target identifier, generation time, privacy profile and SHA-256 of
  the final SBOM (for firmware images also the `firmware` block described above);
- `quality.json`: package counts and identified gaps or removals.

Review all three files. Component names, versions, package URLs and licenses
remain visible and may include confidential package identities. The normalizer
excludes arbitrary properties, source/file lists, location evidence, contacts
and nested originals. Local scan paths and full raw Syft output are not included.

Compare the exact final bytes to the recorded digest locally:

```sh
# Linux
sha256sum /work/evidence/firmware-2026.10.04/sbom.cdx.json
# macOS
shasum -a 256 /work/evidence/firmware-2026.10.04/sbom.cdx.json
```

Embedded generator metadata travels with the SBOM JSON. The value of the
supplied release identifier is your assertion, and the generation time comes
from your machine's clock.

## Inventory behavior

Read errors and `quality.json`. No packages or an unsafe or malformed component
identity is a failure. Missing versions require `--allow-incomplete`, an
explicit acknowledgement rather than a repair or completeness claim. License
coverage, ambiguous license choices and graph warnings remain visible for
review. Do not use `--allow-incomplete` to hide an empty or oversized inventory.

Named or free-text license choices are omitted with an explicit quality
warning, even when another SPDX identifier survives. Safe license IDs outside
the pinned CycloneDX 1.5 enumeration are preserved as a sole license expression
with a warning. CycloneDX 1.5 cannot mix expressions with other license
choices: incompatible expressions are omitted with a warning and an
`omitted_license_choices` count, while valid ID choices remain. No AND/OR
operator is invented. The schema is unchanged; this representation does not
verify legal meaning. Missing licenses are counted in `quality.json` and do not
prevent a versioned inventory from being generated.

## Tests

The test suite needs [Go](https://go.dev/doc/install), Syft and Python dependencies pinned in
`tests/requirements.txt`. Create a virtual environment and install the pinned
test dependencies:

```sh
python3 -m venv /tmp/cracken-sbom-test-venv
/tmp/cracken-sbom-test-venv/bin/pip install --require-hashes --only-binary=:all: \
  -r tests/requirements.txt
```

Then run the suite from the repository root:

```sh
GO=/opt/verified-tools/go/bin/go \
SYFT=/opt/verified-tools/syft \
PYTHON=/tmp/cracken-sbom-test-venv/bin/python \
CRACKEN_SBOM_TEST_OUTPUT=/tmp/cracken-sbom-test-output \
./tests/run-tests.sh
```

Tests scan checked-in synthetic metadata and generated local image archives.
The `firmware-image` test uses `tests/fake-extractor.sh`, a stand-in that
"unpacks" a dummy image into the rootfs fixture; unblob and binwalk themselves
are not installed by the suite. Their real behavior on Linux is checked by the
separate CI job and script described in [Firmware images](#firmware-images);
on other systems check it by hand with the command shown there.
They validate package identities, privacy behavior, output digests and the
CycloneDX schema. Fixtures do not install packages, pull images or contact a
database.

The [GitHub Actions example](examples/github-actions.yml) runs the CLI on a
customer-controlled self-hosted runner. It is reference material, not an
active workflow in this repository. It does not upload generated evidence.

## License

The wrapper is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE) for attribution and third-party notices.
