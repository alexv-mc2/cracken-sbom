# cracken-sbom

Generate a software inventory locally from package metadata and image archives.
The primary use case is an unpacked firmware root filesystem. The tool wraps
unmodified Syft v1.54.0 and writes minimized CycloneDX JSON 1.5 with local
provenance and quality sidecars.

The output reflects metadata available to the selected catalogers. Stripped
images, custom binaries, statically linked code, missing package databases and
software outside those catalogers may be absent. Scan the shipped artifact and
review the quality file. An inventory does not establish completeness, absence
of vulnerabilities or regulatory conformity.

## Requirements and installation

Supported binary targets: Linux and macOS, amd64 and arm64. There is no native
Windows build yet; Windows users can run the Linux release inside WSL 2 as
described below. The CLI does not require Node, Python, Docker, a daemon, socket
or repository credentials. Input metadata and artifacts must already be
available locally; scanning does not run installs or build scripts. Provisioning
the CLI and Syft requires network access; generation can run offline.

### Windows

There is no native Windows build yet. On Windows, use the Linux amd64 or arm64
release inside WSL 2. For a new installation, run `wsl --install` in an
administrator PowerShell session and restart your computer if prompted. If WSL
is already installed, check the distro version with `wsl -l -v`; convert a
distro to WSL 2 with `wsl --set-version <DistroName> 2`. If `wsl --install`
shows help instead of installing a distro, list available distros with
`wsl --list --online` and install one with `wsl --install -d <DistroName>`.
See Microsoft's [WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
for details. Once a WSL 2 distro is available, follow the Linux verification
and installation steps from its Linux shell. See
[installation verification](docs/VERIFICATION.md) for the commands.

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

For Yocto builds, use the native SPDX output from the build. This tool does not
provide a Yocto adapter or conversion.

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
  the final SBOM;
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

The test suite needs Go, Syft and Python dependencies pinned in
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
They validate package identities, privacy behavior, output digests and the
CycloneDX schema. Fixtures do not install packages, pull images or contact a
database.

The [GitHub Actions example](examples/github-actions.yml) runs the CLI on a
customer-controlled self-hosted runner. It is reference material, not an
active workflow in this repository. It does not upload generated evidence.

## License

The wrapper is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE) for attribution and third-party notices.
