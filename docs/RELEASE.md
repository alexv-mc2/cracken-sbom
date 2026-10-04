# Release process

Release tags use `vMAJOR.MINOR.PATCH`, optionally followed by a prerelease suffix.
The first supported version is `v0.1.0`. Maintainers review the source and green
CI before creating a tag. `.github/workflows/release.yml` publishes only on `v*` tags;
the publishing path validates the version before building and treats tags containing `-` as
prereleases. Tags and released assets must not be replaced after distribution.

## Build and publish

1. Run the reusable CI suite on the tagged source: Go tests, offline real-Syft
   fixtures, CycloneDX schema validation and four cross-builds.
2. Provision Go 1.26.1 and authenticate separately installed Syft 1.54.0 with
   the pinned cosign bootstrap and the engine's signed upstream checksums.
3. Build Linux/macOS amd64/arm64 with `CGO_ENABLED=0`, `GOTOOLCHAIN=local`,
   `GOPROXY=off`, `GOSUMDB=off`, `-trimpath`, `-buildvcs=false`, an empty build ID
   and the release version injected into `main.toolVersion`. Builds and binary
   inventory run in an OS network namespace without network access.
4. Rebuild each binary in another output directory and require byte equality.
   Archives have sorted fixed members, normalized owner/permissions, source
   commit timestamps and deterministic gzip headers. Binaries and archives are
   reproducible with the same source, Go toolchain, version and timestamp. SBOM
   timestamps and serial numbers vary and are not claimed reproducible.
5. Scan each exact binary with verified Syft to produce CycloneDX 1.5 and
   validate all four inventories against the pinned official schema offline. Require
   its SHA-256 file evidence and detected Go standard library. Replace only the
   file component's runner path with `cracken-sbom`; preserve its hashes. Syft
   can report the main Go module version as `UNKNOWN`; the inventory is retained
   honestly, while the release version is recorded in metadata and the CLI.
6. Package each binary with LICENSE and NOTICE. Publish those files separately,
   four archives, four `.cdx.json` files and a sorted `SHA256SUMS` covering them.
7. In the publishing job, verify the checksums, sign `SHA256SUMS` with cosign
   keyless using GitHub OIDC, and create GitHub build-provenance attestations
   for every release asset including the manifest and its signature bundle.
   No stored signing key or application secret is used. Only this job receives
   `contents: write`, `id-token: write` and `attestations: write`. Download
   verification jobs receive only `contents: read` and `attestations: read`
   so they can fetch assets and provenance without signing or publishing.
8. Publish a GitHub Release only after signing and attestation succeed. Download
   and verify it on Linux and macOS using the commands in
   [VERIFICATION.md](VERIFICATION.md), then run the native binary's version
   command. Other architectures receive cross-build checks, not runtime claims.

The workflow retains signed candidate assets for seven days and verifies their
signature and checksums on Linux and macOS even if provenance publication fails.
This diagnostic check is distinct from successful release download verification.
A failed attestation blocks release publication; the workflow never downgrades
this requirement. GitHub artifact attestations for non-public repositories
require GitHub Enterprise Cloud; all current plans support public repositories.
See [GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## Trust and inventory limits

Cosign uses the public Sigstore service. Its transparency log records the
repository/workflow identity and signature metadata permanently. Deleting a
trial release or tag does not erase that log. Provenance also identifies the
source commit and GitHub runner workflow.

Syft is not bundled, modified or executed from the archive. Its separate engine
installation and verification are documented in VERIFICATION.md. The tool's own
SBOM describes detected binary metadata, including the Go runtime/standard
library; it does not establish complete static-code or vulnerability coverage.
Signatures and attestations authenticate bytes and workflow identity, not CRA
conformity, inventory completeness, vulnerability absence or server-side trust.

A read-only manual workflow dispatch verifies only the fixed disposable tag
`v0.0.0-rc.1`, using the required reviewed source SHA input. It creates no
release or signature and still fails if provenance is unavailable.

A trial tag such as `v0.0.0-rc.1` exercises the same pipeline. Record source SHA,
workflow URL, artifact hashes and verification output before deleting the trial
release and tag. Retain the evidence separately; never represent a platform
failure or a candidate-artifact check as a completed release verification.
