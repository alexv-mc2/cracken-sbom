# Synthetic local scan fixtures

These are authored metadata records, not downloaded packages or installed code.
Never run npm/pip install or pull container images for these tests.

Independent exact expectations:

| Target | Package name | Version | PURL |
|---|---|---|---|
| npm | left-pad | 1.3.0 | `pkg:npm/left-pad@1.3.0` |
| npm | is-number | 7.0.0 | `pkg:npm/is-number@7.0.0` |
| Python | alpha-fixture | 1.2.3 | `pkg:pypi/alpha-fixture@1.2.3` |
| Python | beta-fixture | 4.5.6 | `pkg:pypi/beta-fixture@4.5.6` |
| rootfs | busybox | 1:1.35.0-4+b3 | `pkg:deb/debian/busybox@1%3A1.35.0-4%2Bb3?arch=arm64&distro=debian-12` |
| rootfs | libssl3 | 3.0.11-1~deb12u2 | `pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=arm64&distro=debian-12` |

The rootfs has a Debian 12 os-release and dpkg status database. It intentionally
has no package payloads, so these tests verify cataloging package records,
not installation validity, package files or arbitrary firmware coverage.
`tests/make-archives.py` deterministically creates Docker/OCI archive layers
from the same rootfs during testing; no binary/archive artifact is committed.
Both archive types must yield exactly the same two package identities.

`rootfs-absolute-symlink` is a small Debian rootfs template for the actual
Syft symlink-boundary regression. The test replaces its `var/lib/dpkg/status`
file with an absolute symlink to a synthetic dpkg status database created
outside the rootfs. It first scans that canary on its own through the CLI to
prove the package is detectable, then verifies that the `--base-path`
rootfs scan still returns exactly the two in-rootfs packages and excludes the
canary. An in-root shadow status file keeps the normal fixture packages
available if the absolute link is resolved within the rootfs. The canary is
generated at runtime so its absolute target works on both macOS and Linux; no
host package database is read or modified.

Versionless, malformed, nested, privacy and license transformation cases belong
in synthetic unit tests, separate from the exact known engine inventories.

Syft also emits `operating-system` identity `debian` version `12` with no PURL.
It is retained as an additional evidence row: rootfs and archives have two
package rows plus one OS row (three components total).
