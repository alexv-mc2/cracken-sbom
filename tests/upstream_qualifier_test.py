#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Debian upstream PURL qualifiers emitted by real Syft."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

from license_choices_test import schema_validator


PACKAGE_NAME = "cracken-fixture-binary-canary"
PACKAGE_VERSION = "1:2.0-3~deb12u1"
SOURCE_NAME = "cracken-fixture-source-canary"
SOURCE_VERSION = "2:4.5-6~deb12u2"


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: upstream_qualifier_test.py CRACKEN_SBOM SYFT SCHEMA_DIR")
    cli, syft, schema_dir = map(Path, sys.argv[1:])
    if not cli.is_absolute() or not syft.is_absolute():
        raise SystemExit("CLI and Syft paths must be absolute")
    schema = schema_validator(schema_dir)

    with tempfile.TemporaryDirectory(prefix="cracken-sbom-upstream-source-") as temporary:
        work = Path(temporary)
        target = work / "rootfs"
        (target / "etc").mkdir(parents=True)
        (target / "var/lib/dpkg").mkdir(parents=True)
        (target / "etc/os-release").write_text(
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\nID_LIKE=debian\n'
        )
        (target / "var/lib/dpkg/status").write_text(
            f"Package: {PACKAGE_NAME}\n"
            "Status: install ok installed\n"
            "Priority: optional\nSection: misc\nArchitecture: amd64\n"
            f"Version: {PACKAGE_VERSION}\n"
            f"Source: {SOURCE_NAME} ({SOURCE_VERSION})\n"
            "Description: Synthetic Debian upstream source regression\n\n"
        )
        output = work / "output"
        process = subprocess.run(
            [
                str(cli), "generate", "--target-type", "rootfs", "--target", str(target),
                "--target-id", "debian-upstream-source-regression", "--syft", str(syft),
                "--output", str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if process.returncode != 0:
            raise AssertionError("actual Syft Debian upstream source scan failed")

        document = json.loads((output / "sbom.cdx.json").read_text())
        errors = sorted(schema.iter_errors(document), key=lambda error: str(list(error.path)))
        if errors:
            details = "\n".join(f"{list(error.path)}: {error.message}" for error in errors)
            raise AssertionError(f"upstream source SBOM failed CycloneDX 1.5 schema:\n{details}")
        components = [
            component for component in document.get("components", [])
            if component.get("name") == PACKAGE_NAME
        ]
        if len(components) != 1:
            raise AssertionError("expected exactly one synthetic Debian binary package")
        component = components[0]
        if component.get("version") != PACKAGE_VERSION:
            raise AssertionError("Debian binary package epoch/tilde version was not retained")
        qualifiers = parse_qs(urlsplit(component.get("purl", "")).query, keep_blank_values=True)
        expected = f"{SOURCE_NAME}@{SOURCE_VERSION}"
        if qualifiers.get("upstream") != [expected]:
            raise AssertionError("Debian upstream name@version qualifier was not retained exactly")
        print("PASS actual Syft Debian upstream qualifier + CycloneDX 1.5 schema")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"FAIL actual Syft Debian upstream qualifier: {error}", file=sys.stderr)
        raise SystemExit(1)
