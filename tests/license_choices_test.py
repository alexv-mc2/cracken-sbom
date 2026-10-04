#!/usr/bin/env python3
"""Exercise real Syft license choices and validate normalized CycloneDX 1.5."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


def make_jar(path: Path, artifact: str, licenses: list[tuple[str, str]]) -> None:
    license_xml = "".join(
        f"<license><name>{name}</name><url>{url}</url></license>"
        for name, url in licenses
    )
    pom = (
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>example</groupId>"
        f"<artifactId>{artifact}</artifactId>"
        "<version>1.0.0</version>"
        f"<licenses>{license_xml}</licenses></project>"
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as jar:
        files = {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
            f"META-INF/maven/example/{artifact}/pom.properties": (
                f"groupId=example\nartifactId={artifact}\nversion=1.0.0\n"
            ).encode(),
            f"META-INF/maven/example/{artifact}/pom.xml": pom,
        }
        for name, contents in files.items():
            item = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            jar.writestr(item, contents)


def schema_validator(schema_dir: Path) -> Draft7Validator:
    for line in (schema_dir / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        actual = hashlib.sha256((schema_dir / name).read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"vendored schema checksum mismatch: {name}")
    resources = []
    for name in ("bom-1.5.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        schema = json.loads((schema_dir / name).read_text())
        resource = Resource.from_contents(schema, default_specification=DRAFT7)
        resources.extend([
            (schema["$id"], resource),
            ("http://cyclonedx.org/schema/" + name, resource),
        ])
    registry = Registry().with_resources(resources)
    return Draft7Validator(
        json.loads((schema_dir / "bom-1.5.schema.json").read_text()),
        registry=registry,
    )


def run_case(
    cli: Path,
    syft: Path,
    schema: Draft7Validator,
    work: Path,
    name: str,
    licenses: list[tuple[str, str]],
    expected_licenses: list[dict] | None,
    expected_quality: dict,
    expected_warning: str,
) -> None:
    target = work / f"target-{name}"
    make_jar(target / f"{name}.jar", name, licenses)
    output = work / f"output-{name}"
    process = subprocess.run(
        [
            str(cli), "generate", "--target-type", "rootfs", "--target", str(target),
            "--target-id", f"license-{name}", "--syft", str(syft), "--output", str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if process.returncode != 0:
        raise AssertionError(f"{name}: actual CLI generation failed: {process.stderr.strip()}")
    document = json.loads((output / "sbom.cdx.json").read_text())
    errors = sorted(schema.iter_errors(document), key=lambda error: str(list(error.path)))
    if errors:
        details = "\n".join(f"{list(error.path)}: {error.message}" for error in errors)
        raise AssertionError(f"{name}: normalized SBOM failed CycloneDX 1.5 schema:\n{details}")
    components = [component for component in document["components"] if component["name"] == name]
    if len(components) != 1:
        raise AssertionError(f"{name}: expected exactly one JAR component, got {len(components)}")
    if components[0].get("licenses") != expected_licenses:
        raise AssertionError(
            f"{name}: unexpected normalized choices {components[0].get('licenses')!r}; "
            f"expected {expected_licenses!r}"
        )
    quality = json.loads((output / "quality.json").read_text())
    for field, expected in expected_quality.items():
        if quality.get(field) != expected:
            raise AssertionError(f"{name}: {field}={quality.get(field)!r}, expected {expected!r}")
    warnings = " ".join(quality.get("warnings", [])).lower()
    if expected_warning.lower() not in warnings:
        raise AssertionError(f"{name}: expected quality warning was absent: {expected_warning}")
    print(f"PASS real Syft license choices + CycloneDX 1.5 schema: {name}")


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: license_choices_test.py CRACKEN_SBOM SYFT SCHEMA_DIR")
    cli, syft, schema_dir = map(Path, sys.argv[1:])
    schema = schema_validator(schema_dir)
    mit = ("MIT", "https://spdx.org/licenses/MIT.html")
    unicode = ("Unicode-3.0", "https://spdx.org/licenses/Unicode-3.0.html")
    fsl = ("FSL-1.1-MIT", "https://spdx.org/licenses/FSL-1.1-MIT.html")
    with tempfile.TemporaryDirectory(prefix="cracken-sbom-license-choices-") as temporary:
        work = Path(temporary)
        run_case(
            cli, syft, schema, work, "unicode-only", [unicode],
            [{"expression": "Unicode-3.0"}],
            {"converted_license_ids": 1, "omitted_license_choices": 0, "missing_licenses": 0},
            "preserved as a license expression",
        )
        run_case(
            cli, syft, schema, work, "mit-and-unicode", [mit, unicode],
            [{"license": {"id": "MIT"}}],
            {"converted_license_ids": 0, "omitted_license_choices": 1, "missing_licenses": 0},
            "unsupported SPDX identifiers were omitted",
        )
        run_case(
            cli, syft, schema, work, "newer-identifiers", [unicode, fsl],
            None,
            {"converted_license_ids": 0, "omitted_license_choices": 2, "missing_licenses": 1},
            "unsupported SPDX identifiers were omitted",
        )


if __name__ == "__main__":
    main()
