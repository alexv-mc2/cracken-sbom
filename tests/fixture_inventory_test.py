#!/usr/bin/env python3
"""Assert exact package inventories from the real Syft fixture scans."""
import hashlib
import json
import os
from pathlib import Path
import sys


EXPECTED_FIRMWARE = [
    {
        "name": "busybox",
        "version": "1:1.35.0-4+b3",
        "purl": "pkg:deb/debian/busybox@1%3A1.35.0-4%2Bb3?arch=arm64&distro=debian-12",
    },
    {"name": "debian", "version": "12", "purl": None},
    {
        "name": "libssl3",
        "version": "3.0.11-1~deb12u2",
        "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=arm64&distro=debian-12",
    },
]

EXPECTED = {
    "npm": [
        {"name": "is-number", "version": "7.0.0", "purl": "pkg:npm/is-number@7.0.0"},
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    ],
    "python": [
        {"name": "alpha-fixture", "version": "1.2.3", "purl": "pkg:pypi/alpha-fixture@1.2.3"},
        {"name": "beta-fixture", "version": "4.5.6", "purl": "pkg:pypi/beta-fixture@4.5.6"},
    ],
    "rootfs": EXPECTED_FIRMWARE,
    "docker-archive": EXPECTED_FIRMWARE,
    "oci-archive": EXPECTED_FIRMWARE,
    "firmware-image": EXPECTED_FIRMWARE,
}

FORBIDDEN_MARKERS = (
    "/Users/",
    "/home/",
    "site-packages/",
    "node_modules/",
    "var/lib/dpkg",
    "METADATA",
    "RECORD",
    "file://",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_firmware(folder: Path, sbom_text: str, provenance: dict, quality: dict) -> None:
    fw = provenance.get("firmware", {})
    image = (folder.parent / "archives" / "image.bin").read_bytes()
    require(fw.get("source_type") == "firmware-image", "firmware: wrong source type")
    require(fw.get("image") == {"file_name": "image.bin", "size_bytes": len(image), "sha256": hashlib.sha256(image).hexdigest()}, "firmware: wrong image facts")
    require(fw.get("extractor", {}).get("kind") == "unblob" and fw["extractor"].get("version") == "0.0.1", "firmware: wrong extractor facts")
    require(fw.get("selected_root") == "image.bin_extract/512-4096.squashfs_extract", "firmware: wrong selected root")
    require(fw.get("unused_entries") == ["image.bin_extract/0-512.unknown"], "firmware: wrong unused entries")
    require(fw.get("extracted_file_count") == 2 and fw.get("extractor_reported_errors") is False, "firmware: wrong extraction counts")
    properties = {p["name"]: p["value"] for p in json.loads(sbom_text)["metadata"]["properties"]}
    require(properties.get("cracken:firmware:image-sha256") == hashlib.sha256(image).hexdigest(), "firmware: SBOM property missing")
    require(properties.get("cracken:firmware:extractor") == "unblob", "firmware: extractor property missing")
    require(any("best-effort extraction" in w for w in quality.get("warnings", [])), "firmware: extraction warning missing")
    require("0-512.unknown" not in sbom_text, "firmware: extracted entry names leaked into the SBOM")


def main() -> None:
    output_value = os.environ.get("CRACKEN_SBOM_TEST_OUTPUT")
    require(bool(output_value), "CRACKEN_SBOM_TEST_OUTPUT must point to generated fixture outputs")
    output = Path(output_value)
    for target, expected in EXPECTED.items():
        folder = output / target
        sbom_bytes = (folder / "sbom.cdx.json").read_bytes()
        text = sbom_bytes.decode()
        document = json.loads(text)
        require(document.get("bomFormat") == "CycloneDX", f"{target}: wrong SBOM format")
        require(document.get("specVersion") == "1.5", f"{target}: wrong SBOM version")
        actual = sorted(
            (
                {key: component.get(key) for key in ("name", "version", "purl")}
                for component in document.get("components", [])
            ),
            key=lambda component: component["name"],
        )
        require(actual == expected, f"{target}: unexpected exact package inventory: {actual!r}")
        for marker in FORBIDDEN_MARKERS:
            require(marker not in text, f"{target}: local file marker leaked: {marker}")

        provenance = json.loads((folder / "provenance.json").read_text())
        digest = hashlib.sha256(sbom_bytes).hexdigest()
        require(provenance.get("sbom_sha256") == digest, f"{target}: digest does not bind final SBOM bytes")
        require(provenance.get("engine") == {"name": "syft", "version": "1.54.0"}, f"{target}: wrong engine identity")
        require(provenance.get("generator", {}).get("name") == "cracken-sbom", f"{target}: wrong generator identity")
        require(provenance.get("target") == {"identifier": f"fixture-{target}", "type": target}, f"{target}: wrong safe target assertion")
        require(provenance.get("provenance_status") == "customer_asserted_local", f"{target}: wrong provenance status")
        require(provenance.get("timestamp_source") == "local_machine_clock", f"{target}: wrong timestamp source")
        require(len(provenance.get("configuration_sha256", "")) == 64, f"{target}: invalid configuration digest")
        for sidecar_name in ("provenance.json", "quality.json"):
            sidecar_text = (folder / sidecar_name).read_text()
            for marker in FORBIDDEN_MARKERS:
                require(marker not in sidecar_text, f"{target}/{sidecar_name}: local file marker leaked: {marker}")
        quality = json.loads((folder / "quality.json").read_text())
        require(quality.get("emitted_components") == len(expected), f"{target}: quality count disagrees with inventory")
        require(quality.get("missing_versions") == 0, f"{target}: fixture package version was lost")
        require(provenance.get("quality") == quality, f"{target}: provenance quality sidecar disagrees")
        if target == "firmware-image":
            check_firmware(folder, text, provenance, quality)
        print(f"PASS actual Syft fixture inventory: {target}")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"FAIL generated fixture inventory: {error}", file=sys.stderr)
        raise SystemExit(1)
