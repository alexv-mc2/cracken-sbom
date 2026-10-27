#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real Syft version-string detection and its documented limits."""
from pathlib import Path
import json
import shutil
import subprocess
import sys


DETECTION_PROPERTY = {"name": "cracken:detection:method", "value": "version-string"}


def run(command, env):
    try:
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out after 120 seconds: {Path(command[0]).name}") from None
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {Path(command[0]).name}")


def write_stub(path, *strings):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"\x7fELF\x02\x01\x01" + b"\0" * 57
    for string in strings:
        data += b"\0" * 64 + string + b"\0"
    path.write_bytes(data + b"\0" * 512)
    path.chmod(0o755)


def identities(document):
    return {
        (component.get("type"), component.get("name"), component.get("version"), component.get("purl"))
        for component in document.get("components", [])
    }


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: version_string_test.py CRACKEN_SBOM SYFT FIXTURE_DIR OUTPUT_DIR")
    cracken, syft, fixtures, output = map(Path, sys.argv[1:])
    if not cracken.is_absolute() or not syft.is_absolute():
        raise SystemExit("tool and Syft paths must be absolute")
    fixtures, output = fixtures.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise SystemExit("version-string test output must be empty")
    runtime_home = output / "runtime"
    runtime_home.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(runtime_home),
        "XDG_CONFIG_HOME": str(runtime_home),
        "XDG_CACHE_HOME": str(runtime_home),
        "TMPDIR": str(runtime_home),
        "LANG": "C",
        "LC_ALL": "C",
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "NO_PROXY": "",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
    }

    def inventory(target, label):
        destination = output / f"output-{label}"
        run(
            [str(cracken), "generate", "--target-type", "rootfs", "--target", str(target),
             "--target-id", f"fixture-version-string-{label}", "--syft", str(syft),
             "--output", str(destination)],
            env,
        )
        for path in destination.rglob("*"):
            if path.is_file() and str(output).encode() in path.read_bytes():
                raise AssertionError(f"temporary absolute path leaked into {path.name}")
        return (
            json.loads((destination / "sbom.cdx.json").read_text()),
            json.loads((destination / "quality.json").read_text()),
        )

    baseline_rootfs = output / "baseline-rootfs"
    binary_rootfs = output / "binary-rootfs"
    removed_version_rootfs = output / "removed-version-rootfs"
    for target in (baseline_rootfs, binary_rootfs, removed_version_rootfs):
        shutil.copytree(fixtures / "rootfs", target)
    baseline, baseline_quality = inventory(baseline_rootfs, "baseline")
    baseline_components = baseline.get("components", [])
    if len(baseline_components) != 3:
        raise AssertionError("base rootfs fixture must emit exactly 3 components")
    if baseline_quality.get("version_string_components") != 0:
        raise AssertionError("base fixture must have zero version-string components")
    if {c.get("name") for c in baseline_components} != {"busybox", "libssl3", "debian"}:
        raise AssertionError("base fixture must contain dpkg busybox, libssl3 and the OS")
    if any(c.get("properties") for c in baseline_components):
        raise AssertionError("base fixture components must have no detection properties")

    write_stub(binary_rootfs / "bin/busybox", b"BusyBox v1.36.1 (2023-11-07 18:53:09 UTC)")
    write_stub(binary_rootfs / "usr/bin/openssl", b"OpenSSL 3.0.13 30 Jan 2024")
    write_stub(binary_rootfs / "usr/bin/curl", b"curl/8.5.0", b"libcurl/8.5.0")
    # Syft v1.54.0 has no classifiers for these common firmware components.
    write_stub(binary_rootfs / "usr/lib/libz.so.1.2.13",
               b"deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler")
    write_stub(binary_rootfs / "usr/sbin/dropbear", b"Dropbear sshd v2022.83")
    detected, quality = inventory(binary_rootfs, "binaries")
    components = detected.get("components", [])
    if len(components) != 6:
        raise AssertionError("rootfs with binary stubs must emit exactly 6 components")
    expected = {("busybox", "1.36.1"), ("openssl", "3.0.13"), ("curl", "8.5.0")}
    marked = [c for c in components if DETECTION_PROPERTY in c.get("properties", [])]
    if {(c.get("name"), c.get("version")) for c in marked} != expected or len(marked) != 3:
        raise AssertionError("expected exactly busybox 1.36.1, openssl 3.0.13 and curl 8.5.0 marked")
    if any(c.get("properties") != [DETECTION_PROPERTY] for c in marked):
        raise AssertionError("binary components must carry exactly the safe detection property")
    unmarked = [c for c in components if c not in marked]
    if identities({"components": unmarked}) != identities(baseline):
        raise AssertionError("binary stubs changed the original dpkg or OS component identities")
    if any(c.get("properties") for c in unmarked):
        raise AssertionError("dpkg busybox/libssl3 and OS components must have no detection property")
    if any(c.get("name", "").lower() in {"zlib", "libz", "dropbear"} for c in components):
        raise AssertionError("Syft v1.54.0 unexpectedly detected a zlib or Dropbear stub")
    if quality.get("version_string_components") != 3:
        raise AssertionError("quality must count exactly 3 version-string components")
    print(f"PASS actual Syft version-string inventory: before={len(baseline_components)} after={len(components)} components")
    print("PASS BusyBox, OpenSSL and curl detection properties; dpkg and OS components unmarked; quality count=3")
    print("PASS documented Syft v1.54.0 limit: zlib and Dropbear stubs are not recognised")

    write_stub(removed_version_rootfs / "bin/busybox", b"BusyBox")
    removed_version, removed_quality = inventory(removed_version_rootfs, "removed-version")
    if identities(removed_version) != identities(baseline) or len(removed_version.get("components", [])) != 3:
        raise AssertionError("BusyBox without its version string must produce no binary component")
    if removed_quality.get("version_string_components") != 0:
        raise AssertionError("removed-version fixture must have zero version-string components")
    print("PASS BusyBox without a version string produces no binary component")
    print("PASS no temporary absolute paths in any generated output file")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"FAIL actual Syft version-string detection: {error}", file=sys.stderr)
        raise SystemExit(1)
