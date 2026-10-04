#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Syft's real rootfs boundary with an external package canary."""
from pathlib import Path
import json
import shutil
import subprocess
import sys


def package_purls(document):
    return {
        ref
        for component in document.get("components", [])
        for ref in component.get("purl", "").splitlines()
        if ref.startswith("pkg:deb/")
    }


def component_identities(document):
    return {
        (component.get("type"), component.get("name"), component.get("version"), component.get("purl"))
        for component in document.get("components", [])
    }


def run(command, env):
    try:
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out after 120 seconds: {Path(command[0]).name}") from None
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {Path(command[0]).name}")
    return result.stdout


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: rootfs_absolute_symlink_test.py CRACKEN_SYFT SYFT FIXTURE_DIR OUTPUT_DIR")
    cracken, syft, fixtures, output = map(Path, sys.argv[1:])
    if not cracken.is_absolute() or not syft.is_absolute():
        raise SystemExit("tool and Syft paths must be absolute")
    fixtures, output = fixtures.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = output / "rootfs-absolute-symlink"
    if work.exists() and any(work.iterdir()):
        raise SystemExit("rootfs-absolute-symlink test output must be empty")
    work.mkdir(exist_ok=True)

    runtime_home = work / "runtime"
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
    # A normal synthetic status database outside rootfs is the non-vacuous
    # control. The production CLI must see this unique host-side package when
    # it is scanned as a rootfs on its own.
    canary = work / "host-package-db"
    (canary / "etc").mkdir(parents=True)
    (canary / "var/lib/dpkg").mkdir(parents=True)
    (canary / "etc/os-release").write_text(
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
        'VERSION_ID="12"\nID=debian\nID_LIKE=debian\n'
    )
    (canary / "var/lib/dpkg/status").write_text(
        "Package: cracken-fixture-host-package-canary\n"
        "Status: install ok installed\n"
        "Priority: optional\nSection: misc\nArchitecture: all\n"
        "Version: 9.8.7\nDescription: Synthetic external host package canary\n\n"
    )
    def cracken_inventory(target, label):
        destination = work / f"output-{label}"
        run(
            [str(cracken), "generate", "--target-type", "rootfs", "--target", str(target),
             "--target-id", f"fixture-rootfs-{label}", "--syft", str(syft),
             "--output", str(destination)],
            env,
        )
        return json.loads((destination / "sbom.cdx.json").read_text())

    direct = cracken_inventory(canary, "host-canary-control")
    canary_components = {
        component.get("name"): component
        for component in direct.get("components", [])
        if component.get("name") == "cracken-fixture-host-package-canary"
    }
    if len(canary_components) != 1:
        raise AssertionError("CLI positive control did not detect the external canary")

    baseline_rootfs = work / "ordinary-rootfs"
    escape_rootfs = work / "absolute-symlink-rootfs"
    shutil.copytree(fixtures / "rootfs-absolute-symlink", baseline_rootfs)
    shutil.copytree(fixtures / "rootfs-absolute-symlink", escape_rootfs)
    status = escape_rootfs / "var/lib/dpkg/status"
    status.unlink()
    host_status = (canary / "var/lib/dpkg/status").resolve()
    # Keep the ordinary package records at the symlink's re-rooted location
    # inside the rootfs. With --base-path, Syft can resolve the absolute link
    # against this in-root shadow; following it on the host would instead read
    # the distinct canary database above.
    shadow_status = escape_rootfs / str(host_status).lstrip("/")
    shadow_status.parent.mkdir(parents=True)
    shutil.copyfile(baseline_rootfs / "var/lib/dpkg/status", shadow_status)
    status.symlink_to(host_status)

    baseline = cracken_inventory(baseline_rootfs, "ordinary")
    escaped = cracken_inventory(escape_rootfs, "absolute-symlink")
    expected = package_purls(baseline)
    actual = package_purls(escaped)
    if expected != {
        "pkg:deb/debian/busybox@1%3A1.35.0-4%2Bb3?arch=arm64&distro=debian-12",
        "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=arm64&distro=debian-12",
    }:
        raise AssertionError("ordinary fixture did not yield its exact two Debian package identities")
    if actual != expected or component_identities(escaped) != component_identities(baseline):
        raise AssertionError("absolute dpkg-status symlink changed the exact rootfs component inventory")
    if "cracken-fixture-host-package-canary" in {c.get("name") for c in escaped.get("components", [])}:
        raise AssertionError("external host package canary escaped the rootfs boundary")
    print("PASS actual Syft rootfs absolute-symlink boundary; CLI canary detected and excluded")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"FAIL actual Syft rootfs absolute-symlink boundary: {error}", file=sys.stderr)
        raise SystemExit(1)
