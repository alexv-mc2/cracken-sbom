#!/usr/bin/env python3
"""Provision the exact authenticated Syft engine; never install globally.

This is a network-enabled installation step, separate from offline generation.
Python 3.8+, curl, and a separately trusted cosign >=2.5 are required. Cached
upstream verification material can be used with --offline, including all four
platform archives with --all-platforms. Sigstore trust-root initialization may
require network independently of archive downloads; provision it beforehand.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require_hash(path, expected):
    actual = digest(path)
    if actual != expected:
        raise ValueError("SHA-256 mismatch for " + path.name)
    print("SHA-256 verified: " + path.name + " " + actual, flush=True)


def fetch(cache, name, expected, version, offline):
    target = cache / name
    if not target.exists():
        if offline:
            raise ValueError("Offline cache is missing " + name)
        url = "https://github.com/anchore/syft/releases/download/v" + version + "/" + name
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as partial:
            temporary = Path(partial.name)
        try:
            subprocess.run([
                "curl", "--fail", "--location", "--silent", "--show-error",
                "--proto", "=https", "--proto-redir", "=https", url,
                "--output", str(temporary),
            ], check=True)
            require_hash(temporary, expected)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    require_hash(target, expected)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--destination", type=Path,
                        help="Exact output executable path; no global installation")
    parser.add_argument("--cosign", default=os.environ.get("COSIGN", "cosign"))
    parser.add_argument("--platform", choices=["linux_amd64", "linux_arm64",
                                               "darwin_amd64", "darwin_arm64"])
    parser.add_argument("--all-platforms", action="store_true")
    parser.add_argument("--offline", action="store_true",
                        help="Do not download archives or signature material")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if not args.verify_only and args.destination is None:
        parser.error("--destination is required unless --verify-only is set")
    manifest = json.loads((Path(__file__).resolve().parent.parent /
                           "engine-manifest.json").read_text(encoding="utf-8"))
    host = platform.system().lower() + "_" + {
        "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"
    }.get(platform.machine().lower(), platform.machine().lower())
    selected = args.platform or host
    if selected not in manifest["binary_sha256"]:
        raise ValueError("Unsupported platform: " + selected)
    if not args.verify_only and selected != host:
        raise ValueError("Installation must match the running host platform")
    version_result = subprocess.run([args.cosign, "version"], check=True,
                                    capture_output=True, text=True)
    version_output = version_result.stdout + version_result.stderr
    match = re.search(r"GitVersion:\s+v?(\d+)\.(\d+)\.(\d+)", version_output)
    if match is None or tuple(map(int, match.groups())) < (2, 5, 0):
        raise ValueError("A separately trusted cosign >=2.5 is required")
    print("cosign version: " + ".".join(match.groups()), flush=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    version = manifest["version"]
    checksums = fetch(args.cache, "syft_" + version + "_checksums.txt",
                      manifest["checksum_manifest_sha256"], version, args.offline)
    bundle = fetch(args.cache, checksums.name + ".sigstore.json",
                   manifest["sigstore_bundle_sha256"], version, args.offline)
    command = [args.cosign, "verify-blob", "--bundle", str(bundle),
               "--certificate-identity", manifest["certificate_identity"],
               "--certificate-oidc-issuer", manifest["certificate_oidc_issuer"],
               str(checksums)]
    if args.offline:
        command.insert(2, "--offline")
    print("Authenticating signed checksum manifest: " + " ".join(command), flush=True)
    subprocess.run(command, check=True)
    authenticated = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2:
            raise ValueError("Malformed checksum manifest entry")
        value, name = fields
        if name in authenticated:
            raise ValueError("Duplicate checksum entry: " + name)
        authenticated[name] = value
    selected_platforms = sorted(manifest["binary_sha256"]) if args.all_platforms else [selected]
    for target_platform in selected_platforms:
        name = "syft_" + version + "_" + target_platform + ".tar.gz"
        expected = manifest["archive_sha256"][target_platform]
        if authenticated.get(name) != expected:
            raise ValueError("Pinned archive hash differs from signed manifest: " + name)
        archive = fetch(args.cache, name, expected, version, args.offline)
        with tarfile.open(archive, "r:gz") as source:
            members = [item for item in source.getmembers() if item.name == "syft"]
            if len(members) != 1 or not members[0].isfile() or members[0].size > 256 * 1024 * 1024:
                raise ValueError("Archive must contain exactly one regular syft executable")
            # Read only the named executable, never extract arbitrary archive paths.
            binary = source.extractfile(members[0]).read()
        binary_hash = hashlib.sha256(binary).hexdigest()
        if binary_hash != manifest["binary_sha256"][target_platform]:
            raise ValueError("Extracted binary hash mismatch: " + target_platform)
        print("Binary verified: " + target_platform + " " + binary_hash, flush=True)
        if not args.verify_only and target_platform == selected:
            args.destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=args.destination.parent, delete=False) as output:
                temporary = Path(output.name)
                output.write(binary)
            try:
                temporary.chmod(0o755)
                result = subprocess.run([str(temporary.resolve()), "version"],
                                        check=True, capture_output=True, text=True)
                if not re.search(r"^Version:\s+" + re.escape(version) + r"\s*$",
                                 result.stdout, re.MULTILINE):
                    raise ValueError("Verified engine reports unexpected version")
                os.replace(temporary, args.destination)
            finally:
                temporary.unlink(missing_ok=True)
            print("Provisioned: " + str(args.destination.resolve()), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print("Syft provisioning failed: " + str(error), file=sys.stderr)
        sys.exit(1)
