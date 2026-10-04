#!/usr/bin/env python3
"""Keep binary inventory evidence while removing the build runner's file path."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

binary, sbom, archive = map(Path, sys.argv[1:4])
epoch = int(sys.argv[4])
data = binary.read_bytes()
digest = hashlib.sha256(data).hexdigest()
inventory = json.loads(sbom.read_text())
matching_files = []
for component in inventory.get("components", []):
    if component.get("type") == "file":
        hashes = {item["alg"]: item["content"] for item in component.get("hashes", [])}
        if hashes.get("SHA-256") != digest:
            raise SystemExit("Unexpected file in binary inventory")
        component["name"] = "cracken-sbom"
        matching_files.append(component)
if not matching_files:
    raise SystemExit("Binary inventory did not bind the exact binary SHA-256")
if not any(c.get("name") == "stdlib" for c in inventory.get("components", [])):
    raise SystemExit("Binary inventory did not detect the Go standard library")
sbom.write_text(json.dumps(inventory, indent=2) + "\n")
# Fixed ownership, permissions, timestamp and gzip metadata make archives reproducible.
with archive.open("wb") as out:
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, content, mode in [
                ("cracken-sbom", data, 0o755),
                ("LICENSE", Path("LICENSE").read_bytes(), 0o644),
                ("NOTICE", Path("NOTICE").read_bytes(), 0o644),
            ]:
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                entry.mode = mode
                entry.mtime = epoch
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                tar.addfile(entry, io.BytesIO(content))
