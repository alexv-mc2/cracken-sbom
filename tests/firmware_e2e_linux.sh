#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end check of the firmware-image target with a REAL extractor on Linux.
#
# Unlike tests/run-tests.sh (which uses tests/fake-extractor.sh), this runs the
# generator against a real OpenWrt image with real unblob and real sasquatch, and
# asserts the facts a user relies on. Everything it needs is passed in; it
# downloads nothing. CI provisions the inputs (see the firmware-linux-e2e job in
# .github/workflows/firmware-linux-e2e.yml); the same script runs on any Linux machine.
#
# Environment:
#   GENERATOR      built cracken-sbom executable (absolute path)
#   SYFT           authenticated Syft executable (absolute path)
#   UNBLOB         unblob executable (absolute path)
#   BINWALK        optional binwalk v3 executable; checked as a second extractor
#   IMAGE          OpenWrt image file (absolute path)
#   IMAGE_SHA256   expected SHA-256 of IMAGE
#   OUTPUT_ROOT    empty directory for outputs (default: a new temporary one)
#   PYTHON         python3 interpreter (default: python3)
set -euo pipefail

: "${GENERATOR:?}" "${SYFT:?}" "${UNBLOB:?}" "${IMAGE:?}" "${IMAGE_SHA256:?}"
PYTHON=${PYTHON:-python3}
if [[ "$(uname -s)" != Linux ]]; then
  echo 'This test needs Linux: sasquatch, the SquashFS helper, runs only there.' >&2
  exit 2
fi
if ! command -v sasquatch >/dev/null 2>&1; then
  echo 'sasquatch is not on PATH; the test would not exercise unblob SquashFS support.' >&2
  exit 2
fi
if [[ -z "${OUTPUT_ROOT:-}" ]]; then
  OUTPUT_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cracken-sbom-firmware-e2e.XXXXXX")
else
  mkdir -p "$OUTPUT_ROOT"
fi
if [[ -n "$(ls -A "$OUTPUT_ROOT")" ]]; then
  echo 'OUTPUT_ROOT must be empty.' >&2
  exit 1
fi

actual=$(sha256sum "$IMAGE" | cut -d' ' -f1)
if [[ "$actual" != "$IMAGE_SHA256" ]]; then
  echo "Image digest mismatch: expected $IMAGE_SHA256, got $actual" >&2
  exit 1
fi

extractors=(unblob)
[[ -n "${BINWALK:-}" ]] && extractors+=(binwalk)
for kind in "${extractors[@]}"; do
  case "$kind" in
    unblob) extractor=$UNBLOB ;;
    binwalk) extractor=$BINWALK ;;
  esac
  started=$SECONDS
  # --allow-incomplete is needed on every Linux image: kernel modules have no
  # package version, so the inventory is reported as incomplete.
  "$GENERATOR" generate --target-type firmware-image --target "$IMAGE" \
    --target-id "e2e-$kind" --syft "$SYFT" --extractor "$extractor" \
    --output "$OUTPUT_ROOT/$kind" --allow-incomplete \
    >"$OUTPUT_ROOT/$kind.stdout" 2>"$OUTPUT_ROOT/$kind.stderr" || {
    echo "FAIL: generate with $kind exited non-zero" >&2
    sed 's/^/  stderr: /' "$OUTPUT_ROOT/$kind.stderr" >&2
    exit 1
  }
  printf '%s run took %ds\n' "$kind" "$((SECONDS - started))"
done

"$PYTHON" -I - "$OUTPUT_ROOT" "$IMAGE" "$IMAGE_SHA256" "${extractors[@]}" <<'PY'
import json
import re
import sys
from pathlib import Path

root, image, image_sha256, *kinds = sys.argv[1:]
root = Path(root)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


# No leftover private extraction folder next to the outputs.
require(not list(root.glob(".cracken-sbom-extract-*")), "leftover .cracken-sbom-extract-* folder")

for kind in kinds:
    folder = root / kind
    sbom_text = (folder / "sbom.cdx.json").read_text()
    provenance_text = (folder / "provenance.json").read_text()
    quality_text = (folder / "quality.json").read_text()
    sbom = json.loads(sbom_text)
    provenance = json.loads(provenance_text)
    quality = json.loads(quality_text)

    # The user's machine must not leak into any uploadable or evidence file.
    for name, text in (("sbom", sbom_text), ("provenance", provenance_text), ("quality", quality_text)):
        for marker in ("/home", "/root", "/Users", "/var/folders", ".cracken-sbom-extract"):
            require(marker not in text, f"{kind}: {marker!r} found in {name}")

    fw = provenance.get("firmware", {})
    require(fw.get("source_type") == "firmware-image", f"{kind}: wrong source type")
    require(fw.get("image", {}).get("sha256") == image_sha256, f"{kind}: wrong image digest")
    require(fw["image"].get("file_name") == Path(image).name, f"{kind}: wrong image name")
    require(fw["image"].get("size_bytes") == Path(image).stat().st_size, f"{kind}: wrong image size")
    require(fw.get("extractor", {}).get("kind") == kind, f"{kind}: wrong extractor kind")
    require(re.fullmatch(r"[0-9]+(\.[0-9]+)+", fw["extractor"].get("version", "")), f"{kind}: bad extractor version")
    require(fw.get("extracted_file_count", 0) > 500, f"{kind}: too few extracted files")
    require("squashfs" in fw.get("selected_root", ""), f"{kind}: root is not the SquashFS")

    properties = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    firmware_properties = {k: v for k, v in properties.items() if k.startswith("cracken:firmware:")}
    required_properties = {
        "source-type", "image-name", "image-size-bytes", "image-sha256", "extractor", "extractor-version",
        "extracted-at", "selected-root", "extracted-file-count", "unused-entry-count",
        "other-root-candidates", "extractor-reported-errors",
    }
    missing = {f"cracken:firmware:{n}" for n in required_properties} - set(firmware_properties)
    require(not missing, f"{kind}: missing properties {sorted(missing)}")
    require(properties["cracken:firmware:image-sha256"] == image_sha256, f"{kind}: property digest")
    require(properties["cracken:firmware:extractor"] == kind, f"{kind}: property extractor")

    components = sbom.get("components", [])
    names = {c["name"] for c in components}
    # Reference value: 375 components (unblob 26.6.4, binwalk 3.1.0, Syft from engine-manifest.json).
    require(len(components) >= 300, f"{kind}: only {len(components)} components")
    # OpenWrt base packages that every sysupgrade image of this release carries.
    for expected in ("busybox", "base-files", "dropbear", "libc", "uci", "netifd"):
        require(expected in names, f"{kind}: component {expected!r} missing")
    busybox = [c for c in components if c["name"] == "busybox"]
    require(any(c.get("version", "").startswith("1.36") for c in busybox), f"{kind}: busybox version not 1.36.x")

    require(any("best-effort extraction" in w for w in quality.get("warnings", [])), f"{kind}: extraction warning missing")
    print(f"PASS {kind}: {len(components)} components, root {fw['selected_root']}, {fw['extracted_file_count']} files")
PY
printf 'PASS firmware-image end-to-end on Linux; evidence: %s\n' "$OUTPUT_ROOT"
