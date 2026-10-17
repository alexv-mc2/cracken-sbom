# cracken-sbom v1.1.0

Release description for the GitHub release. The release workflow is unchanged;
the signed assets are built and verified as described in
[RELEASE.md](RELEASE.md) and [VERIFICATION.md](VERIFICATION.md).

## New: firmware images

`generate --target-type firmware-image` takes a binary firmware image (for
example `firmware.bin` from a contractor who delivered no build inventory),
unpacks it **on your computer** with an extractor you install yourself, and
inventories the root filesystem it finds with the same Syft engine, settings
and minimized CycloneDX 1.5 output as the `rootfs` target.

```sh
pipx install unblob
./cracken-sbom generate \
  --target-type firmware-image --target firmware.bin \
  --target-id firmware-2026.10.17 \
  --syft /opt/verified-tools/syft \
  --extractor "$HOME/.local/bin/unblob" \
  --output /work/evidence/firmware-2026.10.17
```

- Supported extractors: [unblob](https://github.com/onekey-sec/unblob)
  (preferred) and [binwalk](https://github.com/ReFirmLabs/binwalk) 3. Both are
  MIT-licensed and run as separate processes; no extractor code is linked into
  the generator. The image never leaves your machine.
- `provenance.json` gains a `firmware` block: image file name, size and
  SHA-256, extractor kind, version and entry-file digest, extraction time, the
  selected root filesystem, file counts, entries that were not scanned, and
  whether the extractor reported errors.
- `sbom.cdx.json` carries the main facts as `cracken:firmware:*` metadata
  properties. It contains no extracted file lists and no paths of your machine.
- `quality.json` states that the inventory comes from a best-effort extraction.
- New flags: `--extractor`, `--extractor-kind unblob|binwalk`, `--work-dir`.
  They are rejected for all other target types, whose behavior is unchanged.

Tested with unblob 26.6.4 and binwalk 3.1.0 on four public OpenWrt 24.10.8
images (SquashFS and ext4 inside vendor containers, a gzip-compressed disk
image and a FIT image). See the README section "Firmware images".

## Limits (unchanged honesty rule)

Extraction is best effort. Encrypted content, formats the extractor does not
know and formats whose helper tool is missing are not unpacked. Statically
linked or stripped code carries no package metadata. Linux kernel modules appear
without versions, so such images need `--allow-incomplete`. Duplicate entries are
possible where the image keeps the same package list in two places. The
inventory does not establish completeness, absence of vulnerabilities or
regulatory conformity. The extractor and its helper tools run with your own
user rights; for images from sources you do not trust, run the command in a
virtual machine or container.

## Compatibility

No change to the existing target types, the pinned Syft version (1.54.0), the
output files or their schema.
