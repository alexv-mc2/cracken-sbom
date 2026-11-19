# Yocto SPDX fixtures

Authored, minimal documents in the layout OpenEmbedded's `create-spdx`
classes write. They are synthetic: no build output, package or source is
included.

- `spdx2/`: a Scarthgap-style SPDX 2.2 image document set. The image document
  `CONTAINS` `busybox` and `libz1` from their package documents; each package
  is `GENERATED_FROM` a recipe document. `recipe-busybox` lists
  `CVEs fixed: CVE-2022-28391 CVE-2022-30065 CVE-2023-42364`. `index.json` is
  not an SPDX document and is ignored. The e2e test also packs this directory
  as a `.spdx.tar.zst` when `zstd` is available.
- `spdx3/`: a Wrynose-style SPDX 3.0.1 `*.rootfs.spdx.json`. The image contains
  `busybox`, `libz1`, `libssl3` and `quilt-native` (a build-host package that
  must be skipped); `not-in-image` is not reachable and must be skipped. VEX:
  CVE-2023-42364 fixed and CVE-2023-42363 not affected (busybox recipe),
  CVE-2024-0727 affected (openssl), CVE-2022-37434 fixed (zlib), and
  CVE-2023-45853 not affected but withdrawn on 2026-01-01, so it must not appear.
