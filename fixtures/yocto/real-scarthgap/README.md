# Real Yocto Scarthgap SPDX 2.2 image archive

`core-image-minimal-stm32mp25-eval.spdx.tar.zst` is real `create-spdx-2.2`
output of a Yocto Scarthgap 5.0 build (`core-image-minimal` for the
`stm32mp25-eval` machine), unchanged:

- Source: https://github.com/savoirfairelinux/vulnscout, commit
  `89bca1fd09b204620251ef8b7f9455d3689880d1`,
  `example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.spdx.tar.zst`
- SHA-256: `b41b56a8e7f5bf72e3f1c6245bfeec3316c6481d2c2e5afc110a4d10f433b0de`
- Licence: each of the 203 SPDX documents in the archive declares
  `"dataLicense": "CC0-1.0"` (SPDX 2.2 requires CC0-1.0 for SPDX document
  data). Only this data file is used; no vulnscout code (GPL-3.0-only) is
  copied. The remaining entry is the archive's `index.json`.

It contains cross-document licence references such as
`DocumentRef-recipe-busybox:LicenseRef-bzip2-1.0.4` and recipe `sourceInfo`
"CVEs fixed" lists. `tests/e2e/yocto.sh` places it in a deploy directory the
way BitBake does (dated archive plus an `IMAGE_LINK_NAME` link) and expects
38 components and 28 `resolved` VEX statements, all referring to SBOM
bom-refs.
