# Detect fixtures

Synthetic folders for `cracken-sbom detect` cases that build no SBOM. They hold
names only, no real build output or downloaded code.

| Folder | detect says | Exit code |
|---|---|---|
| `yocto-build` | a Yocto build folder; points to the build's own SPDX SBOM and `docs/YOCTO.md` | 0 |
| `dockerfile-only` | a Dockerfile; explains `docker save` and running detect on the archive | 0 |
| `nothing` | nothing it can list | 1 |

The cases that do build an SBOM reuse `fixtures/npm`, `fixtures/dir`,
`fixtures/rootfs`, `fixtures/python` and the archives `tests/make-archives.py`
creates; see `tests/e2e/detect.sh`.
