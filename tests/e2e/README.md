# Extension end-to-end tests

`tests/run-tests.sh` runs every `tests/e2e/*.sh` with `bash`, after the
built-in fixtures and before the schema, TR-03183 value, cyclonedx-cli and
sbomqs checks. A new target type or subcommand adds its own script here; no
other test file needs an edit.

Environment each script receives (all absolute paths):

| Variable | Meaning |
|---|---|
| `CRACKEN_SBOM_BIN` | the freshly built CLI |
| `SYFT` | the authenticated Syft 1.55.0 binary |
| `PYTHON` | Python with the pinned test requirements |
| `SBOMQS` | sbomqs v2.1.3 |
| `CYCLONEDX_CLI` | cyclonedx-cli v0.33.1 (`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` is set) |
| `CRACKEN_SBOM_TEST_OUTPUT` | the run's output folder |

Rules:

- Write outputs only to new folders below `$CRACKEN_SBOM_TEST_OUTPUT`, one per
  case. Every `sbom.cdx.json` and `*.vex.cdx.json` there is then validated
  automatically against the CycloneDX 1.6 schema, `tests/tr_check.py`,
  cyclonedx-cli and sbomqs `--bsi-v21`.
- Run offline: CI executes the suite under `unshare --net`.
- Exit non-zero on failure and print one `PASS ...` line per checked case.
