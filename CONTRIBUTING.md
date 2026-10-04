# Contributing

Changes should include focused tests for changed behavior and documentation
updates when they affect command usage or output. Keep changes formatted with
`gofmt` and run checks from the repository root.

The complete test suite requires Go, a verified Syft v1.54.0 executable,
and the pinned Python dependencies in `tests/requirements.txt`. After
provisioning those tools and dependencies, run:

```sh
SYFT=/absolute/path/to/verified/syft ./tests/run-tests.sh
```

See the [README](README.md#tests) for the full setup and optional tool paths.
