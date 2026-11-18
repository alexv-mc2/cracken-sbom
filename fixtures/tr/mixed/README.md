# Mixed lockfile fixture

A root `package-lock.json` v3 (the same packages as `fixtures/tr/npm`) next to
a Python environment the lockfile does not describe
(`venv/.../gamma_fixture-2.0.0.dist-info`). Scanned as `--target-type npm`,
only the four npm packages may be marked `complete`; `gamma-fixture` and the
product must not be. Synthetic metadata only; nothing is installed.
