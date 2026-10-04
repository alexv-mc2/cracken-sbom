# Vendored test schemas

Unmodified official CycloneDX specification tag `1.5` files, Apache-2.0:

- https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json
- https://github.com/CycloneDX/specification/blob/1.5/schema/spdx.schema.json
- https://github.com/CycloneDX/specification/blob/1.5/schema/jsf-0.82.schema.json
- https://github.com/CycloneDX/specification/blob/1.5/LICENSE

SHA256SUMS binds the exact checked-in bytes. `validate-schema.py` validates
these hashes first and resolves all schema references from a local registry;
it cannot download references. `spdx.schema.json` is also embedded in the CLI to
select the valid `license.id` representation at runtime; a sole safe newer ID
uses `expression` with a quality warning. Incompatible mixed expression choices
are omitted and counted in `quality.json`. These schemas are
not a vendored scanning engine. Source acquired on 2026-10-04.
