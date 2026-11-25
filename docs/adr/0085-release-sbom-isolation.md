# ADR 0085 — Isolate release inventory generation from signing

Generate the release SBOM on a separate macOS runner with read-only repository
access. Check out the dispatched commit and use the release Rust toolchain.
The inventory job may read source and upload its SPDX document. Only the
protected release job receives signing material and publication permissions.

The release job validates the requested commit against the dispatched commit
and downloads the inventory by the artifact ID from its prerequisite job in
the same workflow run. It treats the document as data. A generator can still
misreport dependencies, so the inventory job checks the assembled document
before upload.
