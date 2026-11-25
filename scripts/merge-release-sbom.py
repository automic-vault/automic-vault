"""Assemble the release SPDX document from the pinned Rust and Swift scanners."""

import json
import sys
import uuid
from pathlib import Path


def described_package(document):
    root, = (edge["relatedSpdxElement"] for edge in document["relationships"]
             if edge["relationshipType"] == "DESCRIBES"
             and edge["spdxElementId"] == "SPDXRef-DOCUMENT")
    return root


rust = json.loads(Path("target/sbom-rust.spdx.json").read_text())
swift = json.loads(Path("target/sbom-swift.spdx.json").read_text())
product = described_package(rust)
directory = described_package(swift)

# cargo tree prints "name vVERSION", optionally followed by a source or (*).
runtime = {tuple(line.split()[:2]) for line in Path("target/sbom-runtime.txt").read_text().splitlines()}
build_only = set()
for package in rust["packages"]:
    if (package["name"], "v" + package["versionInfo"]) not in runtime:
        build_only.add(package["SPDXID"])
        if "build-only" not in package["comment"].split("; "):
            package["comment"] += "; build-only"

for edge in rust["relationships"]:
    if edge["relationshipType"] == "DEPENDS_ON" and edge["relatedSpdxElement"] in build_only:
        edge["spdxElementId"], edge["relatedSpdxElement"] = edge["relatedSpdxElement"], edge["spdxElementId"]
        edge["relationshipType"] = "BUILD_DEPENDENCY_OF"

rust["packages"].extend(p for p in swift["packages"] if p["SPDXID"] != directory)
rust["files"] = swift["files"]
for edge in swift["relationships"]:
    if edge["relationshipType"] == "DESCRIBES":
        continue
    if edge["spdxElementId"] == directory:
        edge["spdxElementId"] = product
    rust["relationships"].append(edge)

rust["creationInfo"]["creators"].extend(swift["creationInfo"]["creators"])
rust["documentNamespace"] = f"urn:uuid:{uuid.uuid4()}"
json.dump(rust, sys.stdout, indent=2)
print()
